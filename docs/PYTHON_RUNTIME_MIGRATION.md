# Recuperación del runtime Python machine-wide

## Estado observado el 12 de agosto de 2026

El intento monolítico anterior no se considera una instalación fallida inocua.
El instalador tradicional de CPython 3.14.5 entró en maintenance mode porque ya
existía la misma versión tradicional para el usuario administrativo. Terminó
con código 1603 y dejó un estado mixto:

- `PYTHON_MANAGER_RUNTIME=FUNCTIONAL` en el perfil administrativo;
- `TRADITIONAL_USER_RUNTIME=PRESENT`;
- nueve componentes MSI tradicionales registrados;
- `PARTIAL_TARGET_RUNTIME=PRESENT` bajo
  `C:\Program Files\AutomatonPython\3.14.5` (faltan `Lib` y stdlib);
- registro `PythonCore` mixto: administrado por Python Manager, pero con una
  ruta de instalación sobrescrita hacia el destino parcial;
- `BROKEN_ACTIVE_VENV=PRESENT`: el redirector de `C:\automaton\.venv` apunta
  al intérprete tradicional de usuario que ya no existe.

El Python Manager de mantenimiento fue probado en modo read-only: CPython
3.14.5 x64, `sys.executable`, `sys.prefix` y `sys.base_prefix` coherentes,
`venv` importable y pip funcional. Python Manager y el traditional installer
son productos distintos; la recuperación nunca desinstala Python Manager.

El inventario no usa `Win32_Product`, no repara MSI y no escribe registro. Lee
HKCU/HKLM `PythonCore`, entradas Uninstall, ProductCodes bajo Installer
`UserData`, layouts del filesystem y `pyvenv.cfg`. Solo ejecuta el runtime de
Python Manager ya identificado para obtener metadata; no ejecuta el destino
parcial ni el venv roto.

## Fuentes reproducibles

La fuente autoritativa de paquetes es
`C:\automaton\requirements-gateway-win-py314.lock`, SHA-256:

```text
68d14ddc9d943079e8f791bb8f276ae630f46c8ee8997b2bf2afeabed1e30d99
```

El lock exige `--only-binary=:all:` y `--require-hashes`; por tanto, ninguna
dependencia se compila. Incluye wheels CPython 3.14/Windows x64 para
`MetaTrader5==5.0.6090` y `numpy==2.5.2`. La recuperación verifica sus hashes y
posteriormente sus metadatos de distribución, pero nunca importa MetaTrader5.

El instalador machine-wide autorizado continúa siendo el artefacto full
offline `python-3.14.5-amd64.exe`:

- tamaño: `30,361,968` bytes;
- SHA-256: `f9c09f5ed6f796fd1a8bc5ddfa41715a494b453c4781f0e35d5077cf9fa58f6d`;
- firma Authenticode válida de Python Software Foundation.

El bundle pequeño registrado en Package Cache solo puede usarse como el
desinstalador correspondiente a la instalación tradicional dañada. El script
exige que coincida con la ruta registrada, firma PSF y SHA-256
`693522e3a8a747926a2f1f5a013b07315ac9472657d691b8f152fb6438b81723`.
No borra Package Cache, registros ni ProductCodes manualmente.

## Fases independientes y fail-closed

`Install-TradingLabPythonRuntime.ps1` ya no tiene un Apply monolítico. El valor
predeterminado es `-Phase Inventory`; combinar Inventory con `-Apply` se
rechaza. Cada fase admite primero una prevalidación sin `-Apply` y después una
ejecución humana explícita:

1. `PrepareWheelhouse`: usa únicamente Python Manager para descargar wheels
   admitidos por el lock a un staging de maintenance. Solo promueve el
   wheelhouse tras verificar todos los hashes y los wheels MT5/numpy.
2. `UninstallTraditional`: exige el wheelhouse completo antes de ejecutar el
   desinstalador registrado con `/uninstall /quiet /log`. Antes de `-Apply`
   vuelve a validar todos los wheels y enlaza un reporte durable PASS de
   `PrepareWheelhouse`. La fase no contiene borrado directo de registro,
   Package Cache, Windows Installer cache, venv activo ni target parcial. Tras
   el desinstalador exige que no queden bundle/componentes tradicionales y que
   Python Manager siga funcional; cualquier target parcial o registro
   `PythonCore` mixto restante bloquea fases posteriores y requiere otro gate.
3. `InstallMachineRuntime`: exige y verifica por hash un reporte durable PASS
   aplicado de `UninstallTraditional`, y vuelve a recorrer la evidencia
   enlazada de `PrepareWheelhouse`. Después revalida de forma independiente
   que no queden instalaciones traditional 3.14.5, componentes MSI, destino
   parcial ni registro `PythonCore` mixto. También vuelve a verificar el full
   installer y los 27 wheels antes de exponer el plan exacto; solo entonces
   puede ejecutar el instalador con log durable. Si detecta en cambio el
   payload exacto ya instalado, entra en
   `TARGET_RUNTIME_ALREADY_INSTALLED_VALIDATION_PENDING`, fija
   `MUST_NOT_EXECUTE_INSTALLER=true` y no alcanza el sitio de ejecución del
   bootstrapper.
4. `ResumeMachineRuntime`: solo admite el payload machine-wide exacto, cuatro
   MSI bajo SYSTEM y un reporte fallido que pruebe que el installer anterior
   terminó antes de fallar la validación. Revalida metadata y el log, y puede
   aplicar exclusivamente la ACL del árbol del runtime con un `-Apply`
   separado. Nunca instala, desinstala, construye un venv ni toca otros
   dominios ACL.
5. `BuildVenv`: crea exactamente `C:\automaton\.venv.new` con el Python
   machine-wide e instala offline desde el wheelhouse y el lock.
6. `PromoteVenv`: valida de nuevo `.venv.new`, mueve el venv activo a un backup
   administrativo y solo entonces promueve el staging. Si la validación
   posterior falla, conserva el resultado fallido y restaura el venv anterior.

Las fases son reanudables. Un wheelhouse, runtime, staging o venv final ya
válido se reconoce como `AlreadyComplete`; un artefacto existente pero inválido
se conserva y bloquea la continuación. No hay borrado automático para “hacer
que pase”. Cada ejecución de installer, pip o venv produce stdout/stderr o log
en `C:\ProgramData\AutomatonMT5Lab\maintenance\logs`. Cada fase aplicada crea
un reporte JSON en `python-runtime-results`. `current_run_applied_phase`
describe exclusivamente las mutaciones de esa ejecución. La continuidad se
expresa aparte con `required_previous_phase`, `previous_phase_verified` y
`previous_phase_report`; ningún valor de fase de una ejecución anterior basta
por sí solo para autorizar una operación.

Todos los probes Python ejecutan `python.exe -I -` con
`ProcessStartInfo.UseShellExecute=false`. El programa se transmite sin
transformaciones por stdin y stdout/stderr se capturan por separado. No se usa
`python -c`, shell ni `Invoke-Expression`, eliminando las capas de quoting que
podrían transformar `separators=(',', ':')`.

La instalación base excluye explícitamente Development Libraries, Test Suite,
Documentation y Tcl/Tk porque el Gateway consume exclusivamente wheels
`cp314-win_amd64`: no compila extensiones, no ejecuta la suite de CPython, no
presenta documentación local y no usa interfaces Tk. También deshabilita el
launcher, asociaciones de archivos y modificaciones de PATH para que la ruta
del intérprete sea siempre explícita. Conserva Core Interpreter, Executables,
Standard Library y pip bootstrap. `venv` forma parte de Standard Library y pip
es necesario para reconstruir el venv exclusivamente desde el wheelhouse y el
lock. La prohibición de compilación se refuerza con `--only-binary=:all:` y la
completitud/hash de los 27 wheels se vuelve a verificar antes de instalar el
runtime, aunque los wheels no se instalan hasta `BuildVenv`.

El dry-run de `InstallMachineRuntime` debe mostrar, como mínimo:

```text
required_previous_phase=UninstallTraditional
previous_phase_verified=true
previous_phase_report=<REPORTE_DURABLE_APLICADO>
previous_phase_report_sha256=<SHA256>
PREVIOUS_PHASE_UNINSTALL_TRADITIONAL=PASS
TRADITIONAL_USER_RUNTIME_ABSENT=PASS
TRADITIONAL_MACHINE_RUNTIME_ABSENT=PASS
TRADITIONAL_MSI_COMPONENTS_ZERO=PASS
PARTIAL_TARGET_RUNTIME_ABSENT=PASS
MIXED_PYTHONCORE_REGISTRATION_ABSENT=PASS
TARGET_PATH_EMPTY_OR_ABSENT=PASS
PYTHON_INSTALLER_SIZE=PASS
PYTHON_INSTALLER_SHA256=PASS
PYTHON_INSTALLER_AUTHENTICODE=PASS
WHEELHOUSE_EXPECTED_REQUIREMENTS=27
WHEELHOUSE_ARTIFACT_COUNT=27
INSTALL_ALL_USERS=PASS
TARGET_MACHINE_WIDE=PASS
TARGET_OUTSIDE_USER_PROFILE=PASS
PREPEND_PATH_DISABLED=PASS
LAUNCHER_DISABLED=PASS
FILE_ASSOCIATIONS_DISABLED=PASS
DEVELOPMENT_LIBRARIES_DISABLED=PASS
TEST_SUITE_DISABLED=PASS
DOCUMENTATION_DISABLED=PASS
TCL_TK_DISABLED=PASS
installer_plan.operation=INSTALL_CPYTHON_MACHINE_WIDE_MINIMAL
```

Un reporte anterior nunca sustituye el inventario actual. Si el reporte o su
evidencia anidada faltan, cambian de hash, tienen schema/fase/status
incompatibles, o reaparece cualquier componente traditional/partial/mixed, la
fase termina fail-closed antes de `Start-Process`.

Tras una instalación mínima, el registro del bundle puede permanecer en HKCU
del administrador que lanzó el bootstrapper. Ese registro no demuestra un
segundo payload de usuario. El inventario conserva por separado
`traditional_bundle_registration_scope`; determina
`traditional_runtime_payload_scope=MACHINE` únicamente cuando coinciden el
target bajo Program Files, PythonCore HKLM y exactamente los cuatro MSI
esperados —Core Interpreter, Executables, Standard Library y pip Bootstrap—
bajo SYSTEM. El resultado se clasifica como
`EXPECTED_INSTALLED_TARGET_RUNTIME`; cualquier combinación incompleta o
adicional es `CONFLICTING_PREEXISTING_RUNTIME`.

El estado ACL posterior al installer se inspecciona antes de mutar. El estado
exacto solo contiene SYSTEM y Administrators con FullControl y
AutomatonGateway con ReadAndExecute, sin herencia. AutomatonAgent y Users no
reciben acceso. Si el árbol conserva ACL heredadas, el dry-run emite
`PYTHON_RUNTIME_ACL=INCOMPLETE_REQUIRES_EXPLICIT_APPLY`; no intenta ocultar la
instalación válida ni vuelve a ejecutar el installer.

El dry-run de `ResumeMachineRuntime` incluye un `acl_plan` completo antes de
cualquier autorización de Apply. El plan queda confinado exactamente a
`C:\Program Files\AutomatonPython\3.14.5`, resuelve las identidades por SID,
protege la herencia descartando ACEs heredadas y admite exclusivamente tres
ACEs Allow: SYSTEM FullControl, Administrators FullControl y AutomatonGateway
ReadAndExecute más Synchronize. AutomatonAgent obtiene acceso `NONE` por
ausencia de ACE; no se planifican ACEs Deny. La validación rechaza otros
targets, reparse points, derechos adicionales, grupos amplios o cualquier
mutación de otro dominio.

Antes del primer `Set-Acl`, la futura ejecución autorizada vuelve a validar el
plan, materializa en memoria los descriptores de directorio y fichero, valida
owner/ACEs/herencia y enumera el árbol sin seguir junctions ni enlaces. En
dry-run permanecen explícitamente `machine_runtime_acl_modified=false`,
`acl_apply_requested=false` y `ACL_APPLIED=false`.

## Procedimiento humano elevado para el estado actual

No ejecutar Automaton ni Gateway durante la recuperación. Mantener
`TRADING_MODE=OBSERVE_ONLY`. En una PowerShell elevada del mismo usuario
administrativo que posee la entrada HKCU tradicional:

```powershell
Set-Location C:\automaton

# 1. Inventario read-only. En el estado actual, exit code 2 es esperado.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase Inventory

# 2. Preparar primero una copia offline íntegra de todos los wheels.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase PrepareWheelhouse
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase PrepareWheelhouse -Apply

# 3. Prevalidar la retirada soportada. Debe imprimir todos los gates de
# continuidad, wheelhouse, Manager, bundle y los 9 ProductCodes.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase UninstallTraditional

# Revisar la salida antes de autorizar separadamente la mutación:
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase UninstallTraditional -Apply

# 4. Debe mostrar traditional ausente y partial target ausente.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase Inventory
```

Si `UninstallTraditional` deja componentes MSI, falla. Si el desinstalador
soportado deja el destino parcial o el registro `PythonCore` mixto, detenerse
antes de `InstallMachineRuntime` y preparar una fase de saneamiento separada.
No borrar archivos ni registro manualmente, no usar `msizap` y no ejecutar la
fase de instalación. Conservar el reporte y el log `traditional-uninstall` para
autorizar un gate de recuperación adicional basado en evidencia.

Solo si el inventario anterior a la primera instalación muestra simultáneamente
`SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=ABSENT` y
`PARTIAL_TARGET_RUNTIME=ABSENT` y
`MIXED_PYTHONCORE_REGISTRATION=ABSENT`, continuar:

```powershell
$Installer = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe'

# 5. Prevalidar una única copia traditional machine-wide. Revisar la cadena,
# los hashes, los 27 wheels y installer_plan antes de pedir un Apply separado.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase InstallMachineRuntime -InstallerPath $Installer
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase InstallMachineRuntime -InstallerPath $Installer -Apply

# Si el installer ya terminó pero la validación/ACL quedó pendiente, no repetir
# la línea anterior. Prevalidar exclusivamente la recuperación:
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase ResumeMachineRuntime -InstallerPath $Installer

# Un Apply de ResumeMachineRuntime requiere autorización humana separada y solo
# puede validar/aplicar la ACL del runtime; nunca ejecuta el bootstrapper.

# 6. Construir y validar staging; el venv activo aún no cambia.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase BuildVenv
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase BuildVenv -Apply

# 7. Promover únicamente el staging validado, con rollback administrativo.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase PromoteVenv
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase PromoteVenv -Apply
```

No considerar éxito por un exit code 0 aislado. La fase final debe emitir:

```text
PYTHON_BASE_MACHINE_WIDE=PASS
PYTHON_BASE_OUTSIDE_USER_PROFILE=PASS
PYTHON_GATEWAY_EXECUTE=PASS
PYTHON_GATEWAY_MODIFY_DENY=PASS
VENV_BASE_OUTSIDE_USER_PROFILE=PASS
VENV_LOCK_MATCH=PASS
META_TRADER5_PACKAGE_PRESENT=PASS
GATEWAY_TEMP_OPERATIONAL_ONLY=PENDING_RUNTIME_IDENTITY_TEST
```

El último gate permanece pendiente hasta repetir, con un RunId nuevo, el test
runtime de Gateway. Su TEMP/TMP continúa confinado a
`C:\ProgramData\AutomatonMT5Lab\operational\runtime-tmp\<RunId>`; esta
recuperación no modifica las ACL de perfiles ni los demás dominios del lab.
