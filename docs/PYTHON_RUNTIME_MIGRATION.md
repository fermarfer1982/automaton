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
   desinstalador registrado con `/uninstall /quiet /log`. Después exige que no
   queden bundle, componentes MSI, destino parcial ni registro `PythonCore`
   mixto, y que Python Manager siga funcional.
3. `InstallMachineRuntime`: solo puede ejecutarse cuando no queda ninguna
   instalación traditional 3.14.5 ni destino parcial. Usa el full installer
   verificado con log durable y componentes mínimos.
4. `BuildVenv`: crea exactamente `C:\automaton\.venv.new` con el Python
   machine-wide e instala offline desde el wheelhouse y el lock.
5. `PromoteVenv`: valida de nuevo `.venv.new`, mueve el venv activo a un backup
   administrativo y solo entonces promueve el staging. Si la validación
   posterior falla, conserva el resultado fallido y restaura el venv anterior.

Las fases son reanudables. Un wheelhouse, runtime, staging o venv final ya
válido se reconoce como `AlreadyComplete`; un artefacto existente pero inválido
se conserva y bloquea la continuación. No hay borrado automático para “hacer
que pase”. Cada ejecución de installer, pip o venv produce stdout/stderr o log
en `C:\ProgramData\AutomatonMT5Lab\maintenance\logs`. Cada fase aplicada crea
un reporte JSON con `last_applied_phase` en `python-runtime-results`.

La instalación base excluye Development Libraries, tests, documentación,
Tcl/Tk, launcher, asociaciones y PATH. Conserva executables, stdlib y pip:
`venv` forma parte de stdlib y pip se necesita para instalar el lock offline.
La ausencia de compilación está garantizada por el lock wheel-only y vuelve a
verificarse al preparar el wheelhouse.

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

# 3. Retirar de forma soportada el traditional 3.14.5 dañado.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase UninstallTraditional
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase UninstallTraditional -Apply

# 4. Debe mostrar traditional ausente y partial target ausente.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase Inventory
```

Si `UninstallTraditional` deja componentes MSI, el destino parcial o el
registro `PythonCore` mixto, detenerse.
No borrar archivos ni registro manualmente, no usar `msizap` y no ejecutar la
fase de instalación. Conservar el reporte y el log `traditional-uninstall` para
autorizar un gate de recuperación adicional basado en evidencia.

Solo si el inventario posterior muestra simultáneamente
`SAME_VERSION_TRADITIONAL_INSTALL_PRESENT=PASS` y
`PARTIAL_TARGET_RUNTIME=ABSENT`, continuar:

```powershell
$Installer = 'C:\ProgramData\AutomatonMT5Lab\maintenance\python-3.14.5-amd64.exe'

# 5. Instalar una única copia traditional machine-wide.
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase InstallMachineRuntime -InstallerPath $Installer
.\scripts\Install-TradingLabPythonRuntime.ps1 -Phase InstallMachineRuntime -InstallerPath $Installer -Apply

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
