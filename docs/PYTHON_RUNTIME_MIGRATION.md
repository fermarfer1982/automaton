# Runtime Python machine-wide del Trading Lab

## Estado y causa

El venv original fue creado con CPython 3.14.5 x64 y contiene un redirector
Windows, no un intérprete autocontenido. Su `pyvenv.cfg` y `sys.base_prefix`
apuntan a un Python instalado dentro del perfil administrativo. El usuario
`AutomatonGateway` puede leer `C:\automaton\.venv\Scripts\python.exe`, pero no
puede ejecutar el intérprete base. El runtime test lo clasifica correctamente
como `TEST_INFRASTRUCTURE_ERROR`, etapa `PYTHON_PREFLIGHT`, test
`PYTHON_EXECUTE`.

Inventario previo a la migración:

- CPython `3.14.5`, 64 bits.
- `sys.executable`: `C:\automaton\.venv\Scripts\python.exe`.
- `sys.prefix`: `C:\automaton\.venv`.
- `sys.base_prefix`: perfil administrativo, no válido para servicio.
- Dependencias directas: `requirements-gateway.in`.
- Fuente de instalación autoritativa:
  `requirements-gateway-win-py314.lock`.
- SHA-256 del lock: `68d14ddc9d943079e8f791bb8f276ae630f46c8ee8997b2bf2afeabed1e30d99`.
- El lock es wheel-only, exige hashes e incluye `MetaTrader5==5.0.6090`,
  `numpy==2.5.2`, FastAPI, Uvicorn, Pydantic, HTTPX, pytest, PyYAML y tzdata.

`pip freeze` se conserva como evidencia comparativa, pero no es una fuente de
reconstrucción. El script exige que el inventario resultante coincida con el
lock normalizando los nombres PEP 503 y ejecuta `pip check`. La presencia de
MetaTrader5 se comprueba mediante metadata de distribución, sin importarlo,
inicializarlo ni conectarse a MT5.

## Diseño aplicado por el gate

El destino exacto es:

```text
C:\Program Files\AutomatonPython\3.14.5
```

El árbol queda con herencia bloqueada y únicamente:

- SYSTEM: FullControl.
- Administrators: FullControl.
- AutomatonGateway: ReadAndExecute.

AutomatonAgent no recibe acceso al Python base: el perfil trading usa Node y
HTTP autenticado y no necesita ejecutar Python ni importar MetaTrader5. Ningún
principal de servicio, Users, Authenticated Users o Everyone puede modificar
el intérprete, DLLs o stdlib.

El venv se crea de nuevo ejecutando el Python machine-wide. No se copia
`python.exe` ni se edita `pyvenv.cfg`. Las dependencias se instalan con
`--only-binary=:all: --require-hashes --no-cache-dir` desde el lock del
repositorio. El staging está confinado al workspace y hereda el modelo
read-only ya aplicado para Agent/Gateway. El venv anterior se conserva como
backup administrativo dentro de `maintenance`; no es una dependencia runtime
y las identidades de servicio no pueden leerlo.

El script no cambia ACL de perfiles, `control`, `ipc`, `operational`,
`research`, auditoría, logs ni estado Agent. Solo protege los nuevos dominios
`maintenance`, el nuevo Python base y cualquier backup administrativo.

## Artefacto autorizado

Usar exclusivamente el instalador completo oficial `python-3.14.5-amd64.exe`:

- URL: `https://www.python.org/ftp/python/3.14.5/python-3.14.5-amd64.exe`
- Tamaño: `30,361,968` bytes.
- SHA-256: `f9c09f5ed6f796fd1a8bc5ddfa41715a494b453c4781f0e35d5077cf9fa58f6d`.
- Firma Authenticode válida de Python Software Foundation.

El bootstrapper pequeño de la caché del perfil administrativo no es válido.
El gate no descarga nada: exige un instalador completo previamente descargado,
fuera de perfiles de usuario, y vuelve a comprobar nombre, tamaño, hash, firma,
reparse points y ausencia de permisos Modify no confiables antes de ejecutarlo.

## Procedimiento humano elevado

En una consola PowerShell elevada, con Automaton y Gateway detenidos:

```powershell
Set-Location C:\automaton

$Maintenance = 'C:\ProgramData\AutomatonMT5Lab\maintenance'
$Installer = Join-Path $Maintenance 'python-3.14.5-amd64.exe'
$ExpectedSha256 = 'f9c09f5ed6f796fd1a8bc5ddfa41715a494b453c4781f0e35d5077cf9fa58f6d'

New-Item -ItemType Directory -Path $Maintenance -Force | Out-Null
Invoke-WebRequest `
  -UseBasicParsing `
  -Uri 'https://www.python.org/ftp/python/3.14.5/python-3.14.5-amd64.exe' `
  -OutFile $Installer

$ActualSha256 = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualSha256 -ne $ExpectedSha256) {
  throw "Python installer SHA-256 mismatch: $ActualSha256"
}

.\scripts\Install-TradingLabPythonRuntime.ps1 -InstallerPath $Installer
.\scripts\Install-TradingLabPythonRuntime.ps1 -InstallerPath $Installer -Apply
```

La primera llamada es dry-run y no modifica el runtime. `-Apply` es la
autorización humana explícita. El instalador se ejecuta sin PATH global,
launcher, asociaciones, shortcuts, Tcl/Tk, tests o herramientas adicionales.
No inicia servicios ni accede a MT5.

Tras un `PASS`, repetir el runtime test Gateway con un RunId nuevo. El reporte
runtime y el collector exigen simultáneamente:

```text
PYTHON_BASE_MACHINE_WIDE=PASS
PYTHON_BASE_OUTSIDE_USER_PROFILE=PASS
PYTHON_GATEWAY_EXECUTE=PASS
PYTHON_GATEWAY_MODIFY_DENY=PASS
VENV_BASE_OUTSIDE_USER_PROFILE=PASS
GATEWAY_TEMP_OPERATIONAL_ONLY=PASS
```

El test Gateway también solicita de forma no destructiva los derechos de
escritura/borrado sobre el ejecutable base, DLL, stdlib, ejecutable del venv,
Scripts y site-packages. Cualquier permiso inesperado produce
`CRITICAL_UNEXPECTED_ALLOW`. TEMP y TMP permanecen confinados al directorio
privado por RunId dentro de `operational\runtime-tmp`.

El arranque de producción prepara igualmente, antes de la primera llamada a
Python, `operational\runtime-tmp\gateway-service`; comprueba SID Gateway,
token no administrativo, confinamiento, componentes/descendientes no-reparse y
un canario create/delete. El proceso hijo hereda exclusivamente ese TEMP/TMP y
`PYTHONDONTWRITEBYTECODE=1`.
