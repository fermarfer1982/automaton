# Modelo ACL Windows del laboratorio

Este documento describe el ACL aplicado manualmente mediante
`scripts\Apply-TradingLabAclGate.ps1`. El reporte administrativo de aplicación
confirma `ACL_PREVALIDATION=PASS`, `ACL_APPLY=PASS` y `ACL_APPLIED=true`. La
efectividad bajo los tokens restringidos permanece pendiente hasta completar
el gate runtime descrito al final de este documento. Automaton y Gateway deben
permanecer detenidos hasta entonces.

## Convenciones

- Owner: `BUILTIN\Administrators` (`S-1-5-32-544`).
- Recuperación: `SYSTEM` y `BUILTIN\Administrators` tienen `FullControl`.
- Herencia: protegida, ACE heredadas eliminadas y allowlist explícita.
- No se usan ACE `Deny`.
- `RX` significa `ReadAndExecute`; `M`, `Modify`; `R`, `Read` sin execute;
  `RA`, `Read + AppendData + Synchronize`.
- Las ACE de runtime se propagan solo en árboles mutables. En directorios de
  navegación o control se aplican al directorio; los ficheros nombrados reciben
  ACL exacta propia. Las ACE de recuperación se propagan a los hijos.

| Dominio | Gateway | Agent | Propagación runtime |
|---|---:|---:|---|
| `C:\automaton` | RX | RX | contenedores y objetos |
| raíz `AutomatonMT5Lab` | RX | RX | solo raíz |
| `control` | RX | ninguna | solo directorio |
| `control\trading.yaml` | R | ninguna | fichero |
| `control\STOP_TRADING` | R si existe | ninguna | fichero humano opcional |
| `control\demo-authorization` | RX | ninguna | solo directorio |
| `...\authorization.json` | R si existe | ninguna | fichero humano opcional |
| `ipc` | RX | RX | solo directorio |
| `ipc\automaton.key` | R | R | fichero; sin execute |
| `operational` | M | ninguna | contenedores y objetos |
| `research` | M | ninguna | contenedores y objetos |
| `audit` | RX | ninguna | solo directorio |
| `audit\sqlite` | M | ninguna | contenedores y objetos |
| `audit\journal` | RX | ninguna | solo directorio |
| `audit\journal\audit.jsonl` | RA | ninguna | fichero precreado |
| `logs` | RX | ninguna | solo directorio |
| `logs\gateway` | M | ninguna | contenedores y objetos |
| `logs\security` | RX | ninguna | solo directorio |
| `logs\security\security.log` | RA | ninguna | fichero precreado |
| `C:\Users\AutomatonAgent\.automaton` | ninguna | M | contenedores y objetos |

El ACL exacto de cada fila añade además `SYSTEM: FullControl` y
`BUILTIN\Administrators: FullControl`, ambos `Allow`. No se concede ninguna ACE
a `Authenticated Users`, `Everyone`, `BUILTIN\Users` ni al SID humano. El
mantenimiento requiere una consola elevada y se apoya en Administrators/SYSTEM.
El bootstrap no crea `STOP_TRADING` ni `authorization.json`: su ausencia no
autoriza trading; solo indica que esas dos señales humanas opcionales no han
sido afirmadas. Si un administrador las crea posteriormente, debe reaplicar o
validar su ACL exacta antes de iniciar el Gateway.

La preparación es reanudable: `trading.yaml` preexistente debe coincidir byte a
byte con la plantilla OBSERVE_ONLY inválida y una key IPC preexistente debe ser
Base64URL válido que decodifique exactamente a 32 bytes. Ninguno se sobrescribe
ni regenera. Una key nueva usa `RandomNumberGenerator.Create().GetBytes()` y
`FileMode.CreateNew`, compatible con Windows PowerShell 5.1; su valor nunca se
incluye en consola, reporte o logs. El reporte solo conserva creación/reuso y
longitud codificada.

Antes de la primera modificación de security descriptors, el gate persiste
`ACL_APPLY=IN_PROGRESS`. Cada `Set-Acl` completado se añade a un journal de
progreso administrativo. Un error posterior produce `PARTIAL` y enumera las
rutas afectadas; no existe rollback automático. Un error anterior conserva
`NOT_RUN`, y un intento que entra en apply pero no completa ninguna ACE queda
`FAIL`.

## Límites de confianza

`audit\sqlite` no es inmutable. SQLite WAL necesita crear y modificar el DB,
`-wal`, `-shm` y el directorio; los triggers append-only son una protección
lógica, no física, frente a la identidad Gateway.

El journal JSON hash-chain se abre en Python con modo `a`, flush y `fsync`. El
security log usa `FileHandler(mode="a")` y no rota ni renombra. El plan precrea
ambos ficheros como Administrator y concede al Gateway `Read`, `AppendData` y
`Synchronize`, sin `WriteData`, `Delete`, `DeleteChild`, `ChangePermissions`,
`TakeOwnership` ni `Modify`. Esto reduce privilegios, pero no demuestra
inmutabilidad criptográfica ni confirma todavía cómo traduce el CRT de Python
la apertura append a derechos NTFS en este host. La prueba real queda marcada
`UNVERIFIED_UNTIL_POST_APPLY_NEGATIVE_TESTS`.

Después de aplicar ACL, antes de iniciar el laboratorio, deben ejecutarse bajo
cada identidad pruebas negativas que intenten leer, crear, sobrescribir,
truncar, renombrar, sustituir, borrar y cambiar ACL. Para el Gateway también se
debe confirmar que un append válido y la reapertura tras reinicio funcionan. Si
la apertura Python solicita `WriteData`, el Gateway debe permanecer detenido;
no se ampliarán permisos automáticamente. La alternativa requerirá revisión
humana (por ejemplo, un escritor de auditoría separado en un milestone futuro).

## Matriz runtime pendiente tras `-Apply`

| Identidad | Operación | Resultado requerido |
|---|---|---|
| Agent | leer workspace / crear-modificar-borrar fuente | ALLOW / DENY |
| Agent | leer config, control, operational, research, audit o security log | DENY |
| Agent | leer key / modificar-borrar key | ALLOW / DENY |
| Agent | leer-escribir estado propio | ALLOW |
| Agent | crear-modificar-borrar stop o autorización DEMO | DENY |
| Gateway | leer workspace / modificar fuente | ALLOW / DENY |
| Gateway | leer config, stop y autorización / modificarlos-borrarlos | ALLOW / DENY |
| Gateway | leer key / modificar-borrar-ejecutar key | ALLOW / DENY |
| Gateway | leer-escribir operational y research | ALLOW |
| Gateway | operaciones DB/WAL/SHM en audit SQLite | ALLOW |
| Gateway | leer y append journal | ALLOW |
| Gateway | sobrescribir inicio, truncar, borrar, renombrar o reemplazar journal | DENY |
| Gateway | append security log / truncar-borrar-reemplazar | ALLOW / DENY |
| Gateway | leer o escribir estado Agent | DENY |
| Administrator elevado | mantenimiento y recuperación | ALLOW |

## Gate runtime manual

Los scripts `Test-AgentRuntimeAcl.ps1` y `Test-GatewayRuntimeAcl.ps1` abortan
antes de cualquier acceso si el SID efectivo no coincide exactamente con la
identidad prevista o si reciben un token administrativo. No aceptan ni
almacenan contraseñas. Un mismo UUID público vincula ambos reportes y la
recopilación administrativa final.

Los canarios mutables se limitan al estado privado del Agent y a los dominios
`operational`, `research` y `audit\sqlite` del Gateway. El journal y el log de
seguridad reciben un único append identificable y durable; esos eventos no se
eliminan. Las comprobaciones de overwrite, truncate, delete, rename, replace y
change-ACL sobre ficheros protegidos abren un handle solicitando el derecho
NTFS correspondiente, pero nunca ejecutan la mutación si el derecho resulta
inesperadamente concedido. Esa situación produce `CRITICAL_FAIL` y detiene el
test Gateway.

`Collect-RuntimeAclResults.ps1` debe ejecutarse después desde una consola
elevada. Verifica el SID y UUID de ambos reportes, que no existan campos de
secretos, el prefijo byte a byte mediante tamaño y SHA-256, el sufijo canario
exacto, la cadena hash completa del journal y `TRADING_MODE=OBSERVE_ONLY`.
Ninguno de estos scripts importa MetaTrader5, inicia el laboratorio, usa red,
modifica ACL/grupos o habilita trading.

Las claves LLM se configurarán más adelante solo para `AutomatonAgent`, en un
almacén de credenciales o entorno de usuario protegido, nunca en workspace,
ProgramData, auditoría, logs o memoria del Gateway. Las credenciales MT5
permanecen exclusivamente en el perfil/sesión de `AutomatonGateway` y el
terminal; la configuración protegida contiene login y servidor, nunca password.
