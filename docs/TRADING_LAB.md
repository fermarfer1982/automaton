# Laboratorio Automaton → MT5 DEMO

El laboratorio separa estrictamente observación/decisión y ejecución:

```text
Automaton → Trading Tools → FastAPI Gateway → Account Guard
          → Risk Engine → Execution Engine → MetaTrader 5
```

El estado por defecto es siempre `OBSERVE_ONLY`. El gateway no recibe
contraseñas, no llama a `login()` ni `symbol_select()`, no busca otra cuenta y
solo inicializa la ruta exacta de un terminal MT5 ya visible en la sesión del
usuario Gateway. Una cuenta REAL, otro login, otro servidor o cualquier error
de infraestructura bloquean la operación.

La rama `feature/mt5-demo-trading-lab` conserva el baseline observado al inicio
de este milestone: 75 tests Python superados antes de la ampliación. El historial
Git mantiene ese punto y los incrementos posteriores sin reclonar ni sustituir
el árbol upstream.

## Fronteras permanentes

- Solo el login DEMO, servidor, nombre opcional, `XAUUSD` y magic configurados.
- Automaton propone riesgo monetario; nunca volumen, magic, cuenta, servidor o modo.
- `order_check()` y todas las variantes de `order_send()` viven únicamente en
  el adaptador protegido y se serializan en Execution Engine.
- Tres gates auditados: `PRE_FLIGHT_CHECK`, `POST_LLM_CHECK` y
  `PRE_EXECUTION_CHECK`.
- Cualquier posición u orden pendiente de toda la cuenta bloquea una apertura.
- Una sola entrada con SL obligatorio; grid, martingala, averaging down,
  ampliación del SL y aumento de pérdidas están prohibidos.
- Un resultado perdido tras `order_send()` queda `EXECUTION_UNCERTAIN` y su
  huella se bloquea de forma durable hasta reconciliación humana.
- Los stores JSON hash-chain y SQLite deben coincidir; UPDATE/DELETE de eventos
  históricos están bloqueados por triggers.
- El perfil del agente excluye shell, instalaciones, pagos, wallets, réplica,
  social, compras y `git push`. Las claves de inferencia solo viven en el entorno
  del usuario Agent.

## API local autenticada

El bind es exclusivamente `127.0.0.1:8765`. Todas las rutas siguientes,
incluidas health/status, exigen `X-AUTOMATON-KEY`; la key aleatoria está en el
dominio IPC externo y nunca aparece en configuración, respuestas, logs o memoria.

```text
GET  /v1/health                 GET  /v1/status
GET  /v1/account                GET  /v1/market/XAUUSD
GET  /v1/candles/XAUUSD         GET  /v1/positions[/{ticket}]
GET  /v1/history                GET  /v1/daily-stats
POST /v1/trade/propose          POST /v1/trade/close
POST /v1/trade/modify           POST /v1/trade/cancel-pending
POST /v1/research/decisions     POST /v1/research/hypotheses
POST /v1/research/reviews       GET  /v1/research/metrics
GET  /v1/research/memory
```

`401` identifica key inválida, `422` esquema inválido, `409` conflicto de
idempotencia y `503` infraestructura fail-closed. Las decisiones de dominio
devuelven `200` con códigos estables. `OBSERVE_ONLY` registra y deniega cualquier
gestión sin llamar a MT5. PAPER usa posiciones virtuales persistentes. El futuro
DEMO permite cierre total, cancelación y modificaciones reductoras incluso con
kill switch, pero bloquea aperturas y cualquier aumento de riesgo.

## Configuración, identidades y ACL

Copiar y revisar manualmente [trading.example.yaml](../config/trading.example.yaml)
en:

```text
C:\ProgramData\AutomatonMT5Lab\control\trading.yaml
```

Escribir explícitamente el login/servidor DEMO observados por el humano, sin
contraseña. No se acepta detección automática como autorización. Crear
manualmente dos usuarios Windows estándar distintos. El humano debe ejecutar el
siguiente script en una consola elevada: solicita cada contraseña como
`SecureString`, no la registra y no aplica ACL.

```powershell
.\scripts\New-TradingLabUsers.ps1
```

- `AutomatonGateway`: terminal visible y gateway.
- `AutomatonAgent`: Automaton y su estado externo, sin wallet de firma.

El script ACL no crea usuarios, no pide contraseñas y es dry-run sin `-Apply`:

```powershell
.\scripts\setup.ps1 `
  -GatewayIdentity 'MACHINE\AutomatonGateway' `
  -AutomatonIdentity 'MACHINE\AutomatonAgent' `
  -AutomatonStateDir 'C:\Users\AutomatonAgent\.automaton'
```

Tras revisar SIDs/rutas, un administrador puede repetir con `-Apply`. La opción
adicional `-InstallDependencies` es una autorización humana separada. Usa
`requirements-gateway-win-py314.lock` (wheels CPython 3.14/Windows x64, hashes
SHA-256 completos) y `pnpm --frozen-lockfile`; no se ejecuta automáticamente.
Los scripts resuelven exclusivamente el runtime portable local
`.runtime\node-v22.22.0-win-x64`, verifican Node v22.22.0 x64 y el SHA-256 del
ejecutable antes de usar Corepack con pnpm 10.28.1. `.runtime/` no se versiona.

Python no se resuelve desde `PATH` ni desde perfiles personales. El gate
separado [PYTHON_RUNTIME_MIGRATION.md](PYTHON_RUNTIME_MIGRATION.md) instala el
CPython 3.14.5 x64 completo y verificado en
`C:\Program Files\AutomatonPython\3.14.5`, reconstruye `.venv` desde ese
intérprete y comprueba que Gateway solo tenga ReadAndExecute. El script es
dry-run por defecto y requiere `-Apply`; no arranca servicios ni accede a MT5.

ACLs separadas (la matriz exacta y sus limitaciones están en
[WINDOWS_ACL_MODEL.md](WINDOWS_ACL_MODEL.md)):

- `control`: administradores escriben; Gateway solo lee config, stop y
  autorización; Agent sin acceso.
- `ipc`: Gateway y Agent solo leen la key; el fichero no concede execute.
- `operational`: solo Gateway modifica lock, idempotencia y lifecycle.
- `research`: solo Gateway/SQLite modifica; Agent usa exclusivamente la API.
- `audit\sqlite`: Gateway necesita `Modify` para DB/WAL/SHM y no se presenta
  como inmutable.
- `audit\journal`: fichero precreado con `Read + AppendData + Synchronize`
  propuesto; su eficacia NTFS queda pendiente de tests negativos post-apply.
- `logs\gateway`: rotación UTC con `Modify`; `logs\security\security.log` no
  rota y usa el mismo patrón append propuesto que el journal.
- estado Agent: solo Agent modifica; Gateway sin acceso.
- código: Gateway y Agent solo lectura/ejecución, sin `Authenticated Users:M`.

## Operación

Ejecutar cada start bajo su identidad dedicada, nunca como administrador:

```powershell
.\scripts\start_gateway.ps1

$env:AUTOMATON_LAB_PROVIDER = 'openai' # o anthropic/ollama
$env:AUTOMATON_LAB_MODEL = 'MODELO_EXPLICITO'
.\scripts\start_automaton.ps1 `
  -AutomatonStateDir 'C:\Users\AutomatonAgent\.automaton'
```

Comandos disponibles: `status.ps1`, `stop.ps1` (dry-run/`-Apply`),
`test_gateway.ps1`, `disable_trading.ps1` y `emergency_stop.ps1`. El emergency
stop no depende de Python, Automaton ni del gateway y activa
`control\STOP_TRADING`. Un error o ambigüedad al comprobar ese fichero bloquea
fail-closed. Los logs `gateway` y `trading` rotan a medianoche UTC;
`security.log` y los journals de auditoría no rotan automáticamente. Agent
escribe un JSONL por día UTC en su estado privado.

Política de firewall a aplicar manualmente:

- bloquear toda entrada para ambos usuarios; el gateway solo escucha loopback;
- Agent: salida únicamente al proveedor de inferencia elegido (o loopback Ollama);
- Gateway: salida únicamente al terminal/broker MT5 necesario;
- GitHub, PyPI y NPM: solo durante mantenimiento humano, nunca en runtime.

## Evidencia y ciclo de investigación

El heartbeat consulta health cada 30 s sin LLM, velas cerradas M1 sin iniciar
más de un ciclo por barra y posiciones cada 5 s solo con exposición. Persistir
una decisión `HOLD|PROPOSE` exige que su timestamp coincida con la última M1
cerrada; existe una restricción única por barra.

`research.db` conserva strategy/setup/version, sesiones, régimen, timeframe,
PnL bruto/neto, comisión, swap, R, MFE, MAE, spreads, ATR, distancias, R:R,
duración, hora/día y calidad. Agrega por estrategia/version, setup, sesión,
hora, día, dirección, régimen y timeframe; reporta sample, wins/losses, winrate,
expectancy R, profit factor, drawdown, MFE/MAE, duración mediana e intervalo
bootstrap 95 % reproducible. `minimum_evidence_sample=30` solo marca elegibilidad;
no promociona hipótesis automáticamente.

## Readiness y gate DEMO

Con ambos procesos vivos, un administrador ejecuta:

```powershell
.\scripts\test_gateway.ps1
```

Genera un artefacto read-only con digest SHA-256 y exige simultáneamente MT5,
DEMO, login/servidor, XAUUSD, ticks, M1/M5/M15/H1, posiciones, historia,
auditoría dual, memoria, tools, inferencia fresca, identidades/ACL, suites y
`TRADING_MODE=OBSERVE_ONLY`. Solo entonces puede aparecer:

```text
AUTOMATON_MT5_LAB_READY=true
```

No hace falta ni se permite enviar una orden para alcanzar readiness. El script
`enable_demo_trading.ps1` es dry-run salvo `-Apply`, exige ese artefacto completo,
gateway detenido, y crea autorización externa ligada a login, servidor, hash de
configuración DEMO y hash del readiness. No debe ejecutarse en este milestone;
requiere una autorización humana posterior y separada.
