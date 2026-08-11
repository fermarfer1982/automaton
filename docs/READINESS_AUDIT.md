# Auditoría de aceptación `AUTOMATON_MT5_LAB_READY`

Fecha de evidencia local: 2026-08-11. Rama:
`feature/mt5-demo-trading-lab`.

Este documento separa implementación de verificación live. Ninguna ausencia de
errores se interpreta como prueba de conexión MT5. El milestone solo será válido
cuando `trading_lab.readiness` observe simultáneamente todos los checks bajo las
identidades dedicadas y con `TRADING_MODE=OBSERVE_ONLY`.

## Evidencia ya demostrada localmente

| Requisito | Evidencia autoritativa | Estado |
|---|---|---|
| Cuenta/servidor/DEMO exactos, sin selección automática | `account_guard.py`, `mt5_adapter.py`, `test_account_guard.py`, `test_source_boundaries.py` | Probado con adaptador falso |
| XAUUSD, SL, exposición, riesgo, drawdown, spread, tick, stop/freeze, cooldown y duplicados | `risk_engine.py`, `management_risk.py`, `position_sizer.py` y sus tests | Probado localmente |
| Gates repetidos y envío serializado | `gateway.py`, `execution_engine.py`, `test_gateway.py`, `test_position_management.py` | Probado localmente |
| Resultado perdido y no-retry durable | `audit.py`, `execution_engine.py`, tests de gateway/gestión | Probado localmente |
| API `/v1` autenticada, loopback y esquema sin campos protegidos | `fastapi_service.py`, `api_models.py`, `test_http_service.py` | Probado localmente con FastAPI/httpx hash-locked |
| Auditoría JSON + SQLite concordante y append-only | `audit.py`, `sqlite_audit.py`, `test_audit.py`, `test_sqlite_audit.py` | Probado localmente |
| PAPER durable, SL/TP, cierre/modify y métricas | `paper_engine.py`, `research_store.py`, tests PAPER/research | Probado localmente |
| Contexto estadístico: PnL, R, MFE/MAE, sesiones, timeframe, ATR, spreads, distancias, R:R, régimen y confianza | esquema/migración 8 de `research_store.py` | Probado localmente |
| HOLD, lifecycle y memoria estructurada | `application.py`, `research_store.py`, tests lifecycle | Probado localmente |
| Tools HTTP y heartbeat por vela M1 | `src/trading/*`, tests TypeScript correspondientes | Typecheck/build y 12 tests de trading pasan |
| Perfil sin shell/pagos/replicación/install/push/self-mod de seguridad | `runtime-profile.ts`, `self-mod/code.ts`, tests source-boundary | Probado estáticamente |
| Scripts, ACL, kill switch independiente y enable DEMO humano | `scripts/*.ps1`, `operator.py`, tests ACL/operator | AST/tests locales; aplicación real pendiente |

La `.venv` local se instaló con `--require-hashes` y el lock CPython 3.14 x64.
La suite `pytest` ejecuta 126 tests y 6 subtests: todos pasan. TypeScript
typecheck y build pasan; Vitest ejecuta 69 ficheros y 1.656 tests: todos pasan,
incluidos los 5 ficheros/12 tests específicos de trading.

El runtime local fijado es Node v22.22.0 x64 en `.runtime/`, descargado de la
distribución oficial y verificado contra el SHA-256 publicado. Los scripts de
setup, arranque y pruebas resuelven ese binario exacto, vuelven a comprobar su
hash y rechazan una versión, arquitectura o binario reparse-point distintos.
Corepack ejecuta pnpm 10.28.1 de forma explícita; el install congelado y los
scripts nativos de `better-sqlite3` y `esbuild` se completaron correctamente.

## Evidencia todavía ausente por gates humanos

1. Creación manual de dos usuarios Windows distintos y no administradores, sin
   compartir contraseñas con el proyecto o el agente. La inspección confirmó
   que `AutomatonAgent` y `AutomatonGateway` todavía no existen; el script
   `New-TradingLabUsers.ps1` está preparado para que el humano introduzca ambas
   contraseñas como `SecureString` en una consola elevada.
2. Aplicación humana de ACL después de revisar el dry-run de SIDs y rutas.
3. Configuración protegida del login DEMO, servidor/nombre exactos, ruta del
   terminal y límites revisados; no contiene contraseña.
4. Selección explícita del proveedor/modelo y claves solo en el entorno Agent.
5. Terminal MT5 visible bajo Gateway y smoke test live exclusivamente read-only.
6. Gateway y Automaton activos bajo sus identidades, con evidencia fresca de
   tools/inferencia y cero exposición.

Hasta completar esos puntos, el único informe honesto es:

```text
AUTOMATON_MT5_LAB_READY=false
MT5_CONNECTED=false
DEMO_VERIFIED=false
ACCOUNT_ALLOWED=false
SERVER_ALLOWED=false
XAUUSD_AVAILABLE=false
GATEWAY_HEALTH=false
AUTOMATON_TOOLS_READY=false
AUDIT_READY=false
RISK_TESTS=false
SECURITY_TESTS=false
TRADING_MODE=UNVERIFIED
```

Solo se instalaron la `.venv` hash-locked, Node v22.22.0 x64 portable, pnpm
10.28.1 mediante Corepack y las dependencias Node del lock. No se ha aplicado
ACL, leído una cuenta live, enviado una orden ni habilitado `DEMO_EXECUTION`.
Cuando el informe pase a `true`, el proceso debe detenerse y solicitar una
autorización humana nueva antes de cualquier ejecución DEMO.
