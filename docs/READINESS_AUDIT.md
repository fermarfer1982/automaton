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
| API `/v1` autenticada, loopback y esquema sin campos protegidos | `fastapi_service.py`, `api_models.py`, `test_http_service.py` | Código completo; tests HTTP pendientes de dependencias |
| Auditoría JSON + SQLite concordante y append-only | `audit.py`, `sqlite_audit.py`, `test_audit.py`, `test_sqlite_audit.py` | Probado localmente |
| PAPER durable, SL/TP, cierre/modify y métricas | `paper_engine.py`, `research_store.py`, tests PAPER/research | Probado localmente |
| Contexto estadístico: PnL, R, MFE/MAE, sesiones, timeframe, ATR, spreads, distancias, R:R, régimen y confianza | esquema/migración 8 de `research_store.py` | Probado localmente |
| HOLD, lifecycle y memoria estructurada | `application.py`, `research_store.py`, tests lifecycle | Probado localmente |
| Tools HTTP y heartbeat por vela M1 | `src/trading/*`, tests TypeScript correspondientes | Implementado; build/tests Node pendientes |
| Perfil sin shell/pagos/replicación/install/push/self-mod de seguridad | `runtime-profile.ts`, `self-mod/code.ts`, tests source-boundary | Probado estáticamente |
| Scripts, ACL, kill switch independiente y enable DEMO humano | `scripts/*.ps1`, `operator.py`, tests ACL/operator | AST/tests locales; aplicación real pendiente |

La suite estándar actual ejecuta 122 tests: 119 pasan y 3 se omiten porque las
dependencias FastAPI/httpx/Pydantic hash-locked todavía no están instaladas.
`pytest`, typecheck, build y Vitest no pueden considerarse verdes hasta instalar
las dependencias revisadas.

## Evidencia todavía ausente por gates humanos

1. Instalación de `.venv` con el lock CPython 3.14 x64 y ejecución de
   `pnpm install --frozen-lockfile` con pnpm 10.28.1.
2. Creación manual de dos usuarios Windows distintos y no administradores, sin
   compartir contraseñas con el proyecto o el agente.
3. Aplicación humana de ACL después de revisar el dry-run de SIDs y rutas.
4. Configuración protegida del login DEMO, servidor/nombre exactos, ruta del
   terminal y límites revisados; no contiene contraseña.
5. Selección explícita del proveedor/modelo y claves solo en el entorno Agent.
6. Terminal MT5 visible bajo Gateway y smoke test live exclusivamente read-only.
7. Gateway y Automaton activos bajo sus identidades, con evidencia fresca de
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

No se ha instalado software, aplicado ACL, leído una cuenta live, enviado una
orden ni habilitado `DEMO_EXECUTION`. Cuando el informe pase a `true`, el proceso
debe detenerse y solicitar una autorización humana nueva antes de cualquier
ejecución DEMO.
