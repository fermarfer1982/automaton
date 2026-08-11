# Invariantes de seguridad del laboratorio MT5

Este perfil es un laboratorio aislado y *fail-closed*. No hereda las capacidades soberanas del perfil upstream. Su estado inicial y único autorizado durante el milestone es `OBSERVE_ONLY`.

## Límites permanentes

1. Solo se acepta el login DEMO escrito por un humano en la configuración protegida.
2. Solo se acepta el servidor escrito por un humano; el gateway nunca llama a `login()` ni busca otra cuenta.
3. Solo se observa y gestiona `XAUUSD`; el gateway nunca llama a `symbol_select()`.
4. Una cuenta REAL, desconocida o desconectada bloquea toda mutación.
5. Credenciales, claves de proveedor y contraseñas no pertenecen a la configuración, auditoría, memoria, prompts ni respuestas.
6. El agente propone semántica y riesgo monetario. No puede aportar login, servidor, modo, magic, volumen ni una orden MT5.
7. Account Guard, Risk Engine y Execution Engine son deterministas e independientes del LLM.
8. Toda apertura atraviesa `PRE_FLIGHT_CHECK`, `POST_LLM_CHECK`, `order_check()` y `PRE_EXECUTION_CHECK`; cualquier excepción deniega.
9. `order_send()` está confinado al adaptador MT5 y solo el Execution Engine puede secuenciarlo.
10. Cualquier posición u orden de la cuenta bloquea una apertura nueva. Solo tickets `XAUUSD` con magic propio admiten gestión.
11. SL es obligatorio; grid, martingala, averaging down, ampliar SL y aumentar una posición perdedora están prohibidos estructuralmente.
12. Una respuesta perdida tras autorizar el envío produce `EXECUTION_UNCERTAIN`; no hay reintento automático.
13. El journal JSON hash-chain y `audit.db` deben coincidir. La divergencia o fallo de cualquier store bloquea operaciones.
14. La API escucha solo en `127.0.0.1`; todas las rutas `/v1` exigen exactamente una clave IPC externa.
15. El kill switch es externo al agente y prevalece sobre cualquier autorización.
16. `DEMO_EXECUTION` requiere una acción humana que vincula cuenta, servidor, hash de configuración y readiness completo en `OBSERVE_ONLY`.
17. Gateway y Automaton requieren usuarios Windows distintos, no administradores, y ACL verificadas antes del acceso a MT5 o inferencia.
18. Self-modification no puede cambiar gateway, guards, riesgo, ejecución, configuración protegida, auditoría, scripts de seguridad ni este documento.
19. El perfil trading excluye shell, instalaciones, pagos, wallet, replicación, social, orquestación y `git push`.
20. Ninguna evidencia aislada promociona una hipótesis: la elegibilidad estadística empieza en 30 observaciones y no implica aprobación automática.

## Pruebas que sostienen el límite

- `tests/test_account_guard.py`, `tests/test_risk_engine.py` y `tests/test_position_sizer.py`: cuenta, mercado, exposición y sizing.
- `tests/test_gateway.py`, `tests/test_position_management.py` y `tests/test_execution_uncertain.py`: gates, serialización, gestión reductora y estados inciertos.
- `tests/test_source_boundaries.py`: ausencia de selección/login y confinamiento de ejecución/capacidades.
- `tests/test_audit.py`, `tests/test_sqlite_audit.py` y `tests/test_research_store.py`: redacción, integridad, append-only y evidencia.
- `tests/test_http_service.py`, `tests/test_api_auth.py`: autenticación y contrato HTTP.
- `tests/test_windows_acl.py`, `tests/test_authorization.py` y `tests/test_operator.py`: identidades, autorización externa y controles humanos.

Cambiar cualquiera de estos límites exige revisión humana explícita, tests previos y una nueva versión de la política. Nunca es una tarea de self-modification del agente.
