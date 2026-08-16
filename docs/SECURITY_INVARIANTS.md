# Invariantes de seguridad del laboratorio MT5

Este perfil es un laboratorio aislado y *fail-closed*. No hereda las capacidades soberanas del perfil upstream. Su estado inicial y único autorizado durante el milestone es `OBSERVE_ONLY`.

## Límites permanentes

1. **S1 — Cuenta autorizada.** Solo se acepta el login DEMO escrito por un humano en la configuración protegida.
2. **S2 — Solo DEMO.** Una cuenta REAL, desconocida o desconectada bloquea toda mutación.
3. **S3 — Servidor autorizado.** Solo se acepta el servidor escrito por un humano; el gateway nunca llama a `login()` ni busca otra cuenta.
4. **S4 — Símbolo permitido.** Solo se observa y gestiona `XAUUSD`; el gateway nunca llama a `symbol_select()`.
5. **S5 — Sin MT5 directo.** El agente propone semántica y riesgo monetario; no puede aportar login, servidor, modo, magic, volumen ni una orden MT5.
6. **S6 — Riesgo independiente.** Account Guard, Risk Engine y Execution Engine son deterministas e independientes del LLM.
7. **S7 — Gates obligatorios.** Toda apertura atraviesa `PRE_FLIGHT_CHECK`, `POST_LLM_CHECK`, `order_check()` y `PRE_EXECUTION_CHECK`; cualquier excepción deniega.
8. **S8 — Credenciales fuera de contexto.** Claves y contraseñas no pertenecen a configuración, auditoría, memoria, prompts ni respuestas.
9. **S9 — Seguridad no automodificable.** Self-modification no puede cambiar gateway, guards, riesgo, ejecución, configuración protegida, auditoría, scripts de seguridad ni este documento.
10. **S10 — Ejecución auditada.** `order_send()` está confinado al adaptador MT5, solo Execution Engine puede secuenciarlo y cada intento queda auditado.
11. **S11 — Error implica DENY.** La divergencia de stores, excepciones o verificaciones incompletas bloquean operaciones.
12. **S12 — Nunca cambiar de cuenta.** No existe selección, búsqueda ni recuperación automática mediante otra cuenta o servidor.
13. **S13 — Exposición única.** Cualquier posición u orden de la cuenta bloquea una apertura nueva; solo tickets `XAUUSD` con magic propio admiten gestión.
14. **S14 — Sin escalado de pérdidas.** SL es obligatorio; grid, martingala, averaging down, ampliar SL y aumentar una posición perdedora están prohibidos.
15. **S15 — Incertidumbre durable.** Una respuesta perdida tras autorizar el envío produce `EXECUTION_UNCERTAIN`; no hay reintento automático.
16. **S16 — IPC local autenticado.** La API escucha solo en `127.0.0.1`; todas las rutas `/v1` exigen exactamente una clave IPC externa.
17. **S17 — Kill switch independiente.** Su existencia bloquea aperturas y solo permite gestión validada reductora; un error o estado ambiguo al comprobarlo bloquea fail-closed.
18. **S18 — Habilitación humana.** `DEMO_EXECUTION` vincula cuenta, servidor, configuración y readiness completo en `OBSERVE_ONLY`.
19. **S19 — Privilegio mínimo.** Gateway y Automaton requieren usuarios Windows distintos, no administradores, y ACL verificadas.
20. **S20 — Evidencia antes de conclusión.** La elegibilidad estadística empieza en 30 observaciones y nunca promociona automáticamente hipótesis.
21. **S21 — Perfil sin capacidades externas.** Shell, instalaciones, pagos, wallet, replicación, social, orquestación y `git push` quedan fuera del allowlist.
22. **S22 — ACL por dominio.** No existe un árbol global de datos Gateway con `Modify`; control/IPC son read-only, SQLite se reconoce mutable y journal/security log usan privilegio append propuesto pendiente de validación real post-apply.
23. **S23 — Acceso MT5 explícito.** `MT5_ACCESS_ENABLED` es un control protegido e independiente de `TRADING_MODE`, con valor predeterminado `false`. Mientras esté deshabilitado, el proceso no importa ni accede a MetaTrader5 y solo expone salud autenticada; el entorno puede restringir el valor protegido, pero nunca habilitarlo.

## Pruebas que sostienen el límite

- `tests/test_account_guard.py`, `tests/test_risk_engine.py` y `tests/test_position_sizer.py`: cuenta, mercado, exposición y sizing.
- `tests/test_gateway.py` y `tests/test_position_management.py`: gates, serialización, gestión reductora y estados inciertos.
- `tests/test_source_boundaries.py`: ausencia de selección/login y confinamiento de ejecución/capacidades.
- `tests/test_audit.py`, `tests/test_sqlite_audit.py` y `tests/test_research_store.py`: redacción, integridad, append-only y evidencia.
- `tests/test_http_service.py`, `tests/test_api_auth.py`: autenticación y contrato HTTP.
- `tests/test_health_only_startup.py` y `tests/Test-RuntimeAclScripts.ps1`: arranque health-only sin importar MT5, confinamiento loopback y harness controlado por PID propio.
- `tests/test_windows_acl.py`, `tests/test_authorization.py` y `tests/test_operator.py`: identidades, autorización externa y controles humanos.

Cambiar cualquiera de estos límites exige revisión humana explícita, tests previos y una nueva versión de la política. Nunca es una tarea de self-modification del agente.
