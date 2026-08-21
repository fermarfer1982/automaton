from __future__ import annotations

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .api_auth import ApiKeyVerifier


OBSERVATION_HEADER = (
    "X-AUTOMATON-OBSERVATION-KEY"
)


def create_observation_api(
    application,
    verifier: ApiKeyVerifier,
    collector_loop=None,
) -> FastAPI:
    app = FastAPI(
        title="Automaton MT5 Observation Service",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def authenticate(
        x_automaton_observation_key: str | None = Header(
            default=None,
            alias=OBSERVATION_HEADER,
        ),
    ) -> None:
        if not verifier.verify(
            x_automaton_observation_key
        ):
            from fastapi import HTTPException

            raise HTTPException(
                status_code=401,
                detail="invalid_observation_key",
            )

    protected = [
        Depends(authenticate)
    ]

    @app.middleware("http")
    async def observation_boundary(
        request: Request,
        call_next,
    ):
        if request.url.path.startswith("/v1"):
            keys = request.headers.getlist(
                OBSERVATION_HEADER.lower()
            )

            if (
                len(keys) != 1
                or not verifier.verify(keys[0])
            ):
                return JSONResponse(
                    status_code=401,
                    content={
                        "error":
                        "invalid_observation_key"
                    },
                )

            if request.method != "GET":
                return JSONResponse(
                    status_code=405,
                    content={
                        "error":
                        "observation_service_is_get_only"
                    },
                )

        response = await call_next(request)

        response.headers[
            "Cache-Control"
        ] = "no-store"

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        return response

    @app.exception_handler(
        RequestValidationError
    )
    async def validation_error(
        _request: Request,
        _exc: RequestValidationError,
    ):
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request"
            },
        )

    @app.exception_handler(ValueError)
    async def invalid_domain(
        _request: Request,
        _exc: ValueError,
    ):
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request"
            },
        )

    @app.exception_handler(RuntimeError)
    async def unavailable(
        _request: Request,
        _exc: RuntimeError,
    ):
        return JSONResponse(
            status_code=503,
            content={
                "error":
                "observation_unavailable"
            },
        )

    @app.get("/health")
    def health():
        worker = application.status()

        collector = (
            None
            if collector_loop is None
            else collector_loop.health()
        )

        collector_healthy = (
            collector is None
            or (
                collector.get("running") is True
                and collector.get(
                    "consecutive_errors"
                ) == 0
            )
        )

        return {
            "status": (
                "HEALTHY"
                if collector_healthy
                else "DEGRADED"
            ),
            "service": worker.get(
                "service",
                "automaton-mt5-observation",
            ),
            "mode": worker.get(
                "mode",
                "OBSERVE_ONLY",
            ),
            "execution_capable": False,
            "worker": worker,
            "collector": collector,
        }

    @app.get(
        "/v1/status",
        dependencies=protected,
    )
    def status():
        return application.status()

    @app.get(
        "/v1/account",
        dependencies=protected,
    )
    def account():
        return application.account_state()

    @app.get(
        "/v1/market/{symbol}",
        dependencies=protected,
    )
    def market(symbol: str):
        return application.market_snapshot(
            symbol
        )

    @app.get(
        "/v1/candles/{symbol}",
        dependencies=protected,
    )
    def candles(
        symbol: str,
        timeframe: str = Query(),
        count: int = Query(
            ge=1,
            le=500,
        ),
    ):
        return application.candles(
            symbol,
            timeframe,
            count,
        )

    @app.get(
        "/v1/history",
        dependencies=protected,
    )
    def history(
        from_utc: str = Query(alias="from"),
        to_utc: str = Query(alias="to"),
        symbol: str = Query(
            default="XAUUSD"
        ),
        limit: int = Query(
            default=100,
            ge=1,
            le=1000,
        ),
    ):
        return application.history_state(
            from_utc=from_utc,
            to_utc=to_utc,
            symbol=symbol,
            limit=limit,
        )

    @app.get(
        "/v1/positions",
        dependencies=protected,
    )
    def positions():
        return application.positions_state()

    @app.get(
        "/v1/active-orders",
        dependencies=protected,
    )
    def active_orders():
        return application.active_orders_state()

    @app.get(
        "/v1/daily-stats",
        dependencies=protected,
    )
    def daily_stats():
        return application.daily_stats()

    return app
