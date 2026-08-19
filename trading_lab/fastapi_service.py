from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .api_auth import ApiKeyVerifier
from .api_models import (
    CancelPendingBody,
    ClosePositionBody,
    DecisionBody,
    HypothesisBody,
    ModifyPositionBody,
    ProposeTradeBody,
    ReviewBody,
)
from .domain import SemanticTradeRequest
from .mt5_access import MT5AccessDisabled


MAX_REQUEST_BYTES = 64 * 1024


def create_fastapi_app(
    application,
    verifier: ApiKeyVerifier,
    *,
    research_verifier: ApiKeyVerifier | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Automaton MT5 Gateway",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    research_split_enabled = (
        research_verifier is not None
    )

    active_research_verifier = (
        research_verifier
        if research_verifier is not None
        else verifier
    )

    def is_research_path(
        path: str,
    ) -> bool:
        return (
            path == "/v1/research"
            or path.startswith(
                "/v1/research/"
            )
        )

    def authenticate_gateway(
        x_automaton_key: str | None = Header(
            default=None,
            alias="X-AUTOMATON-KEY",
        ),
        x_automaton_research_key: str | None = Header(
            default=None,
            alias="X-AUTOMATON-RESEARCH-KEY",
        ),
    ) -> None:
        if (
            research_split_enabled
            and x_automaton_research_key is not None
        ):
            raise HTTPException(
                status_code=401,
                detail="invalid_gateway_key",
            )

        if not verifier.verify(
            x_automaton_key
        ):
            raise HTTPException(
                status_code=401,
                detail="invalid_gateway_key",
            )

    def authenticate_research(
        x_automaton_key: str | None = Header(
            default=None,
            alias="X-AUTOMATON-KEY",
        ),
        x_automaton_research_key: str | None = Header(
            default=None,
            alias="X-AUTOMATON-RESEARCH-KEY",
        ),
    ) -> None:
        if research_split_enabled:
            if (
                x_automaton_key is not None
                or not active_research_verifier.verify(
                    x_automaton_research_key
                )
            ):
                raise HTTPException(
                    status_code=401,
                    detail="invalid_research_key",
                )

            return

        if not verifier.verify(
            x_automaton_key
        ):
            raise HTTPException(
                status_code=401,
                detail="invalid_gateway_key",
            )

    gateway_protected = [
        Depends(authenticate_gateway)
    ]

    research_protected = [
        Depends(authenticate_research)
    ]

    # Backward-compatible name retained for the historical
    # health-route source boundary. It is exactly the
    # gateway credential boundary, never the research one.
    protected = gateway_protected

    @app.middleware("http")
    async def security_boundary(
        request: Request,
        call_next,
    ):
        if request.url.path.startswith("/v1"):
            gateway_keys = (
                request.headers.getlist(
                    "x-automaton-key"
                )
            )

            research_keys = (
                request.headers.getlist(
                    "x-automaton-research-key"
                )
            )

            if (
                research_split_enabled
                and is_research_path(request.url.path)
            ):
                if (
                    len(gateway_keys) != 0
                    or len(research_keys) != 1
                    or not active_research_verifier.verify(
                        research_keys[0]
                    )
                ):
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error":
                                "invalid_research_key"
                        },
                    )

            else:
                if (
                    len(gateway_keys) != 1
                    or not verifier.verify(
                        gateway_keys[0]
                    )
                    or (
                        research_split_enabled
                        and len(research_keys) != 0
                    )
                ):
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error":
                                "invalid_gateway_key"
                        },
                    )

            if request.method in {
                "POST",
                "PUT",
                "PATCH",
            }:
                raw_length = request.headers.get(
                    "content-length"
                )

                try:
                    length = int(
                        raw_length or ""
                    )
                except ValueError:
                    length = -1

                if (
                    length < 1
                    or length > MAX_REQUEST_BYTES
                ):
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error":
                                "invalid_request_size"
                        },
                    )

        response = await call_next(
            request
        )

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

    @app.exception_handler(
        FileExistsError
    )
    async def idempotency_conflict(
        _request: Request,
        _exc: FileExistsError,
    ):
        return JSONResponse(
            status_code=409,
            content={
                "error":
                    "idempotency_conflict"
            },
        )

    @app.exception_handler(
        LookupError
    )
    async def not_found(
        _request: Request,
        _exc: LookupError,
    ):
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found"
            },
        )

    @app.exception_handler(
        ValueError
    )
    async def invalid_domain(
        _request: Request,
        _exc: ValueError,
    ):
        return JSONResponse(
            status_code=422,
            content={
                "error":
                    "invalid_request"
            },
        )

    @app.exception_handler(
        RuntimeError
    )
    async def unavailable(
        _request: Request,
        exc: RuntimeError,
    ):
        return JSONResponse(
            status_code=503,
            content={
                "error":
                    "fail_closed",
                "error_type":
                    type(exc).__name__,
            },
        )

    @app.exception_handler(
        MT5AccessDisabled
    )
    async def mt5_access_disabled(
        _request: Request,
        _exc: MT5AccessDisabled,
    ):
        return JSONResponse(
            status_code=503,
            content={
                "error":
                    "fail_closed",
                "code":
                    "MT5_ACCESS_DISABLED",
            },
        )

    @app.get("/health", dependencies=protected)
    def startup_health():
        return application.health()

    @app.get(
        "/v1/health",
        dependencies=gateway_protected,
    )
    def health():
        return application.health()

    @app.get(
        "/v1/status",
        dependencies=gateway_protected,
    )
    def status():
        return application.status()

    @app.get(
        "/v1/account",
        dependencies=gateway_protected,
    )
    def account():
        return application.account_state()

    @app.get(
        "/v1/market/{symbol}",
        dependencies=gateway_protected,
    )
    def market(
        symbol: str,
    ):
        return application.market_snapshot(
            symbol
        )

    @app.get(
        "/v1/candles/{symbol}",
        dependencies=gateway_protected,
    )
    def candles(
        symbol: str,
        timeframe: str = Query(
            pattern="^(M1|M5|M15|H1)$"
        ),
        count: int = Query(
            default=100,
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
        "/v1/positions",
        dependencies=gateway_protected,
    )
    def positions():
        return application.positions_state()

    @app.get(
        "/v1/positions/{ticket}",
        dependencies=gateway_protected,
    )
    def position(
        ticket: int,
    ):
        return application.position_state(
            ticket
        )

    @app.get(
        "/v1/history",
        dependencies=gateway_protected,
    )
    def history(
        from_utc: datetime = Query(
            alias="from"
        ),
        to_utc: datetime = Query(
            alias="to"
        ),
        symbol: Literal[
            "XAUUSD"
        ] = "XAUUSD",
        limit: int = Query(
            default=1000,
            ge=1,
            le=1000,
        ),
    ):
        return application.history(
            from_utc,
            to_utc,
            symbol=symbol,
            limit=limit,
        )

    @app.get(
        "/v1/daily-stats",
        dependencies=gateway_protected,
    )
    def daily_stats():
        return application.daily_stats()

    @app.post(
        "/v1/trade/propose",
        dependencies=gateway_protected,
    )
    def propose(
        body: ProposeTradeBody,
        idempotency_key: str = Header(
            alias="Idempotency-Key"
        ),
    ):
        return application.propose_semantic(
            SemanticTradeRequest(
                idempotency_key=idempotency_key,
                **body.model_dump(),
            )
        )

    @app.post(
        "/v1/trade/close",
        dependencies=gateway_protected,
    )
    def close(
        body: ClosePositionBody,
    ):
        return application.manage_position(
            "CLOSE",
            body.model_dump(),
        )

    @app.post(
        "/v1/trade/modify",
        dependencies=gateway_protected,
    )
    def modify(
        body: ModifyPositionBody,
    ):
        return application.manage_position(
            "MODIFY",
            body.model_dump(),
        )

    @app.post(
        "/v1/trade/cancel-pending",
        dependencies=gateway_protected,
    )
    def cancel_pending(
        body: CancelPendingBody,
    ):
        return application.manage_position(
            "CANCEL_PENDING",
            body.model_dump(),
        )

    @app.post(
        "/v1/research/decisions",
        dependencies=research_protected,
    )
    def decisions(
        body: DecisionBody,
    ):
        payload = body.model_dump()

        payload["bar_time_utc"] = (
            payload[
                "bar_time_utc"
            ].isoformat()
        )

        return application.record_decision(
            payload
        )

    @app.post(
        "/v1/research/hypotheses",
        dependencies=research_protected,
    )
    def hypotheses(
        body: HypothesisBody,
    ):
        return application.save_hypothesis(
            body.hypothesis_id,
            body.thesis,
        )

    @app.post(
        "/v1/research/reviews",
        dependencies=research_protected,
    )
    def reviews(
        body: ReviewBody,
    ):
        return application.save_trade_review(
            body.model_dump()
        )

    @app.get(
        "/v1/research/metrics",
        dependencies=research_protected,
    )
    def metrics():
        return application.research_metrics()

    @app.get(
        "/v1/research/memory",
        dependencies=research_protected,
    )
    def memory(
        limit: int = Query(
            default=50,
            ge=1,
            le=200,
        ),
    ):
        return application.recent_memory(
            limit
        )

    return app