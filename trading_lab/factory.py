from __future__ import annotations

from .account_guard import AccountGuard
from .application import GatewayApplication
from .audit import HashChainAuditLog
from .authorization import FileExecutionAuthorization
from .config import SecurityConfig
from .execution_engine import ExecutionEngine
from .gateway import MT5Gateway
from .mt5_adapter import MT5Adapter
from .paper_engine import PaperEngine
from .position_sizer import PositionSizer
from .risk_engine import RiskEngine
from .research_store import ResearchStore
from .sqlite_audit import DualAuditLog


def build_application(
    config: SecurityConfig,
    adapter: MT5Adapter | None = None,
    *,
    runtime_identity_verified: bool = False,
) -> GatewayApplication:
    mt5 = adapter or MT5Adapter(config.mt5_terminal_path)
    guard = AccountGuard(
        config.authorized_account,
        config.authorized_server,
        config.authorized_account_name,
    )
    audit = (
        DualAuditLog(config.audit_path, config.audit_db_path)
        if config.audit_db_path is not None
        else HashChainAuditLog(config.audit_path)
    )
    research = ResearchStore(config.research_db_path)
    paper = PaperEngine(research, audit)
    risk = RiskEngine(config.allowed_symbol, config.magic_number, config.risk)
    gateway = MT5Gateway(
        mode=config.trading_mode,
        adapter=mt5,
        account_guard=guard,
        risk_engine=risk,
        execution_engine=ExecutionEngine(mt5),
        audit=audit,
        execution_authorization=FileExecutionAuthorization(
            config.demo_authorization_path, config.kill_switch_path
        ),
        research_store=research,
        paper_engine=paper,
    )
    return GatewayApplication(
        mode=config.trading_mode,
        allowed_symbol=config.allowed_symbol,
        adapter=mt5,
        account_guard=guard,
        gateway=gateway,
        audit=audit,
        research_store=research,
        paper_engine=paper,
        runtime_identity_verified=runtime_identity_verified,
        magic_number=config.magic_number,
        position_sizer=PositionSizer(mt5, config.risk),
    )
