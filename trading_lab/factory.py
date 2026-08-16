from __future__ import annotations

from .account_guard import AccountGuard
from .application import GatewayApplication
from .audit import HashChainAuditLog
from .authorization import FileExecutionAuthorization
from .config import SecurityConfig, security_config_hash
from .execution_engine import ExecutionEngine
from .gateway import MT5Gateway
from .mt5_adapter import MT5Adapter
from .mt5_access import MT5AccessDisabled
from .paper_engine import PaperEngine
from .position_sizer import PositionSizer
from .providers import LiveMT5MarketDataProvider, MT5ExecutionProvider
from .risk_engine import RiskEngine
from .research_store import ResearchStore
from .sqlite_audit import DualAuditLog


def build_application(
    config: SecurityConfig,
    adapter: MT5Adapter | None = None,
    *,
    runtime_identity_verified: bool = False,
) -> GatewayApplication:
    if not config.mt5_access_enabled:
        raise MT5AccessDisabled()
    mt5 = adapter or MT5ExecutionProvider(config.mt5_terminal_path)
    market_data = LiveMT5MarketDataProvider(mt5)
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
        adapter=market_data,
        account_guard=guard,
        risk_engine=risk,
        execution_engine=ExecutionEngine(mt5, config.risk.max_deviation_points),
        audit=audit,
        execution_authorization=FileExecutionAuthorization(
            config.demo_authorization_path,
            config.kill_switch_path,
            expected_account=config.authorized_account,
            expected_server=config.authorized_server,
            expected_config_hash=security_config_hash(config),
        ),
        research_store=research,
        paper_engine=paper,
    )
    return GatewayApplication(
        mode=config.trading_mode,
        allowed_symbol=config.allowed_symbol,
        adapter=market_data,
        account_guard=guard,
        gateway=gateway,
        audit=audit,
        research_store=research,
        paper_engine=paper,
        runtime_identity_verified=runtime_identity_verified,
        magic_number=config.magic_number,
        position_sizer=PositionSizer(mt5, config.risk),
        risk_limits=config.risk,
    )
