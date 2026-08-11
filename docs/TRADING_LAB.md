# Automaton MT5 Laboratory

This repository runs Conway Automaton with a restricted trading profile and a
separate deterministic Windows gateway. The initial and milestone mode is
always `OBSERVE_ONLY`; no code path changes it in response to an agent request.

## Trust boundary

```text
Automaton
  -> restricted Trading Tools (loopback HTTP only)
  -> MT5 Gateway (serialized, fail-closed)
  -> Account Guard (exact login + exact server + DEMO)
  -> Risk Engine (pure deterministic policy)
  -> Execution Engine (order_check before order_send)
  -> MetaTrader 5 terminal
```

The service receives no MT5 password. `MT5Adapter.initialize()` is called with
only the exact terminal executable path and never calls `login()` or
`symbol_select()`. The already logged-in terminal account must match the
external protected configuration exactly or every request fails closed.
The gateway also refuses to initialize unless that exact executable already has
a visible window in the gateway process's current Windows session; it never
auto-launches a hidden terminal or relies on another user's MT5 session.

The agent-facing API has only:

- `GET /v1/health`
- `GET /v1/market/XAUUSD`
- `GET /v1/research/metrics`
- `POST /v1/proposals`

There is no execution endpoint, account selector, login endpoint, mode setter,
or credentials field. In `OBSERVE_ONLY` and `PAPER`, neither `order_check()` nor
`order_send()` can be called. In `DEMO_EXECUTION`, both an external human allow
file containing exactly `ALLOW_DEMO_EXECUTION` and an absent kill-switch file
are required. The kill switch always wins.

Once `order_send()` has been attempted, a timeout, lost response, or failure to
persist its result is returned as `EXECUTION_UNCERTAIN`, never as a safe
rejection. The pre-send fingerprint remains durable, blocks automatic retry,
and requires human reconciliation with MT5 history.

## Protected external configuration

Copy `config/trading.security.example.json` manually to:

```text
C:\ProgramData\AutomatonMT5Lab\control\security.json
```

Replace only the exact authorized DEMO account number and DEMO server after
verifying them in the visible MT5 terminal. Keep `trading_mode` equal to
`OBSERVE_ONLY`. Never put a password, API key, token, or private key in this
file. The loader rejects credential-shaped fields recursively.

Create two distinct standard (non-administrator) Windows identities first:
one for the interactive MT5 terminal plus gateway, and another for Automaton.
Passwords remain human-managed and must never be placed in this repository or
passed to the agent. As Administrator, inspect the ACL plan and apply it only
after checking the resolved SIDs and paths:

```powershell
.\scripts\Initialize-TradingLabAcl.ps1 `
  -GatewayIdentity 'MACHINE\AutomatonMT5Gateway' `
  -AutomatonIdentity 'MACHINE\AutomatonLabAgent' `
  -AutomatonStateDir 'C:\Users\AutomatonLabAgent\.automaton'

.\scripts\Initialize-TradingLabAcl.ps1 `
  -GatewayIdentity 'MACHINE\AutomatonMT5Gateway' `
  -AutomatonIdentity 'MACHINE\AutomatonLabAgent' `
  -AutomatonStateDir 'C:\Users\AutomatonLabAgent\.automaton' `
  -Apply
```

The script does not create users, set passwords, install software, configure
MT5, or copy `security.json`. Without `-Apply` it is read-only. With `-Apply` it
refuses broad/workspace/overlapping targets, administrator identities, signing
wallets, and reparse-point trees before changing ACLs. Run MT5 and the gateway
as the configured gateway identity; log into the authorized DEMO manually in
the visible terminal. Run Automaton only as the configured agent identity.

The operational paths must remain outside `C:\automaton` and use three distinct
ACL domains: read-only gateway control (`security.json`, authorization, kill
switch), gateway-writable data (`audit.jsonl`, `research.db`), and
Automaton-writable state. Automaton must have no access to gateway control/data;
the gateway must have no access to Automaton state and cannot write its own
authorization or kill switch. Directory inheritance must be disabled. Startup
and readiness inspect Windows SIDs and ACL rights and fail closed if this exact
separation is absent; they never create accounts or change ACLs automatically.
The same verifier requires both runtime identities to have read/execute but no
write, delete, ownership, or ACL-changing rights over the workspace and every
protected security source. Install and build as Administrator; runtime state
belongs only in the external Automaton state directory.

The gateway-owned `research.db` records hypothesis, strategy/setup/version,
session, market regime, proposal status, and closed-trade evidence. Aggregates
include sample size, PnL, R expectancy, profit factor, win rate, MFE, MAE, and
maximum drawdown. A result is not labelled evidence-sufficient below 30 closed
trades; this threshold is a guard against learning from isolated outcomes, not a
claim that 30 observations guarantee statistical significance.

`PAPER` uses persistent virtual positions in that database. It fills buys at
ask and sells at bid, marks exits at the opposite executable quote, survives
gateway restarts, records SL/TP closure plus PnL/R/MFE/MAE, and feeds open PAPER
exposure and the more conservative of live/PAPER daily PnL back into the same
Risk Engine. It still has no path to `order_check()` or `order_send()`.

## Commands

The pure safety suite uses only the Python standard library:

```powershell
python -m unittest discover -s tests -p 'test_*.py' -v
```

The MT5 dependency is pinned for this Windows CPython 3.14 environment in
`requirements-mt5.txt`. Installation is intentionally a human-authorized step.
After it is installed and the protected configuration exists, start the visible
MT5 terminal and gateway as the configured gateway identity. The service proves
its current SID before initializing MT5:

```powershell
python -m trading_lab.service --config C:\ProgramData\AutomatonMT5Lab\control\security.json
```

The standard Conway setup/provision/configure flows are disabled by default in
the trading profile because upstream can provision services, register identity,
start social/financial heartbeats, and buy credits. After the Node dependencies
are explicitly authorized and installed, one explicit human command creates a
non-signing public laboratory identifier and the restricted configuration:

```powershell
$env:AUTOMATON_STATE_DIR = 'C:\Users\AutomatonLabAgent\.automaton'
$env:AUTOMATON_LAB_PROVIDER = 'openai'  # or anthropic / ollama
$env:AUTOMATON_LAB_MODEL = 'YOUR_EXPLICIT_MODEL'
node dist/index.js --setup-trading-lab
node dist/index.js --run
```

The public identifier has no private key and all signing methods fail closed;
the normal `--init` signing-wallet path is disabled in the default trading
profile. Lab setup writes zero treasury limits, disables social/replication, and
persists no provider key. Supply `OPENAI_API_KEY` or
`ANTHROPIC_API_KEY` only in the runtime service environment. For Ollama, use a
credential-free loopback `OLLAMA_BASE_URL`. Never paste these credentials into
the genesis prompt, trading security JSON, research database, or agent memory.
Readiness also requires `wallet.json` to be absent from the Automaton identity's
state directory; use a dedicated Windows identity rather than reusing an
upstream Automaton profile that contains signing material.

Finally, run readiness from a separate Administrator terminal while both
processes are alive:

```powershell
python -m trading_lab.readiness --config C:\ProgramData\AutomatonMT5Lab\control\security.json
```

Readiness contacts MT5 only through the loopback gateway. It requires fresh
non-secret runtime evidence showing that Automaton completed inference and used
both the guarded health and XAUUSD observation tools; it never requires the
provider key in the Administrator environment.

The readiness command returns nonzero and prints
`AUTOMATON_MT5_LAB_READY=false` unless every live check and security test passes
while the configured mode remains `OBSERVE_ONLY`.

## Explicitly disabled in the trading profile

The default `AUTOMATON_RUNTIME_PROFILE=trading_lab` allowlist excludes shell
execution, source edits, package/skill/MCP installation, Git push, payments,
credit transfers, x402, domains, sandbox creation, replication, child funding,
and social messaging. `AUTOMATON_RUNTIME_PROFILE=upstream` exists solely for
upstream compatibility and must never be used by the trading laboratory without
an explicit human security review.
