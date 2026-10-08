# AgentShield Architecture

## 1. Separation of Concerns
AgentShield strictly separates the **AI Agent Client** (`backend/agent/`) from the **Runtime Security Gateway** (`backend/gateway/`) and the **Sandboxed Tool Execution Layer** (`backend/tools/`).

1. **AI Agent Service (`backend/agent/`)**:
   - Receives natural language tasks via `POST /agent/tasks`.
   - Reasons over tool schemas exposed by `AgentToolRegistry` (metadata only; no raw execution bindings).
   - Emits standardized `ToolRequestPayload` objects to `AgentGatewayClient`.
2. **AgentShield Runtime Interceptor (`backend/gateway/interceptor.py`)**:
   - Executes a deterministic 16-step inspection pipeline on every `POST /tool-request`.
   - Orchestrates Context Trust, Policy Engine, Behavior Analysis, Attack-Chain Correlation, Multi-Signal Risk Scoring, and Decision/Containment engines.
   - Issues single-use HMAC-SHA256 execution tokens only on `ALLOW` decisions.
3. **Controlled Tool Sandbox (`backend/tools/`)**:
   - Validates the gateway HMAC execution token before invoking any tool handler.
   - Confines all file operations strictly inside `sandbox/` using `os.path.realpath` boundary validation.
4. **SQLite Persistence (`backend/database/db.py`)**:
   - Stores all agents, sessions, capabilities, tool requests, security events, attack chains, containment incidents, replay runs, and agent tasks in WAL mode.
