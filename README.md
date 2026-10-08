# AgentShield — AI Agent Runtime Security Gateway

> **"Stop malicious AI actions before they reach sensitive tools."**

AgentShield is a runtime security enforcement gateway located between an autonomous AI agent and the protected tools and resources that agent can access.

**Core Security Principle:** *AgentShield does not need to trust the agent.* Even when an AI agent is manipulated by indirect prompt injection inside an untrusted document, AgentShield evaluates every tool request independently at runtime—enforcing deterministic least-privilege policy, context trust, multi-signal risk scoring, behavioral sequence detection, directed attack-chain correlation, and automatic capability quarantine.

---

## 1. Architecture Overview

```text
                REAL AI AGENT / AGENT CLIENT
                           |
                           | tool request
                           v
                 +----------------------+
                 |      AGENTSHIELD     |
                 |  Runtime Security    |
                 |       Gateway        |
                 +----------+-----------+
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
          Policy          Risk          Behavior
          Engine          Engine        Analysis
             |              |              |
             +--------------+--------------+
                            |
                     Attack Correlation
                            |
                     Decision Engine
                            |
                   +--------+--------+
                   |                 |
                 ALLOW              BLOCK
                   |                 |
                   v                 v
              Real Local        Tool Not
              Tool Execution    Executed
                   |
                   v
              Audit Logging (SQLite)
                   |
                   v
             Web Security SOC
                Dashboard
```

### Canonical Subsystems
- **`backend/agent/`**: Real local AI agent service (`AgentRuntime`, `AgentPlanner`, `LocalLLMAdapter`, `AgentGatewayClient`, `AgentToolExecutor`, `AgentContextManager`, `AgentMemory`). Supports local **Ollama** models with a clean deterministic offline planner fallback.
- **`backend/gateway/`**:
  - `interceptor.py`: 16-step fail-closed runtime interceptor (`POST /tool-request`).
  - `policy_engine.py`: Default-deny, least-privilege capability and resource policy enforcement.
  - `context_trust.py`: Evaluates `TRUSTED`, `INTERNAL`, `UNKNOWN`, `UNTRUSTED` provenance and scans documents for adversarial prompt-injection markers.
  - `risk_engine.py`: Deterministic 0–100 multi-signal risk engine with explainable contributors.
  - `behavior_engine.py`: Stateful sequence detector (`DOCUMENT_TO_SECRET_ANOMALY`, `DATA_EXFILTRATION_CHAIN`, `PRIVILEGE_ESCALATION_EXECUTION`).
  - `attack_chain.py`: Directed graph correlation engine (`INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION`, `INJECTION_TRIGGERED_CREDENTIAL_HARVESTING`).
  - `capability_manager.py`: Dynamic capability state machine (`ACTIVE`, `QUARANTINED`, `REVOKED`).
  - `blast_radius.py`: Computes dynamic before/after capability reduction percentages from SQLite.
  - `replay_engine.py`: Executes 5-step attack and post-containment replay runs.
- **`backend/tools/`**: Controlled sandbox tool registry (`read_document`, `list_files`, `search_database`, `read_customer_record`, `read_secret`, `send_data`, `send_email`, `execute_command`) protected by HMAC runtime gateway tokens and strict `sandbox/` path confinement.
- **`backend/database/`**: Persistent SQLite database (`agentshield.db` in WAL mode).
- **`src/`**: React + Vite + Tailwind CSS + Cytoscape.js Security Operations Center (SOC) web interface.

---

## 2. Running Locally

### Prerequisites
- Python 3.10+
- Node.js 20+ / 22+
- *(Optional)* Ollama running locally (`http://localhost:11434`)

### Full-Stack Quickstart
```bash
# 1. Install frontend/proxy dependencies
npm install

# 2. Start the full-stack server (automatically launches the Python Gateway on :8000 and Web SOC on :3000)
npm run dev
```

Or run the Python Gateway and Frontend separately:
```bash
# Terminal 1: Start canonical Python Gateway
python3 backend/main.py

# Terminal 2: Run backend unit & integration test suite
python3 -m unittest discover -s backend/tests -v
```

### Optional Ollama Local LLM Setup
```bash
ollama serve
ollama pull llama3.2
export OLLAMA_BASE_URL="http://localhost:11434"
export OLLAMA_MODEL="llama3.2"
```
When Ollama is unavailable, `LocalLLMAdapter` automatically uses the deterministic local reasoning planner while routing all requests through the exact same AgentShield Runtime Gateway.

---

## 3. Running Tests

```bash
# Run all 20 backend unit, security invariant, agent integration, and API tests
python3 -m unittest discover -s backend/tests -v
```

You can also run the 8 interactive end-to-end verification suites directly from the **Security Tests** tab in the web interface (`POST /api/security-tests/run`).

---

## 4. Docker Deployment

```bash
docker compose up --build
```
- Frontend SOC: `http://localhost:3000`
- Backend Gateway API: `http://localhost:8000`

---

## 5. Honest Scope & Limitations

- AgentShield **does not** claim to prevent an LLM from reading or being influenced by adversarial text inside an untrusted document.
- Instead, AgentShield provides a **runtime enforcement boundary** between the agent and protected tools so that even when an agent is manipulated by indirect prompt injection, dangerous tool actions (`read_secret`, `send_data`, `execute_command`) are intercepted, scored, blocked, and contained before execution.
- This local implementation uses a controlled filesystem `sandbox/` directory and simulated secrets to safely demonstrate the architecture. Production enterprise deployment requires hardware/container isolation, IAM/OIDC identity integration, external KMS secrets management, network egress firewalling, and hardened tool adapters.
