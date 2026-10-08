# Presentation Outline — AgentShield

1. **The Problem**: AI agents are moving from chat interfaces to autonomous tool execution (reading files, querying databases, sending webhooks, running commands). When an agent ingests untrusted external documents, indirect prompt injection can hijack the agent's control flow.
2. **Why Prompt Filtering Fails**: Trying to make the LLM "ignore bad instructions" is probabilistic and brittle.
3. **Our Solution — AgentShield**: A deterministic Runtime Security Gateway placed between the AI agent and its tools. *"AgentShield does not need to trust the agent."*
4. **How It Works**:
   - Runtime Interceptor (`POST /tool-request`)
   - Deterministic Policy + Context Trust + 6-Signal Risk Engine
   - Stateful Behavioral Sequence & NetworkX/DiGraph Attack-Chain Correlation
   - Automatic Capability Quarantine (60% Blast-Radius Reduction)
5. **Live Demo**: Benign task (`ALLOW`) vs. Malicious invoice prompt injection (`BLOCK` + `CONTAINMENT` + `REPLAY VERIFICATION`).
