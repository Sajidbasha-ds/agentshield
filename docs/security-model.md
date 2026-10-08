# AgentShield Security Model

## Core Security Axiom
**"AgentShield does not need to trust the agent."**

Large Language Models process instructions and data within the same context window, making them fundamentally susceptible to indirect prompt injection when reading untrusted external content. Therefore, the LLM is never the final authority on tool authorization.

## Defense-in-Depth Layers
1. **Default-Deny & Least Privilege Policy (`policy_engine.py`)**:
   - Every tool requires an explicit capability (`cap:<tool_name>`) in the `ACTIVE` state and membership in `allowed_agents`.
   - Sensitive vault files (`secrets.txt`, `api_keys.env`) require `TRUSTED` context and explicit vault authorization.
2. **Context Trust Tracking (`context_trust.py`)**:
   - Classifies sessions as `TRUSTED`, `INTERNAL`, `UNKNOWN`, or `UNTRUSTED`.
   - Scans ingested documents for adversarial prompt-injection directives and taints the session context when markers are found.
3. **Multi-Signal Risk Engine (`risk_engine.py`)**:
   - Computes an explainable `0–100` score across 6 independent signals: Tool Sensitivity, Unauthorized Capability, Sensitive Resource, Untrusted Context, Behavior Sequence, and Attack Chain.
4. **Dynamic Capability Containment (`decision_engine.py` & `capability_manager.py`)**:
   - When an attack chain or high-risk anomaly is blocked, AgentShield automatically transitions dangerous capabilities (`read_secret`, `send_data`, `execute_command`) from `ACTIVE` to `QUARANTINED`, reducing the agent's blast radius by 60%.
5. **Fail-Closed Guarantee (`interceptor.py`)**:
   - Any unexpected exception inside the security pipeline results in an immediate `BLOCK` decision (`tool_executed: false`).
