# AI Agent Integration Guide

## How the Local Agent Connects to AgentShield

The local agent in `backend/agent/` consists of:
- `agent_runtime.py`: Orchestrates the task reasoning loop.
- `llm_adapter.py`: Connects to local Ollama (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`) or falls back to the deterministic local planner.
- `planner.py`: Selects tools based on user tasks and ingested context.
- `gateway_client.py`: Submits structured tool requests to `RuntimeInterceptor`.
- `tool_executor.py`: Enforces that tools are only invoked via the gateway response.

## Standard Tool Request Protocol
```json
{
  "request_id": "req-91a8f2c10b",
  "agent_id": "agent-001",
  "session_id": "sess-agent-001-default",
  "tool": "read_document",
  "arguments": {
    "path": "invoice.pdf"
  },
  "context": {
    "source": "agent_console",
    "trust": "INTERNAL"
  },
  "timestamp": "2026-10-07T18:00:00Z",
  "reason": "Read invoice.pdf to generate summary for user"
}
```
