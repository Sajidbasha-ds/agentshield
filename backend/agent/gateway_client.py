"""Gateway Client used by the local AI agent to submit tool requests to AgentShield."""

from typing import Any, Dict, Optional
from backend.database.models import new_id, utc_now_iso
from backend.gateway.interceptor import RuntimeInterceptor, runtime_interceptor


class AgentGatewayClient:
    """
    Sends structured tool requests from the AI agent to the canonical
    AgentShield RuntimeInterceptor.
    """

    def __init__(self, interceptor: RuntimeInterceptor = runtime_interceptor):
        self.interceptor = interceptor

    def submit_tool_request(
        self,
        *,
        agent_id: str,
        session_id: str,
        tool: str,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
        reason: str,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "request_id": request_id or new_id("req"),
            "agent_id": agent_id,
            "session_id": session_id,
            "tool": tool,
            "arguments": arguments,
            "context": {
                "source": context.get("source", "agent_console"),
                "trust": context.get("trust", "INTERNAL"),
                "document_path": context.get("document_path"),
                "metadata": context.get("metadata", {}),
            },
            "timestamp": utc_now_iso(),
            "reason": reason,
        }
        return self.interceptor.intercept(payload)


gateway_client = AgentGatewayClient()
