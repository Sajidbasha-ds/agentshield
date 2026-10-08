"""Agent Tool Executor enforcing mandatory AgentShield Gateway mediation."""

from typing import Any, Dict
from backend.agent.gateway_client import AgentGatewayClient, gateway_client


class AgentToolExecutor:
    """
    Executes agent tool choices exclusively by submitting them to the
    AgentShield Gateway Client and respecting the ALLOW / BLOCK decision.
    """

    def __init__(self, client: AgentGatewayClient = gateway_client):
        self.client = client

    def execute_via_gateway(
        self,
        *,
        agent_id: str,
        session_id: str,
        tool: str,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        gateway_response = self.client.submit_tool_request(
            agent_id=agent_id,
            session_id=session_id,
            tool=tool,
            arguments=arguments,
            context=context,
            reason=reason,
        )
        return gateway_response


agent_tool_executor = AgentToolExecutor()
