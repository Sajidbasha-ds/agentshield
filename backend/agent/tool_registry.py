"""Agent-side Tool Registry view (metadata only, zero raw tool execution access)."""

from typing import Any, Dict, List
from backend.tools.registry import list_all_tools


class AgentToolRegistry:
    """
    Provides tool schemas to the AI agent for planning.
    Does NOT import or expose raw tool implementation functions, enforcing
    that the agent must route every tool request through AgentShield.
    """

    def get_available_tools(self) -> List[Dict[str, Any]]:
        return list_all_tools()


agent_tool_registry = AgentToolRegistry()
