"""Session memory store for the local AI agent."""

from typing import Any, Dict, List
from backend.database.models import utc_now_iso


class AgentMemory:
    """Stores reasoning steps, tool observations, and gateway decisions per session."""

    def __init__(self) -> None:
        self._sessions: Dict[str, List[Dict[str, Any]]] = {}

    def append_entry(self, session_id: str, entry: Dict[str, Any]) -> None:
        if session_id not in self._sessions:
            self._sessions[session_id] = []
        self._sessions[session_id].append({"timestamp": utc_now_iso(), **entry})

    def get_history(self, session_id: str) -> List[Dict[str, Any]]:
        return list(self._sessions.get(session_id, []))

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)


agent_memory = AgentMemory()
