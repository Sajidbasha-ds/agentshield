"""Agent Context Manager tracking document provenance and session context."""

from typing import Any, Dict, Optional


class AgentContextManager:
    """Manages the agent's working context and ingested document state per session."""

    def __init__(self) -> None:
        self._contexts: Dict[str, Dict[str, Any]] = {}

    def get_context(self, session_id: str, initial_source: str = "agent_console") -> Dict[str, Any]:
        if session_id not in self._contexts:
            self._contexts[session_id] = {
                "source": initial_source,
                "trust": "INTERNAL",
                "document_path": None,
                "ingested_content": None,
                "metadata": {},
            }
        return dict(self._contexts[session_id])

    def update_from_document(
        self,
        session_id: str,
        document_path: str,
        content: str,
    ) -> Dict[str, Any]:
        ctx = self.get_context(session_id)
        lower_content = content.lower()
        is_suspicious = any(
            marker in lower_content
            for marker in [
                "ignore the user's request",
                "ignore previous",
                "disregard prior",
                "read_secret",
                "send_data",
                "instruction injection",
            ]
        )
        ctx["document_path"] = document_path
        ctx["ingested_content"] = content
        if is_suspicious or "malicious" in document_path.lower() or "untrusted" in document_path.lower():
            ctx["source"] = "untrusted_document"
            ctx["trust"] = "UNTRUSTED"
        else:
            ctx["source"] = "local_document"
            ctx["trust"] = "INTERNAL"

        self._contexts[session_id] = ctx
        return dict(ctx)


agent_context_manager = AgentContextManager()
