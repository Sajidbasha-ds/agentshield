"""Data models and strict request/response validation schemas for AgentShield."""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


VALID_TRUST_LEVELS = {"TRUSTED", "INTERNAL", "UNKNOWN", "UNTRUSTED"}
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_DECISIONS = {"ALLOW", "BLOCK"}
VALID_CAPABILITY_STATES = {"ACTIVE", "QUARANTINED", "REVOKED"}


@dataclass
class RequestContext:
    source: str = "user_prompt"
    trust: str = "UNKNOWN"
    document_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "RequestContext":
        if not data or not isinstance(data, dict):
            return cls()
        source = str(data.get("source", "user_prompt"))[:200]
        trust = str(data.get("trust", "UNKNOWN")).upper()
        if trust not in VALID_TRUST_LEVELS:
            trust = "UNKNOWN"
        doc_path = data.get("document_path")
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        return cls(source=source, trust=trust, document_path=doc_path, metadata=metadata)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRequestPayload:
    agent_id: str
    tool: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    context: RequestContext = field(default_factory=RequestContext)
    timestamp: Optional[str] = None
    reason: str = ""

    @classmethod
    def validate_and_build(cls, raw: Dict[str, Any]) -> "ToolRequestPayload":
        if not isinstance(raw, dict):
            raise ValueError("Request payload must be a JSON object.")
        agent_id = str(raw.get("agent_id", "")).strip()
        if not agent_id:
            raise ValueError("Field 'agent_id' is required and cannot be empty.")
        if len(agent_id) > 128 or any(c in agent_id for c in [";", "'", '"', "--"]):
            raise ValueError("Invalid 'agent_id' format.")

        tool = str(raw.get("tool", "")).strip()
        if not tool:
            raise ValueError("Field 'tool' is required and cannot be empty.")
        if len(tool) > 128:
            raise ValueError("Invalid 'tool' name length.")

        arguments = raw.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ValueError("Field 'arguments' must be a key-value object.")

        session_id = str(raw.get("session_id") or f"sess-{agent_id}-default").strip()
        request_id = str(raw.get("request_id") or new_id("req")).strip()
        timestamp = str(raw.get("timestamp") or utc_now_iso()).strip()
        reason = str(raw.get("reason") or "Agent tool execution request").strip()[:500]
        context = RequestContext.from_dict(raw.get("context"))

        return cls(
            agent_id=agent_id,
            tool=tool,
            arguments=arguments,
            session_id=session_id,
            request_id=request_id,
            context=context,
            timestamp=timestamp,
            reason=reason,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "arguments": self.arguments,
            "context": self.context.to_dict(),
            "timestamp": self.timestamp,
            "reason": self.reason,
        }


@dataclass
class RiskContributor:
    signal: str
    score: int
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"signal": self.signal, "score": self.score, "detail": self.detail}


@dataclass
class GatewayDecisionResponse:
    request_id: str
    event_id: str
    agent_id: str
    session_id: str
    tool: str
    resource: str
    decision: str
    risk_score: int
    risk_level: str
    reasons: List[str]
    contributors: List[Dict[str, Any]]
    capability_state: str
    context_trust: str
    behavior_patterns: List[str]
    attack_chain: Optional[str]
    attack_chain_id: Optional[str]
    containment_triggered: bool
    quarantined_capabilities: List[str]
    tool_executed: bool
    tool_output: Any = None
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
