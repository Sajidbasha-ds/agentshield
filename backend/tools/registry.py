"""Canonical Tool Registry with rich security metadata for AgentShield."""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    description: str
    category: str
    risk_level: str
    base_risk_score: int
    required_capability: str
    resource_sensitivity: str
    resource_sensitivity_score: int
    allowed_agents: List[str]
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


CANONICAL_TOOLS: Dict[str, ToolMetadata] = {
    "read_document": ToolMetadata(
        name="read_document",
        description="Reads a document file from the controlled sandbox/documents directory.",
        category="filesystem_read",
        risk_level="LOW",
        base_risk_score=5,
        required_capability="cap:read_document",
        resource_sensitivity="LOW",
        resource_sensitivity_score=5,
        allowed_agents=["agent-001", "agent-002"],
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        output_schema={"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}},
    ),
    "list_files": ToolMetadata(
        name="list_files",
        description="Lists available files inside an approved sandbox directory.",
        category="filesystem_read",
        risk_level="LOW",
        base_risk_score=5,
        required_capability="cap:list_files",
        resource_sensitivity="LOW",
        resource_sensitivity_score=0,
        allowed_agents=["agent-001", "agent-002"],
        input_schema={"type": "object", "properties": {"directory": {"type": "string"}}, "required": []},
        output_schema={"type": "object", "properties": {"files": {"type": "array"}}},
    ),
    "search_database": ToolMetadata(
        name="search_database",
        description="Searches non-sensitive customer directory metadata in the sandbox.",
        category="database_query",
        risk_level="MEDIUM",
        base_risk_score=10,
        required_capability="cap:search_database",
        resource_sensitivity="MEDIUM",
        resource_sensitivity_score=10,
        allowed_agents=["agent-001", "agent-002"],
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        output_schema={"type": "object", "properties": {"matches": {"type": "array"}}},
    ),
    "read_customer_record": ToolMetadata(
        name="read_customer_record",
        description="Reads a detailed customer account record including contract value and contact info.",
        category="database_read",
        risk_level="HIGH",
        base_risk_score=15,
        required_capability="cap:read_customer_record",
        resource_sensitivity="HIGH",
        resource_sensitivity_score=15,
        allowed_agents=["agent-002"],
        input_schema={"type": "object", "properties": {"customer_id": {"type": "string"}}, "required": ["customer_id"]},
        output_schema={"type": "object", "properties": {"record": {"type": "object"}}},
    ),
    "read_secret": ToolMetadata(
        name="read_secret",
        description="Accesses sensitive credentials or signing keys from the sandbox secrets vault.",
        category="credential_access",
        risk_level="CRITICAL",
        base_risk_score=20,
        required_capability="cap:read_secret",
        resource_sensitivity="CRITICAL",
        resource_sensitivity_score=20,
        allowed_agents=["agent-001"],
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        output_schema={"type": "object", "properties": {"content": {"type": "string"}}},
    ),
    "send_data": ToolMetadata(
        name="send_data",
        description="Transmits a data payload to an outbound webhook or external endpoint.",
        category="network_egress",
        risk_level="HIGH",
        base_risk_score=20,
        required_capability="cap:send_data",
        resource_sensitivity="HIGH",
        resource_sensitivity_score=15,
        allowed_agents=["agent-001"],
        input_schema={
            "type": "object",
            "properties": {"destination": {"type": "string"}, "payload": {"type": "string"}},
            "required": ["destination", "payload"],
        },
        output_schema={"type": "object", "properties": {"status": {"type": "string"}}},
    ),
    "send_email": ToolMetadata(
        name="send_email",
        description="Dispatches an email notification to a specified recipient.",
        category="network_egress",
        risk_level="MEDIUM",
        base_risk_score=12,
        required_capability="cap:send_email",
        resource_sensitivity="MEDIUM",
        resource_sensitivity_score=10,
        allowed_agents=["agent-002"],
        input_schema={
            "type": "object",
            "properties": {"recipient": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            "required": ["recipient", "subject", "body"],
        },
        output_schema={"type": "object", "properties": {"status": {"type": "string"}}},
    ),
    "execute_command": ToolMetadata(
        name="execute_command",
        description="Executes a privileged system diagnostic command within the sandbox.",
        category="system_execution",
        risk_level="CRITICAL",
        base_risk_score=25,
        required_capability="cap:execute_command",
        resource_sensitivity="CRITICAL",
        resource_sensitivity_score=20,
        allowed_agents=["agent-001"],
        input_schema={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        output_schema={"type": "object", "properties": {"output": {"type": "string"}}},
    ),
}


def get_tool_metadata(tool_name: str) -> Optional[ToolMetadata]:
    return CANONICAL_TOOLS.get(tool_name)


def list_all_tools() -> List[Dict[str, Any]]:
    return [t.to_dict() for t in CANONICAL_TOOLS.values()]


def extract_resource_identifier(tool_name: str, arguments: Dict[str, Any]) -> str:
    if not isinstance(arguments, dict):
        return "unknown"
    if "path" in arguments:
        return str(arguments["path"])
    if "destination" in arguments:
        return str(arguments["destination"])
    if "customer_id" in arguments:
        return str(arguments["customer_id"])
    if "command" in arguments:
        return f"cmd:{arguments['command']}"
    if "recipient" in arguments:
        return f"mailto:{arguments['recipient']}"
    if "directory" in arguments:
        return f"dir:{arguments['directory']}"
    if "query" in arguments:
        return f"query:{arguments['query']}"
    return f"{tool_name}:default"
