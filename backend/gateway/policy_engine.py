"""Deterministic Policy Engine for AgentShield."""

from typing import Any, Dict, List
from backend.database.models import ToolRequestPayload
from backend.tools.registry import get_tool_metadata
from backend.gateway.capability_manager import CapabilityManager, capability_manager


class PolicyEngine:
    """
    Enforces default-deny, least-privilege, capability authorization,
    and resource sensitivity rules independent of the LLM.
    """

    def __init__(self, cap_mgr: CapabilityManager = capability_manager):
        self.cap_mgr = cap_mgr

    def evaluate(
        self,
        req: ToolRequestPayload,
        context_eval: Dict[str, Any],
    ) -> Dict[str, Any]:
        reasons: List[str] = []
        violations: List[str] = []
        allowed = True

        tool_meta = get_tool_metadata(req.tool)
        if not tool_meta:
            return {
                "allowed": False,
                "capability_state": "REVOKED",
                "violations": ["UNKNOWN_TOOL"],
                "reasons": [f"Default Deny: Tool '{req.tool}' is not registered in canonical Tool Registry."],
            }

        # Check agent registration & tool allowlist
        if req.agent_id not in tool_meta.allowed_agents:
            allowed = False
            violations.append("UNAUTHORIZED_AGENT_FOR_TOOL")
            reasons.append(
                f"Least Privilege Policy: Agent '{req.agent_id}' is not in allowed_agents for '{req.tool}'."
            )

        # Check dynamic capability state
        cap = self.cap_mgr.get_capability(req.agent_id, req.tool)
        cap_state = cap["status"] if cap else "REVOKED"

        if cap_state == "QUARANTINED":
            allowed = False
            violations.append("CAPABILITY_QUARANTINED")
            reasons.append(
                f"Containment Enforcement: Capability '{tool_meta.required_capability}' for '{req.tool}' is QUARANTINED."
            )
        elif cap_state == "REVOKED":
            allowed = False
            violations.append("CAPABILITY_REVOKED")
            reasons.append(
                f"Unauthorized Capability: Required capability '{tool_meta.required_capability}' is REVOKED."
            )

        trust = context_eval.get("trust", "UNKNOWN")

        # Rule: Sensitive resources (read_secret) require explicit TRUSTED vault context
        if req.tool == "read_secret":
            vault_authorized = bool(req.context.metadata.get("vault_authorized") is True and trust == "TRUSTED")
            if not vault_authorized:
                allowed = False
                violations.append("UNAUTHORIZED_SENSITIVE_RESOURCE")
                reasons.append(
                    f"Sensitive Resource Policy: Accessing secret '{req.arguments.get('path', 'secrets.txt')}' requires verified TRUSTED vault authorization (current context trust: {trust})."
                )

        # Rule: Outbound data transmission (send_data) is blocked for untrusted context or external unknown domains
        if req.tool == "send_data":
            dest = str(req.arguments.get("destination", "")).lower()
            if trust == "UNTRUSTED":
                allowed = False
                violations.append("UNTRUSTED_CONTEXT_EGRESS")
                reasons.append(
                    "Exfiltration Prevention Policy: Outbound 'send_data' is prohibited when session context is UNTRUSTED."
                )
            if any(bad in dest for bad in ["attacker", "exfil", "external", "http://", "https://"]) and "internal" not in dest:
                allowed = False
                violations.append("UNAPPROVED_EXTERNAL_DESTINATION")
                reasons.append(
                    f"Data Egress Policy: Destination '{req.arguments.get('destination')}' is not on the approved internal sink allowlist."
                )

        # Rule: Privileged command execution restrictions
        if req.tool == "execute_command":
            cmd = str(req.arguments.get("command", "")).strip()
            if trust in ("UNTRUSTED", "UNKNOWN"):
                allowed = False
                violations.append("UNTRUSTED_COMMAND_EXECUTION")
                reasons.append(
                    f"Privilege Boundary Policy: 'execute_command' cannot run under {trust} context."
                )
            if any(tok in cmd for tok in ["&&", ";", "|", "`", "$(", "env", "whoami", "cat ", "curl ", "wget "]):
                allowed = False
                violations.append("RESTRICTED_COMMAND_SYNTAX")
                reasons.append(
                    f"Command Policy: Command '{cmd}' contains restricted shell or reconnaissance directives."
                )

        # Rule: Path traversal check in arguments
        if "path" in req.arguments:
            path_val = str(req.arguments.get("path", ""))
            if ".." in path_val or path_val.startswith("/etc") or path_val.startswith("/root"):
                allowed = False
                violations.append("SANDBOX_PATH_VIOLATION")
                reasons.append(f"Sandbox Boundary Policy: Illegal path reference '{path_val}'.")

        return {
            "allowed": allowed,
            "capability_state": cap_state,
            "violations": violations,
            "reasons": reasons,
        }


policy_engine = PolicyEngine()
