"""Stateful Behavioral Sequence Analysis Engine for AgentShield."""

import json
from typing import Any, Dict, List, Optional
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import ToolRequestPayload


class BehaviorEngine:
    """
    Analyzes historical security_events per agent and session to detect
    suspicious multi-step action sequences.
    """

    def __init__(self, db: DatabaseManager = db_manager):
        self.db = db

    def analyze(
        self,
        req: ToolRequestPayload,
        context_eval: Dict[str, Any],
    ) -> Dict[str, Any]:
        recent_events = self.db.execute_query(
            """
            SELECT tool, resource, context_trust, decision, risk_score, timestamp
            FROM security_events
            WHERE agent_id = ? AND session_id = ?
            ORDER BY timestamp DESC
            LIMIT 15
            """,
            (req.agent_id, req.session_id),
        )

        patterns: List[str] = []
        descriptions: List[str] = []
        anomaly_score = 0

        recent_tools = [e["tool"] for e in recent_events]
        had_doc_read = "read_document" in recent_tools or bool(context_eval.get("tainted_by_document"))
        had_secret_attempt = "read_secret" in recent_tools
        is_untrusted = context_eval.get("trust") == "UNTRUSTED"

        # 1. DOCUMENT_TO_SECRET_ANOMALY
        if req.tool == "read_secret" and (had_doc_read or is_untrusted):
            patterns.append("DOCUMENT_TO_SECRET_ANOMALY")
            descriptions.append(
                "Behavioral Sequence Anomaly: Agent attempted credential access (read_secret) immediately after ingesting document context."
            )
            anomaly_score += 15

        # 2. DATA_EXFILTRATION_CHAIN
        if req.tool in ("send_data", "send_email") and (had_secret_attempt or had_doc_read or is_untrusted):
            patterns.append("DATA_EXFILTRATION_CHAIN")
            descriptions.append(
                f"Behavioral Exfiltration Sequence: Agent attempted outbound transmission ({req.tool}) following sensitive resource or untrusted document interaction."
            )
            anomaly_score += 20

        # 3. PRIVILEGE_ESCALATION_EXECUTION
        if req.tool == "execute_command" and (had_doc_read or had_secret_attempt or is_untrusted):
            patterns.append("PRIVILEGE_ESCALATION_EXECUTION")
            descriptions.append(
                "Behavioral Privilege Escalation: Agent attempted system command execution following document ingestion or secret probing."
            )
            anomaly_score += 20

        # 4. REPEATED_SENSITIVE_PROBING
        blocked_count = sum(1 for e in recent_events if e["decision"] == "BLOCK")
        if blocked_count >= 1 and req.tool in ("read_secret", "send_data", "execute_command", "read_customer_record"):
            patterns.append("REPEATED_BLOCKED_PROBING")
            descriptions.append(
                f"Persistent Probing Detected: Agent issued sensitive tool request '{req.tool}' after {blocked_count} prior blocked action(s) in session."
            )
            anomaly_score += 10

        return {
            "agent_id": req.agent_id,
            "session_id": req.session_id,
            "patterns": patterns,
            "descriptions": descriptions,
            "anomaly_score": min(25, anomaly_score),
            "recent_event_count": len(recent_events),
        }

    def list_behavior_states(self) -> List[Dict[str, Any]]:
        rows = self.db.execute_query(
            """
            SELECT event_id, timestamp, agent_id, session_id, tool, resource,
                   behavior_patterns_json, risk_score, decision
            FROM security_events
            WHERE behavior_patterns_json != '[]'
            ORDER BY timestamp DESC
            LIMIT 50
            """
        )
        result = []
        for r in rows:
            patterns = json.loads(r.get("behavior_patterns_json") or "[]")
            if patterns:
                result.append(
                    {
                        "event_id": r["event_id"],
                        "timestamp": r["timestamp"],
                        "agent_id": r["agent_id"],
                        "session_id": r["session_id"],
                        "tool": r["tool"],
                        "resource": r["resource"],
                        "patterns": patterns,
                        "risk_score": r["risk_score"],
                        "decision": r["decision"],
                    }
                )
        return result


behavior_engine = BehaviorEngine()
