"""Blast Radius Analysis Engine for AgentShield."""

import json
from typing import Any, Dict, List, Optional
from backend.database.db import DatabaseManager, db_manager


class BlastRadiusEngine:
    """
    Calculates dynamic blast-radius metrics from actual SQLite capability states:
    - capabilities_before
    - dangerous_capabilities_before
    - capabilities_after
    - dangerous_capabilities_after
    - reduction_percentage
    """

    def __init__(self, db: DatabaseManager = db_manager):
        self.db = db

    def calculate(self, agent_id: str = "agent-001") -> Dict[str, Any]:
        caps = self.db.execute_query(
            "SELECT * FROM capabilities WHERE agent_id = ? ORDER BY is_dangerous DESC, tool_name ASC",
            (agent_id,),
        )
        if not caps:
            return {
                "agent_id": agent_id,
                "capabilities_before": 0,
                "dangerous_capabilities_before": 0,
                "capabilities_after": 0,
                "dangerous_capabilities_after": 0,
                "reduction_percentage": 0.0,
                "removed_capabilities": [],
                "active_capabilities": [],
                "quarantined_capabilities": [],
            }

        before_active = [c for c in caps if c["initial_status"] == "ACTIVE"]
        before_dangerous = [c for c in before_active if bool(c["is_dangerous"])]

        after_active = [c for c in caps if c["status"] == "ACTIVE"]
        after_dangerous = [c for c in after_active if bool(c["is_dangerous"])]
        quarantined = [c for c in caps if c["status"] == "QUARANTINED"]

        removed = [
            c["tool_name"]
            for c in before_active
            if c["status"] in ("QUARANTINED", "REVOKED")
        ]

        cap_before_count = len(before_active)
        cap_after_count = len(after_active)

        if cap_before_count > 0:
            reduction = round(((cap_before_count - cap_after_count) / cap_before_count) * 100.0, 1)
        else:
            reduction = 0.0

        reduction = max(0.0, reduction)

        incidents = self.db.execute_query(
            "SELECT * FROM containment_incidents WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 5",
            (agent_id,),
        )
        for inc in incidents:
            inc["quarantined_capabilities"] = json.loads(inc.get("quarantined_capabilities_json") or "[]")

        return {
            "agent_id": agent_id,
            "capabilities_before": cap_before_count,
            "dangerous_capabilities_before": len(before_dangerous),
            "capabilities_after": cap_after_count,
            "dangerous_capabilities_after": len(after_dangerous),
            "reduction_percentage": reduction,
            "removed_capabilities": removed,
            "active_capabilities": [c["tool_name"] for c in after_active],
            "quarantined_capabilities": [c["tool_name"] for c in quarantined],
            "recent_containment_incidents": incidents,
        }


blast_radius_engine = BlastRadiusEngine()
