"""Dynamic Capability Manager for AgentShield."""

from typing import Any, Dict, List, Optional
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import utc_now_iso, VALID_CAPABILITY_STATES
from backend.tools.registry import get_tool_metadata


class CapabilityManager:
    """Manages per-agent tool capabilities (ACTIVE, QUARANTINED, REVOKED) in SQLite."""

    def __init__(self, db: DatabaseManager = db_manager):
        self.db = db

    def inspect(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if agent_id:
            rows = self.db.execute_query(
                "SELECT * FROM capabilities WHERE agent_id = ? ORDER BY is_dangerous DESC, tool_name ASC",
                (agent_id,),
            )
        else:
            rows = self.db.execute_query(
                "SELECT * FROM capabilities ORDER BY agent_id ASC, is_dangerous DESC, tool_name ASC"
            )
        for r in rows:
            r["is_dangerous"] = bool(r.get("is_dangerous"))
        return rows

    def get_capability(self, agent_id: str, tool_name: str) -> Optional[Dict[str, Any]]:
        rows = self.db.execute_query(
            "SELECT * FROM capabilities WHERE agent_id = ? AND tool_name = ?",
            (agent_id, tool_name),
        )
        if not rows:
            return None
        row = rows[0]
        row["is_dangerous"] = bool(row.get("is_dangerous"))
        return row

    def _set_status(
        self,
        agent_id: str,
        tool_name: str,
        new_status: str,
        reason: str,
    ) -> Dict[str, Any]:
        if new_status not in VALID_CAPABILITY_STATES:
            raise ValueError(f"Invalid capability state: {new_status}")

        existing = self.get_capability(agent_id, tool_name)
        now = utc_now_iso()
        if not existing:
            meta = get_tool_metadata(tool_name)
            if not meta:
                raise ValueError(f"Unknown tool '{tool_name}'")
            cap_id = f"cap-{agent_id}-{tool_name}"
            is_dang = 1 if meta.risk_level in ("HIGH", "CRITICAL") else 0
            self.db.execute_write(
                """
                INSERT INTO capabilities (
                    id, agent_id, tool_name, capability_name, risk_level,
                    is_dangerous, status, initial_status, reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cap_id,
                    agent_id,
                    tool_name,
                    meta.required_capability,
                    meta.risk_level,
                    is_dang,
                    new_status,
                    new_status,
                    reason,
                    now,
                ),
            )
        else:
            self.db.execute_write(
                """
                UPDATE capabilities
                SET status = ?, reason = ?, updated_at = ?
                WHERE agent_id = ? AND tool_name = ?
                """,
                (new_status, reason, now, agent_id, tool_name),
            )

        self._sync_agent_containment_state(agent_id)
        updated = self.get_capability(agent_id, tool_name)
        return updated or {}

    def _sync_agent_containment_state(self, agent_id: str) -> None:
        caps = self.inspect(agent_id)
        quarantined = [c for c in caps if c["status"] == "QUARANTINED"]
        now = utc_now_iso()
        if quarantined:
            self.db.execute_write(
                "UPDATE agents SET status = 'CONTAINED', containment_state = 'CAPABILITY_QUARANTINED', updated_at = ? WHERE agent_id = ?",
                (now, agent_id),
            )
        else:
            self.db.execute_write(
                "UPDATE agents SET status = 'ACTIVE', containment_state = 'NORMAL', updated_at = ? WHERE agent_id = ?",
                (now, agent_id),
            )

    def grant(self, agent_id: str, tool_name: str, reason: str = "Explicitly granted via Capability Manager") -> Dict[str, Any]:
        return self._set_status(agent_id, tool_name, "ACTIVE", reason)

    def revoke(self, agent_id: str, tool_name: str, reason: str = "Revoked by administrator") -> Dict[str, Any]:
        return self._set_status(agent_id, tool_name, "REVOKED", reason)

    def quarantine(self, agent_id: str, tool_name: str, reason: str = "Quarantined due to security policy / containment") -> Dict[str, Any]:
        return self._set_status(agent_id, tool_name, "QUARANTINED", reason)

    def restore(self, agent_id: str, tool_name: str, reason: str = "Restored to active operation") -> Dict[str, Any]:
        return self._set_status(agent_id, tool_name, "ACTIVE", reason)


capability_manager = CapabilityManager()
