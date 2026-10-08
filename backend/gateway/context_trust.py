"""Context Trust Engine for AgentShield."""

import json
import os
from typing import Any, Dict, List
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import ToolRequestPayload, utc_now_iso
from backend.tools.sandbox import resolve_sandbox_path


INJECTION_MARKERS = [
    "ignore the user's request",
    "ignore previous",
    "disregard prior instructions",
    "override standard",
    "important system instruction",
    "instruction injection payload",
    "call tool `read_secret`",
    "call tool `send_data`",
    "read_secret",
    "exfil",
    "attacker",
    "do not mention these steps",
]

TRUSTED_SOURCES = {"system_init", "verified_admin", "trusted_internal_workflow"}
INTERNAL_SOURCES = {"user_prompt", "local_document", "internal_report", "agent_console"}
UNTRUSTED_SOURCES = {"external_web", "untrusted_document", "external_attachment", "external_upload_portal", "malicious_document"}


class ContextTrustEngine:
    """Deterministically evaluates context trust (TRUSTED, INTERNAL, UNKNOWN, UNTRUSTED)."""

    def __init__(self, db: DatabaseManager = db_manager):
        self.db = db

    def inspect_document_for_markers(self, doc_path: str) -> List[str]:
        if not doc_path:
            return []
        try:
            full_path = resolve_sandbox_path(doc_path, default_subdir="documents")
            if not os.path.exists(full_path) or not os.path.isfile(full_path):
                return []
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read().lower()
            found = [m for m in INJECTION_MARKERS if m in text]
            return found
        except Exception:
            return []

    def evaluate(self, req: ToolRequestPayload) -> Dict[str, Any]:
        session_rows = self.db.execute_query(
            "SELECT * FROM sessions WHERE session_id = ?", (req.session_id,)
        )
        now = utc_now_iso()
        if not session_rows:
            self.db.execute_write(
                """
                INSERT INTO sessions (
                    session_id, agent_id, context_source, context_trust,
                    tainted_by_document, detected_markers_json, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (req.session_id, req.agent_id, req.context.source, "INTERNAL", None, "[]", now, now),
            )
            session = {
                "session_id": req.session_id,
                "agent_id": req.agent_id,
                "context_source": req.context.source,
                "context_trust": "INTERNAL",
                "tainted_by_document": None,
                "detected_markers_json": "[]",
            }
        else:
            session = session_rows[0]

        existing_markers: List[str] = json.loads(session.get("detected_markers_json") or "[]")
        tainted_doc = session.get("tainted_by_document")
        signals: List[str] = []

        # Inspect document if read_document is called or context references a document
        target_doc = None
        if req.tool == "read_document":
            target_doc = str(req.arguments.get("path", ""))
        elif req.context.document_path:
            target_doc = req.context.document_path

        doc_markers: List[str] = []
        if target_doc:
            doc_markers = self.inspect_document_for_markers(target_doc)
            if doc_markers:
                tainted_doc = target_doc
                for m in doc_markers:
                    if m not in existing_markers:
                        existing_markers.append(m)
                signals.append(f"Injected instruction markers detected in '{target_doc}': {', '.join(doc_markers[:3])}")
            elif "malicious" in target_doc.lower() or "untrusted" in target_doc.lower():
                tainted_doc = target_doc
                signals.append(f"Suspicious document filename '{target_doc}'")

        source_lower = req.context.source.lower()
        explicit_trust = req.context.trust.upper()

        # Determine effective trust level
        if (
            explicit_trust == "UNTRUSTED"
            or source_lower in UNTRUSTED_SOURCES
            or bool(doc_markers)
            or bool(tainted_doc)
            or session.get("context_trust") == "UNTRUSTED"
        ):
            effective_trust = "UNTRUSTED"
            if tainted_doc:
                signals.append(f"Session context tainted by untrusted document '{tainted_doc}'")
            if source_lower in UNTRUSTED_SOURCES:
                signals.append(f"Untrusted context source '{req.context.source}'")
        elif explicit_trust == "TRUSTED" and source_lower in TRUSTED_SOURCES:
            effective_trust = "TRUSTED"
            signals.append("Verified local trusted source")
        elif explicit_trust in ("TRUSTED", "INTERNAL") or source_lower in INTERNAL_SOURCES:
            effective_trust = "INTERNAL"
            signals.append(f"Internal context source '{req.context.source}'")
        else:
            effective_trust = "UNKNOWN"
            signals.append(f"Unverified context source '{req.context.source}'")

        # Persist session trust state
        self.db.execute_write(
            """
            UPDATE sessions
            SET context_source = ?, context_trust = ?, tainted_by_document = ?,
                detected_markers_json = ?, updated_at = ?
            WHERE session_id = ?
            """,
            (
                req.context.source,
                effective_trust,
                tainted_doc,
                json.dumps(existing_markers),
                now,
                req.session_id,
            ),
        )

        return {
            "session_id": req.session_id,
            "agent_id": req.agent_id,
            "source": req.context.source,
            "trust": effective_trust,
            "tainted_by_document": tainted_doc,
            "detected_markers": existing_markers,
            "signals": signals,
        }

    def list_session_trust_states(self) -> List[Dict[str, Any]]:
        rows = self.db.execute_query("SELECT * FROM sessions ORDER BY updated_at DESC")
        for r in rows:
            r["detected_markers"] = json.loads(r.get("detected_markers_json") or "[]")
        return rows


context_trust_engine = ContextTrustEngine()
