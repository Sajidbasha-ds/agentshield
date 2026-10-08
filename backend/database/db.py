"""Canonical SQLite database engine and schema manager for AgentShield."""

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional
from backend.database.models import utc_now_iso


DEFAULT_DB_PATH = os.environ.get("AGENTSHIELD_DB_PATH", os.path.abspath("agentshield.db"))


class DatabaseManager:
    """Thread-safe SQLite persistence layer for AgentShield."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._lock = threading.RLock()
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        with self._lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        role TEXT NOT NULL,
                        description TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'ACTIVE',
                        current_session_id TEXT NOT NULL,
                        current_risk_score INTEGER NOT NULL DEFAULT 0,
                        containment_state TEXT NOT NULL DEFAULT 'NORMAL',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        context_source TEXT NOT NULL DEFAULT 'user_prompt',
                        context_trust TEXT NOT NULL DEFAULT 'TRUSTED',
                        tainted_by_document TEXT,
                        detected_markers_json TEXT NOT NULL DEFAULT '[]',
                        started_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS capabilities (
                        id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        capability_name TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        is_dangerous INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL DEFAULT 'ACTIVE',
                        initial_status TEXT NOT NULL DEFAULT 'ACTIVE',
                        reason TEXT NOT NULL DEFAULT 'Initial policy baseline',
                        updated_at TEXT NOT NULL,
                        UNIQUE(agent_id, tool_name)
                    );

                    CREATE TABLE IF NOT EXISTS tool_requests (
                        request_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        arguments_json TEXT NOT NULL,
                        context_json TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        timestamp TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS security_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        arguments_json TEXT NOT NULL,
                        context_source TEXT NOT NULL,
                        context_trust TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        contributors_json TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        reasons_json TEXT NOT NULL,
                        capability_state TEXT NOT NULL,
                        behavior_patterns_json TEXT NOT NULL,
                        attack_chain TEXT,
                        attack_chain_id TEXT,
                        containment_triggered INTEGER NOT NULL DEFAULT 0,
                        tool_executed INTEGER NOT NULL DEFAULT 0,
                        tool_output_preview TEXT
                    );

                    CREATE TABLE IF NOT EXISTS attack_chains (
                        chain_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        nodes_json TEXT NOT NULL,
                        edges_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS containment_incidents (
                        incident_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        trigger_event_id TEXT NOT NULL,
                        attack_chain_id TEXT,
                        quarantined_capabilities_json TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        capabilities_before INTEGER NOT NULL,
                        capabilities_after INTEGER NOT NULL,
                        reduction_percentage REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS replay_runs (
                        replay_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        scenario_name TEXT NOT NULL,
                        steps_json TEXT NOT NULL,
                        containment_verified INTEGER NOT NULL DEFAULT 0,
                        persistence_rate REAL NOT NULL DEFAULT 0.0,
                        summary TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS agent_tasks (
                        task_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        task_prompt TEXT NOT NULL,
                        planner_mode TEXT NOT NULL,
                        steps_json TEXT NOT NULL,
                        final_response TEXT NOT NULL,
                        status TEXT NOT NULL
                    );
                    """
                )
                conn.commit()
                self._seed_default_agents_and_capabilities(conn)
            finally:
                conn.close()

    def _seed_default_agents_and_capabilities(self, conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM agents")
        row = cur.fetchone()
        if row and row["cnt"] > 0:
            return

        now = utc_now_iso()
        default_agents = [
            (
                "agent-001",
                "FinOps Document & Operations Agent",
                "autonomous_ops_agent",
                "Processes vendor invoices, summarizes internal reports, and executes authorized operational workflows.",
                "ACTIVE",
                "sess-agent-001-default",
                0,
                "NORMAL",
                now,
                now,
            ),
            (
                "agent-002",
                "Customer Support Triage Agent",
                "support_triage_agent",
                "Handles customer account inquiries and searches approved customer records.",
                "ACTIVE",
                "sess-agent-002-default",
                0,
                "NORMAL",
                now,
                now,
            ),
        ]
        cur.executemany(
            """
            INSERT INTO agents (
                agent_id, name, role, description, status,
                current_session_id, current_risk_score, containment_state,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            default_agents,
        )

        cur.execute(
            """
            INSERT OR IGNORE INTO sessions (
                session_id, agent_id, context_source, context_trust,
                tainted_by_document, detected_markers_json, started_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("sess-agent-001-default", "agent-001", "system_init", "TRUSTED", None, "[]", now, now),
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO sessions (
                session_id, agent_id, context_source, context_trust,
                tainted_by_document, detected_markers_json, started_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("sess-agent-002-default", "agent-002", "system_init", "TRUSTED", None, "[]", now, now),
        )

        # Agent-001 starts with 5 ACTIVE capabilities (2 safe: read_document, list_files;
        # 3 high/critical: read_secret, send_data, execute_command) and 3 REVOKED capabilities
        # so that when containment quarantines the 3 dangerous capabilities, active capabilities
        # drop from 5 -> 2 (60% blast radius reduction), matching the exact security model.
        agent_001_caps = [
            ("cap-a1-read_document", "agent-001", "read_document", "cap:read_document", "LOW", 0, "ACTIVE", "ACTIVE", "Baseline document read privilege"),
            ("cap-a1-list_files", "agent-001", "list_files", "cap:list_files", "LOW", 0, "ACTIVE", "ACTIVE", "Baseline directory listing privilege"),
            ("cap-a1-read_secret", "agent-001", "read_secret", "cap:read_secret", "CRITICAL", 1, "ACTIVE", "ACTIVE", "Conditional secret inspection (requires TRUSTED vault scope)"),
            ("cap-a1-send_data", "agent-001", "send_data", "cap:send_data", "HIGH", 1, "ACTIVE", "ACTIVE", "Outbound webhook dispatch privilege"),
            ("cap-a1-execute_command", "agent-001", "execute_command", "cap:execute_command", "CRITICAL", 1, "ACTIVE", "ACTIVE", "Controlled diagnostic command privilege"),
            ("cap-a1-search_database", "agent-001", "search_database", "cap:search_database", "MEDIUM", 0, "REVOKED", "REVOKED", "Least-privilege default: not assigned to FinOps agent"),
            ("cap-a1-read_customer_record", "agent-001", "read_customer_record", "cap:read_customer_record", "HIGH", 1, "REVOKED", "REVOKED", "Least-privilege default: restricted to Support agent"),
            ("cap-a1-send_email", "agent-001", "send_email", "cap:send_email", "MEDIUM", 1, "REVOKED", "REVOKED", "Least-privilege default: email dispatch disabled"),
        ]

        agent_002_caps = [
            ("cap-a2-read_document", "agent-002", "read_document", "cap:read_document", "LOW", 0, "ACTIVE", "ACTIVE", "Support documentation access"),
            ("cap-a2-list_files", "agent-002", "list_files", "cap:list_files", "LOW", 0, "ACTIVE", "ACTIVE", "Support file listing"),
            ("cap-a2-search_database", "agent-002", "search_database", "cap:search_database", "MEDIUM", 0, "ACTIVE", "ACTIVE", "Customer database search"),
            ("cap-a2-read_customer_record", "agent-002", "read_customer_record", "cap:read_customer_record", "HIGH", 1, "ACTIVE", "ACTIVE", "Customer record lookup"),
            ("cap-a2-send_email", "agent-002", "send_email", "cap:send_email", "MEDIUM", 1, "ACTIVE", "ACTIVE", "Customer notification email"),
            ("cap-a2-read_secret", "agent-002", "read_secret", "cap:read_secret", "CRITICAL", 1, "REVOKED", "REVOKED", "Least-privilege default: secrets prohibited"),
            ("cap-a2-send_data", "agent-002", "send_data", "cap:send_data", "HIGH", 1, "REVOKED", "REVOKED", "Least-privilege default: raw outbound prohibited"),
            ("cap-a2-execute_command", "agent-002", "execute_command", "cap:execute_command", "CRITICAL", 1, "REVOKED", "REVOKED", "Least-privilege default: command execution prohibited"),
        ]

        for cap_tuple in agent_001_caps + agent_002_caps:
            cur.execute(
                """
                INSERT INTO capabilities (
                    id, agent_id, tool_name, capability_name, risk_level,
                    is_dangerous, status, initial_status, reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*cap_tuple, now),
            )
        conn.commit()

    def reset_to_baseline(self) -> Dict[str, Any]:
        """Resets all tables and re-seeds clean baseline agents and capabilities."""
        with self._lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                for table in [
                    "security_events",
                    "tool_requests",
                    "attack_chains",
                    "containment_incidents",
                    "replay_runs",
                    "agent_tasks",
                    "sessions",
                    "capabilities",
                    "agents",
                ]:
                    cur.execute(f"DELETE FROM {table}")
                conn.commit()
                self._seed_default_agents_and_capabilities(conn)
                return {"status": "reset_complete", "timestamp": utc_now_iso()}
            finally:
                conn.close()

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                rows = cur.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def execute_write(self, query: str, params: tuple = ()) -> None:
        with self._lock:
            conn = self.get_connection()
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                conn.commit()
            finally:
                conn.close()


# Singleton canonical DB instance
db_manager = DatabaseManager()
