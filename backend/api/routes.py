"""Canonical REST API handlers for AgentShield Runtime Security Gateway."""

import json
import os
from typing import Any, Dict, List, Optional, Tuple
from backend.database.db import db_manager
from backend.database.models import utc_now_iso
from backend.tools.registry import list_all_tools
from backend.tools.sandbox import list_sandbox_files, resolve_sandbox_path
from backend.gateway.interceptor import runtime_interceptor
from backend.gateway.capability_manager import capability_manager
from backend.gateway.context_trust import context_trust_engine
from backend.gateway.behavior_engine import behavior_engine
from backend.gateway.attack_chain import attack_chain_engine
from backend.gateway.blast_radius import blast_radius_engine
from backend.gateway.replay_engine import replay_engine
from backend.gateway.security_test_runner import security_test_runner
from backend.agent.agent_runtime import agent_runtime


def _format_event_row(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_id": r["event_id"],
        "timestamp": r["timestamp"],
        "request_id": r["request_id"],
        "agent_id": r["agent_id"],
        "session_id": r["session_id"],
        "tool": r["tool"],
        "resource": r["resource"],
        "arguments": json.loads(r.get("arguments_json") or "{}"),
        "context_source": r["context_source"],
        "context_trust": r["context_trust"],
        "risk_score": r["risk_score"],
        "risk_level": r["risk_level"],
        "contributors": json.loads(r.get("contributors_json") or "[]"),
        "decision": r["decision"],
        "reasons": json.loads(r.get("reasons_json") or "[]"),
        "capability_state": r["capability_state"],
        "behavior_patterns": json.loads(r.get("behavior_patterns_json") or "[]"),
        "attack_chain": r.get("attack_chain"),
        "attack_chain_id": r.get("attack_chain_id"),
        "containment_triggered": bool(r.get("containment_triggered")),
        "tool_executed": bool(r.get("tool_executed")),
        "tool_output_preview": r.get("tool_output_preview"),
    }


def get_health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "AgentShield Runtime Security Gateway",
        "timestamp": utc_now_iso(),
        "database": "connected",
        "fail_closed": True,
    }


def get_events(limit: int = 100) -> List[Dict[str, Any]]:
    rows = db_manager.execute_query(
        "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (int(limit),)
    )
    return [_format_event_row(r) for r in rows]


def get_event_by_id(event_id: str) -> Optional[Dict[str, Any]]:
    rows = db_manager.execute_query(
        "SELECT * FROM security_events WHERE event_id = ?", (event_id,)
    )
    if not rows:
        return None
    return _format_event_row(rows[0])


def get_agents() -> List[Dict[str, Any]]:
    agents = db_manager.execute_query("SELECT * FROM agents ORDER BY agent_id ASC")
    result = []
    for a in agents:
        aid = a["agent_id"]
        caps = capability_manager.inspect(aid)
        ev_stats = db_manager.execute_query(
            """
            SELECT
                COUNT(*) as total_requests,
                SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked_actions,
                SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed_actions,
                MAX(risk_score) as peak_risk
            FROM security_events
            WHERE agent_id = ?
            """,
            (aid,),
        )[0]
        result.append(
            {
                **a,
                "capabilities": caps,
                "active_capabilities_count": sum(1 for c in caps if c["status"] == "ACTIVE"),
                "quarantined_capabilities_count": sum(1 for c in caps if c["status"] == "QUARANTINED"),
                "revoked_capabilities_count": sum(1 for c in caps if c["status"] == "REVOKED"),
                "requests_count": int(ev_stats["total_requests"] or 0),
                "blocked_actions": int(ev_stats["blocked_actions"] or 0),
                "allowed_actions": int(ev_stats["allowed_actions"] or 0),
                "peak_risk_score": int(ev_stats["peak_risk"] or 0),
            }
        )
    return result


def get_agent_by_id(agent_id: str) -> Optional[Dict[str, Any]]:
    all_agents = get_agents()
    for a in all_agents:
        if a["agent_id"] == agent_id:
            recent = db_manager.execute_query(
                "SELECT * FROM security_events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 25",
                (agent_id,),
            )
            a["recent_events"] = [_format_event_row(r) for r in recent]
            a["blast_radius"] = blast_radius_engine.calculate(agent_id)
            return a
    return None


def get_metrics() -> Dict[str, Any]:
    ev_rows = db_manager.execute_query("SELECT * FROM security_events")
    total_requests = len(ev_rows)
    allowed_requests = sum(1 for r in ev_rows if r["decision"] == "ALLOW")
    blocked_requests = sum(1 for r in ev_rows if r["decision"] == "BLOCK")
    block_rate = round((blocked_requests / total_requests) * 100.0, 1) if total_requests > 0 else 0.0
    avg_risk = round(sum(r["risk_score"] for r in ev_rows) / total_requests, 1) if total_requests > 0 else 0.0
    latest_risk = ev_rows[-1]["risk_score"] if ev_rows else 0
    # Order by timestamp desc to get actual latest event risk
    latest_row = db_manager.execute_query(
        "SELECT risk_score, risk_level FROM security_events ORDER BY timestamp DESC LIMIT 1"
    )
    current_risk = int(latest_row[0]["risk_score"]) if latest_row else 0
    current_risk_level = str(latest_row[0]["risk_level"]) if latest_row else "LOW"

    high_risk_requests = sum(1 for r in ev_rows if 50 <= r["risk_score"] <= 74)
    critical_requests = sum(1 for r in ev_rows if r["risk_score"] >= 75)

    chains = attack_chain_engine.list_chains()
    incidents = db_manager.execute_query("SELECT * FROM containment_incidents")
    all_caps = capability_manager.inspect()
    quarantined_caps = [c for c in all_caps if c["status"] == "QUARANTINED"]
    active_agents = db_manager.execute_query("SELECT * FROM agents")

    blast = blast_radius_engine.calculate("agent-001")
    replays = replay_engine.list_replays()
    if replays:
        persistence_rate = round(
            sum(r["persistence_rate"] for r in replays) / len(replays), 1
        )
    else:
        persistence_rate = 100.0

    # Determine real-time system security posture from database state
    if quarantined_caps or incidents:
        system_state = "CONTAINMENT ACTIVE"
    elif blocked_requests > 0 or chains:
        system_state = "THREAT DETECTED"
    else:
        system_state = "PROTECTED"

    return {
        "system_state": system_state,
        "active_agents": len(active_agents),
        "total_requests": total_requests,
        "intercepted_requests": total_requests,
        "allowed_requests": allowed_requests,
        "blocked_requests": blocked_requests,
        "blocked_threats": blocked_requests,
        "block_rate": block_rate,
        "average_risk": avg_risk,
        "current_risk": current_risk,
        "current_risk_level": current_risk_level,
        "high_risk_requests": high_risk_requests,
        "critical_requests": critical_requests,
        "attack_chains": len(chains),
        "containment_incidents": len(incidents),
        "quarantined_capabilities": len(quarantined_caps),
        "blast_radius_reduction": blast["reduction_percentage"],
        "replay_persistence_rate": persistence_rate,
        "replay_runs_count": len(replays),
        "timestamp": utc_now_iso(),
    }


def get_sandbox_overview() -> Dict[str, Any]:
    files = list_sandbox_files("all")
    previews: Dict[str, str] = {}
    for rel in files:
        try:
            full = resolve_sandbox_path(rel)
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                previews[rel] = f.read()[:600]
        except Exception:
            previews[rel] = "<unreadable>"
    return {
        "sandbox_files": files,
        "previews": previews,
    }


def dispatch_api_request(
    method: str,
    path: str,
    query_params: Dict[str, str],
    body: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Any]:
    """
    Framework-agnostic canonical request dispatcher supporting both `/api/...`
    and root `/...` routes.
    """
    clean_path = path.strip()
    if clean_path.startswith("/api/"):
        clean_path = clean_path[4:]
    elif clean_path == "/api":
        clean_path = "/"

    if clean_path != "/" and clean_path.endswith("/"):
        clean_path = clean_path.rstrip("/")

    method = method.upper()
    body = body or {}

    try:
        if method == "GET" and clean_path == "/health":
            return 200, get_health()

        if method == "POST" and clean_path == "/tool-request":
            res = runtime_interceptor.intercept(body)
            return 200, res

        if method == "GET" and clean_path == "/events":
            limit = int(query_params.get("limit", "100"))
            return 200, get_events(limit=limit)

        if method == "GET" and clean_path.startswith("/events/"):
            event_id = clean_path.split("/events/", 1)[1]
            ev = get_event_by_id(event_id)
            if not ev:
                return 404, {"error": f"Event '{event_id}' not found."}
            return 200, ev

        if method == "GET" and clean_path == "/agents":
            return 200, get_agents()

        if method == "GET" and clean_path.startswith("/agents/"):
            agent_id = clean_path.split("/agents/", 1)[1]
            ag = get_agent_by_id(agent_id)
            if not ag:
                return 404, {"error": f"Agent '{agent_id}' not found."}
            return 200, ag

        if method == "GET" and clean_path == "/capabilities":
            agent_id = query_params.get("agent_id")
            return 200, capability_manager.inspect(agent_id=agent_id)

        if method == "POST" and clean_path == "/capabilities/grant":
            agent_id = str(body.get("agent_id", "agent-001"))
            tool_name = str(body.get("tool_name") or body.get("tool", ""))
            reason = str(body.get("reason", "Granted via SOC Capability Manager"))
            return 200, capability_manager.grant(agent_id, tool_name, reason)

        if method == "POST" and clean_path == "/capabilities/revoke":
            agent_id = str(body.get("agent_id", "agent-001"))
            tool_name = str(body.get("tool_name") or body.get("tool", ""))
            reason = str(body.get("reason", "Revoked via SOC Capability Manager"))
            return 200, capability_manager.revoke(agent_id, tool_name, reason)

        if method == "POST" and clean_path == "/capabilities/quarantine":
            agent_id = str(body.get("agent_id", "agent-001"))
            tool_name = str(body.get("tool_name") or body.get("tool", ""))
            reason = str(body.get("reason", "Quarantined via SOC Capability Manager"))
            return 200, capability_manager.quarantine(agent_id, tool_name, reason)

        if method == "POST" and clean_path == "/capabilities/restore":
            agent_id = str(body.get("agent_id", "agent-001"))
            tool_name = str(body.get("tool_name") or body.get("tool", ""))
            reason = str(body.get("reason", "Restored via SOC Capability Manager"))
            return 200, capability_manager.restore(agent_id, tool_name, reason)

        if method == "GET" and clean_path == "/context-trust":
            return 200, context_trust_engine.list_session_trust_states()

        if method == "GET" and clean_path == "/behavior":
            return 200, behavior_engine.list_behavior_states()

        if method == "GET" and clean_path == "/attack-chain":
            chains = attack_chain_engine.list_chains()
            return 200, {
                "chains": chains,
                "active_chain": chains[0] if chains else None,
            }

        if method == "GET" and clean_path.startswith("/attack-chain/"):
            chain_id = clean_path.split("/attack-chain/", 1)[1]
            chain = attack_chain_engine.get_chain(chain_id)
            if not chain:
                return 404, {"error": f"Attack chain '{chain_id}' not found."}
            return 200, chain

        if method == "GET" and clean_path == "/blast-radius":
            agent_id = query_params.get("agent_id", "agent-001")
            return 200, blast_radius_engine.calculate(agent_id=agent_id)

        if method == "GET" and clean_path == "/metrics":
            return 200, get_metrics()

        if method == "POST" and clean_path == "/replay":
            return 200, replay_engine.run_replay(body)

        if method == "GET" and clean_path == "/replay":
            return 200, replay_engine.list_replays()

        if method == "GET" and clean_path.startswith("/replay/"):
            replay_id = clean_path.split("/replay/", 1)[1]
            rpl = replay_engine.get_replay(replay_id)
            if not rpl:
                return 404, {"error": f"Replay run '{replay_id}' not found."}
            return 200, rpl

        if method == "GET" and clean_path == "/tools":
            return 200, list_all_tools()

        if method == "GET" and clean_path == "/sessions":
            return 200, context_trust_engine.list_session_trust_states()

        if method == "POST" and clean_path == "/agent/tasks":
            agent_id = str(body.get("agent_id", "agent-001")).strip()
            task = str(body.get("task", "")).strip()
            session_id = body.get("session_id")
            return 200, agent_runtime.execute_task(agent_id=agent_id, task=task, session_id=session_id)

        if method == "GET" and clean_path == "/agent/status":
            return 200, agent_runtime.get_status()

        if method == "POST" and clean_path == "/security-tests/run":
            test_id = str(body.get("test_id", "all")).strip()
            return 200, security_test_runner.run_test(test_id)

        if method == "GET" and clean_path == "/system/sandbox":
            return 200, get_sandbox_overview()

        if method == "POST" and clean_path == "/system/reset":
            return 200, db_manager.reset_to_baseline()

        return 404, {"error": f"Endpoint not found: {method} {path}"}

    except ValueError as ve:
        return 400, {"error": str(ve)}
    except PermissionError as pe:
        return 403, {"error": str(pe)}
    except Exception as exc:
        return 500, {"error": f"Internal Gateway Error: {str(exc)}"}
