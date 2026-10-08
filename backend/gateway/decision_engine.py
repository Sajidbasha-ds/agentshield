"""Decision Engine and Automatic Capability Containment for AgentShield."""

import json
from typing import Any, Dict, List
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import ToolRequestPayload, new_id, utc_now_iso
from backend.gateway.capability_manager import CapabilityManager, capability_manager
from backend.gateway.blast_radius import BlastRadiusEngine, blast_radius_engine


class DecisionEngine:
    """
    Combines Policy, Risk, Behavior, and Attack-Chain evaluations to produce
    a deterministic ALLOW / BLOCK decision and trigger automatic capability-level
    containment when high-risk or attack-chain conditions occur.
    """

    def __init__(
        self,
        db: DatabaseManager = db_manager,
        cap_mgr: CapabilityManager = capability_manager,
        blast_eng: BlastRadiusEngine = blast_radius_engine,
    ):
        self.db = db
        self.cap_mgr = cap_mgr
        self.blast_eng = blast_eng

    def decide_and_contain(
        self,
        req: ToolRequestPayload,
        event_id: str,
        policy_eval: Dict[str, Any],
        context_eval: Dict[str, Any],
        risk_eval: Dict[str, Any],
        behavior_eval: Dict[str, Any],
        attack_chain_eval: Dict[str, Any],
    ) -> Dict[str, Any]:
        reasons: List[str] = list(policy_eval.get("reasons", []))
        for desc in behavior_eval.get("descriptions", []):
            if desc not in reasons:
                reasons.append(desc)

        if attack_chain_eval.get("detected") and attack_chain_eval.get("classification"):
            chain_msg = f"Attack Chain Correlation: Detected {attack_chain_eval['classification']}."
            if chain_msg not in reasons:
                reasons.append(chain_msg)

        risk_score = int(risk_eval.get("risk_score", 0))
        risk_level = str(risk_eval.get("risk_level", "LOW"))
        policy_allowed = bool(policy_eval.get("allowed", False))

        # Decision rule: ALLOW only if policy allows AND risk_score < 50 AND no attack chain
        if not policy_allowed or risk_score >= 50 or attack_chain_eval.get("detected"):
            decision = "BLOCK"
            if policy_allowed and risk_score >= 50:
                reasons.append(
                    f"Risk Threshold Exceeded: Calculated risk score {risk_score} ({risk_level}) exceeds safe execution threshold (50)."
                )
        else:
            decision = "ALLOW"
            if not reasons:
                reasons.append(
                    f"Policy & Risk Verified: Capability ACTIVE, context {context_eval.get('trust')}, risk score {risk_score} ({risk_level})."
                )

        # Automatic Capability Containment check
        containment_triggered = False
        quarantined_list: List[str] = []

        should_contain = (
            decision == "BLOCK"
            and (
                risk_score >= 70
                or attack_chain_eval.get("detected")
                or bool(behavior_eval.get("patterns"))
                or context_eval.get("trust") == "UNTRUSTED"
            )
        )

        if should_contain:
            agent_caps = self.cap_mgr.inspect(req.agent_id)
            for cap in agent_caps:
                # Automatically quarantine dangerous active capabilities on the agent
                if cap["is_dangerous"] and cap["status"] == "ACTIVE":
                    q_reason = (
                        f"Auto-quarantined by AgentShield Containment Engine following blocked '{req.tool}' "
                        f"(Risk: {risk_score} {risk_level}, Chain: {attack_chain_eval.get('classification') or 'ANOMALY'})"
                    )
                    self.cap_mgr.quarantine(req.agent_id, cap["tool_name"], reason=q_reason)
                    quarantined_list.append(cap["tool_name"])

            if quarantined_list:
                containment_triggered = True
                reasons.append(
                    f"Automatic Containment Activated: Quarantined dangerous capabilities [{', '.join(quarantined_list)}] to reduce agent blast radius."
                )
                blast_stats = self.blast_eng.calculate(req.agent_id)
                self.db.execute_write(
                    """
                    INSERT INTO containment_incidents (
                        incident_id, timestamp, agent_id, session_id, trigger_event_id,
                        attack_chain_id, quarantined_capabilities_json, reason,
                        capabilities_before, capabilities_after, reduction_percentage
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id("inc"),
                        utc_now_iso(),
                        req.agent_id,
                        req.session_id,
                        event_id,
                        attack_chain_eval.get("chain_id"),
                        json.dumps(quarantined_list),
                        reasons[-1],
                        blast_stats["capabilities_before"],
                        blast_stats["capabilities_after"],
                        blast_stats["reduction_percentage"],
                    ),
                )

        # Refresh capability state after any automatic containment
        latest_cap = self.cap_mgr.get_capability(req.agent_id, req.tool)
        final_cap_state = latest_cap["status"] if latest_cap else policy_eval.get("capability_state", "REVOKED")

        return {
            "decision": decision,
            "reasons": reasons,
            "capability_state": final_cap_state,
            "containment_triggered": containment_triggered,
            "quarantined_capabilities": quarantined_list,
        }


decision_engine = DecisionEngine()
