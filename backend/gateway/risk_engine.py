"""Deterministic Multi-Signal Risk Engine for AgentShield."""

from typing import Any, Dict, List
from backend.database.models import RiskContributor, ToolRequestPayload
from backend.tools.registry import get_tool_metadata


def score_to_risk_level(score: int) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    if score <= 74:
        return "HIGH"
    return "CRITICAL"


class RiskEngine:
    """
    Calculates a deterministic 0-100 risk score from 6 independent security signals:
    1. Tool Sensitivity
    2. Capability Authorization
    3. Resource Sensitivity
    4. Context Trust
    5. Behavior Sequence
    6. Attack Chain Correlation
    """

    def calculate(
        self,
        req: ToolRequestPayload,
        policy_eval: Dict[str, Any],
        context_eval: Dict[str, Any],
        behavior_eval: Dict[str, Any],
        attack_chain_eval: Dict[str, Any],
    ) -> Dict[str, Any]:
        contributors: List[RiskContributor] = []
        tool_meta = get_tool_metadata(req.tool)

        # 1. Tool Sensitivity (0 - 20)
        if tool_meta:
            tool_score = min(20, tool_meta.base_risk_score)
            contributors.append(
                RiskContributor(
                    signal="Tool Sensitivity",
                    score=tool_score,
                    detail=f"Tool '{req.tool}' classified as {tool_meta.risk_level} risk ({tool_meta.category})",
                )
            )
        else:
            contributors.append(
                RiskContributor(
                    signal="Tool Sensitivity",
                    score=20,
                    detail=f"Unregistered tool '{req.tool}'",
                )
            )

        # 2. Capability Authorization & Policy Scope (0 - 25)
        cap_state = policy_eval.get("capability_state", "REVOKED")
        violations = policy_eval.get("violations", [])
        if cap_state in ("QUARANTINED", "REVOKED") or violations:
            cap_score = 25
            detail_msg = (
                f"Capability is {cap_state}"
                if cap_state != "ACTIVE"
                else f"Policy violation: {', '.join(violations)}"
            )
            contributors.append(
                RiskContributor(
                    signal="Unauthorized Capability",
                    score=cap_score,
                    detail=detail_msg,
                )
            )

        # 3. Resource Sensitivity (0 - 20)
        res_score = tool_meta.resource_sensitivity_score if tool_meta else 15
        path_arg = str(req.arguments.get("path", req.arguments.get("destination", ""))).lower()
        if any(w in path_arg for w in ["secret", "api_key", "malicious", "untrusted", "attacker", "exfil"]):
            res_score = max(res_score, 20)
        if res_score > 0:
            contributors.append(
                RiskContributor(
                    signal="Sensitive Resource",
                    score=res_score,
                    detail=f"Target resource sensitivity rated {tool_meta.resource_sensitivity if tool_meta else 'HIGH'}",
                )
            )

        # 4. Context Trust (0 - 20)
        trust = context_eval.get("trust", "UNKNOWN")
        markers = context_eval.get("detected_markers", [])
        if trust == "UNTRUSTED":
            ctx_score = 20
            contributors.append(
                RiskContributor(
                    signal="Untrusted Context",
                    score=ctx_score,
                    detail=(
                        f"Untrusted context with {len(markers)} injection marker(s)"
                        if markers
                        else "Session context marked UNTRUSTED"
                    ),
                )
            )
        elif trust == "UNKNOWN":
            contributors.append(
                RiskContributor(
                    signal="Untrusted Context",
                    score=10,
                    detail="Unverified UNKNOWN context provenance",
                )
            )

        # 5. Behavior Anomaly (0 - 15)
        beh_score = min(15, int(behavior_eval.get("anomaly_score", 0)))
        beh_patterns = behavior_eval.get("patterns", [])
        if beh_score > 0:
            contributors.append(
                RiskContributor(
                    signal="Behavior Sequence",
                    score=beh_score,
                    detail=f"Detected pattern(s): {', '.join(beh_patterns)}",
                )
            )

        # 6. Attack-Chain Correlation (0 - 15)
        chain_score = min(15, int(attack_chain_eval.get("correlation_score", 0)))
        chain_cls = attack_chain_eval.get("classification")
        if chain_score > 0 and chain_cls:
            contributors.append(
                RiskContributor(
                    signal="Attack Chain",
                    score=chain_score,
                    detail=f"Correlated chain: {chain_cls}",
                )
            )

        raw_total = sum(c.score for c in contributors)
        final_score = max(0, min(100, raw_total))
        risk_level = score_to_risk_level(final_score)

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "contributors": [c.to_dict() for c in contributors],
        }


risk_engine = RiskEngine()
