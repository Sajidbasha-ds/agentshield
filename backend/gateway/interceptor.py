"""Canonical Runtime Security Interceptor for AgentShield."""

import json
from typing import Any, Dict
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import (
    GatewayDecisionResponse,
    ToolRequestPayload,
    new_id,
    utc_now_iso,
)
from backend.tools.registry import extract_resource_identifier
from backend.tools.fake_tools import execute_protected_tool, issue_gateway_execution_token
from backend.gateway.context_trust import ContextTrustEngine, context_trust_engine
from backend.gateway.policy_engine import PolicyEngine, policy_engine
from backend.gateway.behavior_engine import BehaviorEngine, behavior_engine
from backend.gateway.attack_chain import AttackChainEngine, attack_chain_engine
from backend.gateway.risk_engine import RiskEngine, risk_engine
from backend.gateway.decision_engine import DecisionEngine, decision_engine


class RuntimeInterceptor:
    """
    Canonical 16-step runtime interception boundary between AI agents and protected tools.
    Enforces FAIL-CLOSED security semantics: if any critical security subsystem raises an
    unexpected error, the request is immediately BLOCKED and the tool is NEVER executed.
    """

    def __init__(
        self,
        db: DatabaseManager = db_manager,
        ctx_engine: ContextTrustEngine = context_trust_engine,
        pol_engine: PolicyEngine = policy_engine,
        beh_engine: BehaviorEngine = behavior_engine,
        chain_engine: AttackChainEngine = attack_chain_engine,
        rsk_engine: RiskEngine = risk_engine,
        dec_engine: DecisionEngine = decision_engine,
    ):
        self.db = db
        self.ctx_engine = ctx_engine
        self.pol_engine = pol_engine
        self.beh_engine = beh_engine
        self.chain_engine = chain_engine
        self.rsk_engine = rsk_engine
        self.dec_engine = dec_engine

    def intercept(self, raw_request: Dict[str, Any]) -> Dict[str, Any]:
        # Step 1: Validate request payload strictly
        req = ToolRequestPayload.validate_and_build(raw_request)
        event_id = new_id("evt")
        resource = extract_resource_identifier(req.tool, req.arguments)

        try:
            # Step 2 & 3: Ensure agent and session are tracked
            self._ensure_agent_exists(req.agent_id, req.session_id)

            # Record incoming tool request
            self.db.execute_write(
                """
                INSERT OR REPLACE INTO tool_requests (
                    request_id, agent_id, session_id, tool, resource,
                    arguments_json, context_json, reason, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.request_id,
                    req.agent_id,
                    req.session_id,
                    req.tool,
                    resource,
                    json.dumps(req.arguments),
                    json.dumps(req.context.to_dict()),
                    req.reason,
                    req.timestamp,
                ),
            )

            # Step 4-7: Inspect tool, arguments, resource, and evaluate Context Trust
            context_eval = self.ctx_engine.evaluate(req)

            # Step 8-9: Check capabilities and evaluate deterministic Policy Engine
            policy_eval = self.pol_engine.evaluate(req, context_eval)

            # Step 10: Analyze Behavioral Sequences
            behavior_eval = self.beh_engine.analyze(req, context_eval)

            # Step 11: Correlate Attack Chains
            attack_chain_eval = self.chain_engine.correlate(
                req, context_eval, behavior_eval, policy_eval
            )

            # Step 12: Calculate Multi-Signal Risk Score
            risk_eval = self.rsk_engine.calculate(
                req, policy_eval, context_eval, behavior_eval, attack_chain_eval
            )

            # Step 13: Make Decision & Trigger Automatic Containment if required
            decision_eval = self.dec_engine.decide_and_contain(
                req,
                event_id,
                policy_eval,
                context_eval,
                risk_eval,
                behavior_eval,
                attack_chain_eval,
            )

            decision = decision_eval["decision"]
            tool_executed = False
            tool_output = None
            reasons = list(decision_eval["reasons"])

            # Step 14: Execute protected tool ONLY if decision == ALLOW
            if decision == "ALLOW":
                exec_token = issue_gateway_execution_token(req.request_id, req.agent_id, req.tool)
                tool_output = execute_protected_tool(
                    req.tool,
                    req.arguments,
                    gateway_token=exec_token,
                    request_id=req.request_id,
                    agent_id=req.agent_id,
                )
                tool_executed = True

                # Post-execution inspection: if read_document returned content with prompt-injection
                # markers, immediately update session context trust so the UI and subsequent calls see it
                if req.tool == "read_document":
                    self.ctx_engine.evaluate(req)

            # Step 15: Persist audit security event and update agent risk state
            output_preview = None
            if tool_output is not None:
                output_preview = json.dumps(tool_output)[:500]

            now = utc_now_iso()
            self.db.execute_write(
                """
                INSERT INTO security_events (
                    event_id, timestamp, request_id, agent_id, session_id,
                    tool, resource, arguments_json, context_source, context_trust,
                    risk_score, risk_level, contributors_json, decision, reasons_json,
                    capability_state, behavior_patterns_json, attack_chain,
                    attack_chain_id, containment_triggered, tool_executed, tool_output_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    now,
                    req.request_id,
                    req.agent_id,
                    req.session_id,
                    req.tool,
                    resource,
                    json.dumps(req.arguments),
                    req.context.source,
                    context_eval["trust"],
                    risk_eval["risk_score"],
                    risk_eval["risk_level"],
                    json.dumps(risk_eval["contributors"]),
                    decision,
                    json.dumps(reasons),
                    decision_eval["capability_state"],
                    json.dumps(behavior_eval["patterns"]),
                    attack_chain_eval.get("classification"),
                    attack_chain_eval.get("chain_id"),
                    1 if decision_eval["containment_triggered"] else 0,
                    1 if tool_executed else 0,
                    output_preview,
                ),
            )

            self.db.execute_write(
                "UPDATE agents SET current_session_id = ?, current_risk_score = ?, updated_at = ? WHERE agent_id = ?",
                (req.session_id, risk_eval["risk_score"], now, req.agent_id),
            )

            # Step 16: Return structured GatewayDecisionResponse
            response = GatewayDecisionResponse(
                request_id=req.request_id,
                event_id=event_id,
                agent_id=req.agent_id,
                session_id=req.session_id,
                tool=req.tool,
                resource=resource,
                decision=decision,
                risk_score=risk_eval["risk_score"],
                risk_level=risk_eval["risk_level"],
                reasons=reasons,
                contributors=risk_eval["contributors"],
                capability_state=decision_eval["capability_state"],
                context_trust=context_eval["trust"],
                behavior_patterns=behavior_eval["patterns"],
                attack_chain=attack_chain_eval.get("classification"),
                attack_chain_id=attack_chain_eval.get("chain_id"),
                containment_triggered=decision_eval["containment_triggered"],
                quarantined_capabilities=decision_eval["quarantined_capabilities"],
                tool_executed=tool_executed,
                tool_output=tool_output,
                timestamp=now,
            )
            return response.to_dict()

        except Exception as exc:
            # FAIL CLOSED: Never execute a protected tool when an internal security error occurs
            now = utc_now_iso()
            fail_reasons = [
                f"FAIL-CLOSED ENFORCEMENT: Security gateway blocked execution due to runtime error: {str(exc)}"
            ]
            self.db.execute_write(
                """
                INSERT INTO security_events (
                    event_id, timestamp, request_id, agent_id, session_id,
                    tool, resource, arguments_json, context_source, context_trust,
                    risk_score, risk_level, contributors_json, decision, reasons_json,
                    capability_state, behavior_patterns_json, attack_chain,
                    attack_chain_id, containment_triggered, tool_executed, tool_output_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    now,
                    req.request_id,
                    req.agent_id,
                    req.session_id,
                    req.tool,
                    resource,
                    json.dumps(req.arguments),
                    req.context.source,
                    "UNTRUSTED",
                    100,
                    "CRITICAL",
                    json.dumps([{"signal": "Fail-Closed Boundary", "score": 100, "detail": str(exc)}]),
                    "BLOCK",
                    json.dumps(fail_reasons),
                    "QUARANTINED",
                    "[]",
                    None,
                    None,
                    0,
                    0,
                    None,
                ),
            )
            return GatewayDecisionResponse(
                request_id=req.request_id,
                event_id=event_id,
                agent_id=req.agent_id,
                session_id=req.session_id,
                tool=req.tool,
                resource=resource,
                decision="BLOCK",
                risk_score=100,
                risk_level="CRITICAL",
                reasons=fail_reasons,
                contributors=[{"signal": "Fail-Closed Boundary", "score": 100, "detail": str(exc)}],
                capability_state="QUARANTINED",
                context_trust="UNTRUSTED",
                behavior_patterns=[],
                attack_chain=None,
                attack_chain_id=None,
                containment_triggered=False,
                quarantined_capabilities=[],
                tool_executed=False,
                tool_output=None,
                timestamp=now,
            ).to_dict()

    def _ensure_agent_exists(self, agent_id: str, session_id: str) -> None:
        rows = self.db.execute_query("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,))
        if not rows:
            now = utc_now_iso()
            self.db.execute_write(
                """
                INSERT INTO agents (
                    agent_id, name, role, description, status,
                    current_session_id, current_risk_score, containment_state,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, 0, 'NORMAL', ?, ?)
                """,
                (
                    agent_id,
                    f"Dynamic Agent ({agent_id})",
                    "custom_agent",
                    "Dynamically registered runtime agent.",
                    session_id,
                    now,
                    now,
                ),
            )


runtime_interceptor = RuntimeInterceptor()
