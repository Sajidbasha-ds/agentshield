"""Directed Graph Attack-Chain Correlation Engine for AgentShield."""

import json
from typing import Any, Dict, List, Optional
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import ToolRequestPayload, utc_now_iso, new_id
from backend.tools.registry import extract_resource_identifier

try:
    import networkx as nx  # type: ignore

    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class DirectedAttackGraph:
    """
    Graph representation that uses NetworkX DiGraph when available or
    an isomorphic pure-Python directed graph structure.
    """

    def __init__(self) -> None:
        self._nx_graph = nx.DiGraph() if HAS_NETWORKX else None
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, **attrs: Any) -> None:
        data = {"id": node_id, **attrs}
        self._nodes[node_id] = data
        if self._nx_graph is not None:
            self._nx_graph.add_node(node_id, **attrs)

    def add_edge(self, source: str, target: str, label: str = "") -> None:
        edge_id = f"edge-{source}->{target}"
        if not any(e["id"] == edge_id for e in self._edges):
            self._edges.append({"id": edge_id, "source": source, "target": target, "label": label})
        if self._nx_graph is not None:
            self._nx_graph.add_edge(source, target, label=label)

    def to_serializable(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "nodes": list(self._nodes.values()),
            "edges": list(self._edges),
        }


class AttackChainEngine:
    """
    Correlates multi-step context, behavior, tool, and resource interactions into
    explainable attack-chain graphs persisted in SQLite.
    """

    def __init__(self, db: DatabaseManager = db_manager):
        self.db = db

    def correlate(
        self,
        req: ToolRequestPayload,
        context_eval: Dict[str, Any],
        behavior_eval: Dict[str, Any],
        policy_eval: Dict[str, Any],
    ) -> Dict[str, Any]:
        patterns = behavior_eval.get("patterns", [])
        trust = context_eval.get("trust", "UNKNOWN")
        tainted_doc = context_eval.get("tainted_by_document")
        markers = context_eval.get("detected_markers", [])
        resource = extract_resource_identifier(req.tool, req.arguments)

        # Determine if an attack chain is active or emerging
        is_attack_chain = False
        classification: Optional[str] = None
        severity = "LOW"
        correlation_score = 0

        if (
            "DATA_EXFILTRATION_CHAIN" in patterns
            or (req.tool == "send_data" and (trust == "UNTRUSTED" or tainted_doc))
        ):
            is_attack_chain = True
            classification = "INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION"
            severity = "CRITICAL"
            correlation_score = 15
        elif (
            "DOCUMENT_TO_SECRET_ANOMALY" in patterns
            or (req.tool == "read_secret" and (trust == "UNTRUSTED" or tainted_doc or markers))
        ):
            is_attack_chain = True
            classification = "INJECTION_TRIGGERED_CREDENTIAL_HARVESTING"
            severity = "CRITICAL"
            correlation_score = 15
        elif (
            "PRIVILEGE_ESCALATION_EXECUTION" in patterns
            or (req.tool == "execute_command" and not policy_eval.get("allowed", True))
        ):
            is_attack_chain = True
            classification = "PRIVILEGE_ESCALATION_ATTEMPT"
            severity = "CRITICAL"
            correlation_score = 15
        elif not policy_eval.get("allowed", True) and req.tool in ("read_secret", "send_data", "execute_command"):
            is_attack_chain = True
            classification = "UNAUTHORIZED_SENSITIVE_TOOL_ACCESS"
            severity = "HIGH"
            correlation_score = 10

        if not is_attack_chain:
            return {
                "detected": False,
                "chain_id": None,
                "classification": None,
                "severity": "NONE",
                "correlation_score": 0,
                "nodes": [],
                "edges": [],
            }

        # Check if session already has an active attack chain to enrich
        existing_rows = self.db.execute_query(
            "SELECT * FROM attack_chains WHERE agent_id = ? AND session_id = ? ORDER BY created_at DESC LIMIT 1",
            (req.agent_id, req.session_id),
        )

        graph = DirectedAttackGraph()
        if existing_rows:
            chain_row = existing_rows[0]
            chain_id = chain_row["chain_id"]
            for n in json.loads(chain_row["nodes_json"]):
                graph.add_node(n.pop("id"), **n)
            for e in json.loads(chain_row["edges_json"]):
                graph.add_edge(e["source"], e["target"], e.get("label", ""))
            # Upgrade classification if exfiltration step happens after credential harvesting
            if classification == "INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION":
                pass
            elif chain_row["classification"] == "INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION":
                classification = "INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION"
        else:
            chain_id = new_id("chain")

        # Build canonical graph nodes and edges
        doc_label = tainted_doc or req.context.document_path or req.context.source
        doc_node_id = f"doc:{doc_label}"
        agent_node_id = f"agent:{req.agent_id}"
        ctx_node_id = f"ctx:{trust}"
        tool_node_id = f"tool:{req.tool}"
        res_node_id = f"res:{resource}"
        gw_node_id = "gateway:agentshield"
        block_node_id = f"decision:BLOCK:{req.tool}"
        contain_node_id = f"containment:{req.agent_id}"

        if tainted_doc or trust == "UNTRUSTED":
            graph.add_node(
                doc_node_id,
                label=f"Untrusted Document\n({doc_label})",
                type="document",
                risk="HIGH",
            )
            graph.add_node(
                ctx_node_id,
                label=f"Suspicious Context\n(Trust: {trust})",
                type="context",
                risk="HIGH",
            )
            graph.add_edge(doc_node_id, agent_node_id, "read by")
            graph.add_edge(doc_node_id, ctx_node_id, "injects prompt")
            graph.add_edge(ctx_node_id, agent_node_id, "influences")
        else:
            graph.add_node(
                ctx_node_id,
                label=f"Session Context\n({req.context.source})",
                type="context",
                risk="MEDIUM",
            )
            graph.add_edge(ctx_node_id, agent_node_id, "context")

        graph.add_node(
            agent_node_id,
            label=f"AI Agent\n({req.agent_id})",
            type="agent",
            risk="MEDIUM",
        )
        graph.add_node(
            tool_node_id,
            label=f"Tool Request\n({req.tool})",
            type="tool",
            risk="CRITICAL" if req.tool in ("read_secret", "execute_command") else "HIGH",
        )
        graph.add_node(
            res_node_id,
            label=f"Target Resource\n({resource})",
            type="resource",
            risk="CRITICAL",
        )
        graph.add_node(
            gw_node_id,
            label="AgentShield\nRuntime Interceptor",
            type="gateway",
            risk="SAFE",
        )
        graph.add_node(
            block_node_id,
            label=f"ACTION BLOCKED\n({req.tool})",
            type="decision",
            risk="BLOCKED",
        )
        graph.add_node(
            contain_node_id,
            label="Capability Quarantine\n(Blast Radius Reduced)",
            type="containment",
            risk="CONTAINED",
        )

        graph.add_edge(agent_node_id, tool_node_id, "requests")
        graph.add_edge(tool_node_id, res_node_id, "targets")
        graph.add_edge(tool_node_id, gw_node_id, "intercepted by")
        graph.add_edge(gw_node_id, block_node_id, "enforces BLOCK")
        graph.add_edge(block_node_id, contain_node_id, "triggers")

        serialized = graph.to_serializable()
        now = utc_now_iso()

        if existing_rows:
            self.db.execute_write(
                """
                UPDATE attack_chains
                SET classification = ?, severity = ?, status = 'CONTAINED',
                    nodes_json = ?, edges_json = ?, updated_at = ?
                WHERE chain_id = ?
                """,
                (
                    classification,
                    severity,
                    json.dumps(serialized["nodes"]),
                    json.dumps(serialized["edges"]),
                    now,
                    chain_id,
                ),
            )
        else:
            self.db.execute_write(
                """
                INSERT INTO attack_chains (
                    chain_id, agent_id, session_id, classification, severity,
                    status, nodes_json, edges_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'CONTAINED', ?, ?, ?, ?)
                """,
                (
                    chain_id,
                    req.agent_id,
                    req.session_id,
                    classification,
                    severity,
                    json.dumps(serialized["nodes"]),
                    json.dumps(serialized["edges"]),
                    now,
                    now,
                ),
            )

        return {
            "detected": True,
            "chain_id": chain_id,
            "classification": classification,
            "severity": severity,
            "correlation_score": correlation_score,
            "nodes": serialized["nodes"],
            "edges": serialized["edges"],
        }

    def list_chains(self) -> List[Dict[str, Any]]:
        rows = self.db.execute_query("SELECT * FROM attack_chains ORDER BY updated_at DESC")
        result = []
        for r in rows:
            result.append(
                {
                    "chain_id": r["chain_id"],
                    "agent_id": r["agent_id"],
                    "session_id": r["session_id"],
                    "classification": r["classification"],
                    "severity": r["severity"],
                    "status": r["status"],
                    "nodes": json.loads(r["nodes_json"]),
                    "edges": json.loads(r["edges_json"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return result

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        rows = self.db.execute_query("SELECT * FROM attack_chains WHERE chain_id = ?", (chain_id,))
        if not rows:
            return None
        r = rows[0]
        return {
            "chain_id": r["chain_id"],
            "agent_id": r["agent_id"],
            "session_id": r["session_id"],
            "classification": r["classification"],
            "severity": r["severity"],
            "status": r["status"],
            "nodes": json.loads(r["nodes_json"]),
            "edges": json.loads(r["edges_json"]),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }


attack_chain_engine = AttackChainEngine()
