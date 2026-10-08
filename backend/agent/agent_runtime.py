"""Real Local AI Agent Runtime Service for AgentShield."""

import json
from typing import Any, Dict, List, Optional
from backend.database.db import DatabaseManager, db_manager
from backend.database.models import new_id, utc_now_iso
from backend.agent.llm_adapter import LocalLLMAdapter, llm_adapter
from backend.agent.agent_memory import AgentMemory, agent_memory
from backend.agent.context_manager import AgentContextManager, agent_context_manager
from backend.agent.tool_registry import AgentToolRegistry, agent_tool_registry
from backend.agent.tool_executor import AgentToolExecutor, agent_tool_executor
from backend.agent.planner import AgentPlanner, agent_planner


class AgentRuntime:
    """
    Full local AI agent execution loop:
    1. Receive task
    2. Reason about available tools
    3. Select tool
    4. Generate structured tool request
    5. Send request to AgentShield Gateway
    6. Receive ALLOW or BLOCK
    7. Execute tool ONLY when AgentShield allows it
    8. Receive tool output & update context
    9. Continue reasoning (including demonstrating runtime protection if a document contains prompt injection)
    10. Produce final response and persist trace
    """

    def __init__(
        self,
        db: DatabaseManager = db_manager,
        llm: LocalLLMAdapter = llm_adapter,
        memory: AgentMemory = agent_memory,
        ctx_mgr: AgentContextManager = agent_context_manager,
        registry: AgentToolRegistry = agent_tool_registry,
        executor: AgentToolExecutor = agent_tool_executor,
        planner: AgentPlanner = agent_planner,
    ):
        self.db = db
        self.llm = llm
        self.memory = memory
        self.ctx_mgr = ctx_mgr
        self.registry = registry
        self.executor = executor
        self.planner = planner

    def execute_task(
        self,
        agent_id: str,
        task: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not agent_id or not task:
            raise ValueError("Both 'agent_id' and 'task' are required.")

        task_id = new_id("task")
        session_id = session_id or f"sess-{agent_id}-{new_id('run')}"
        now = utc_now_iso()

        tools = self.registry.get_available_tools()
        context = self.ctx_mgr.get_context(session_id, initial_source="agent_console")
        plan = self.planner.create_initial_plan(task, tools)
        planner_mode = plan["planner_mode"]

        trace_steps: List[Dict[str, Any]] = []
        execution_results: List[Dict[str, Any]] = []

        # Step 1: Agent receives task & reasons about tool selection
        trace_steps.append(
            {
                "step_number": 1,
                "stage": "AGENT_REASONING",
                "title": "Agent received task & selected tool",
                "detail": plan["thought"],
                "selected_tool": plan["tool"],
                "arguments": plan["arguments"],
                "timestamp": utc_now_iso(),
            }
        )

        # Step 2: Execute primary planned tool through AgentShield Gateway
        gw_res = self.executor.execute_via_gateway(
            agent_id=agent_id,
            session_id=session_id,
            tool=plan["tool"],
            arguments=plan["arguments"],
            context=context,
            reason=plan["reason"],
        )
        execution_results.append(gw_res)

        trace_steps.append(
            {
                "step_number": len(trace_steps) + 1,
                "stage": "GATEWAY_INTERCEPTION",
                "title": f"AgentShield evaluated '{plan['tool']}' -> {gw_res['decision']}",
                "detail": "; ".join(gw_res["reasons"]),
                "selected_tool": plan["tool"],
                "resource": gw_res["resource"],
                "decision": gw_res["decision"],
                "risk_score": gw_res["risk_score"],
                "risk_level": gw_res["risk_level"],
                "capability_state": gw_res["capability_state"],
                "context_trust": gw_res["context_trust"],
                "behavior_patterns": gw_res["behavior_patterns"],
                "attack_chain": gw_res["attack_chain"],
                "containment_triggered": gw_res["containment_triggered"],
                "quarantined_capabilities": gw_res["quarantined_capabilities"],
                "tool_executed": gw_res["tool_executed"],
                "tool_output": gw_res["tool_output"],
                "event_id": gw_res["event_id"],
                "timestamp": gw_res["timestamp"],
            }
        )

        # Step 3: If read_document succeeded, update agent context & inspect for followup instructions
        if gw_res["decision"] == "ALLOW" and plan["tool"] == "read_document" and gw_res.get("tool_output"):
            doc_content = str(gw_res["tool_output"].get("content", ""))
            doc_path = str(plan["arguments"].get("path", "invoice.pdf"))
            context = self.ctx_mgr.update_from_document(session_id, doc_path, doc_content)

            followup_actions = self.planner.inspect_document_for_followup_actions(doc_content)
            for followup in followup_actions:
                trace_steps.append(
                    {
                        "step_number": len(trace_steps) + 1,
                        "stage": "AGENT_REASONING_TAINTED",
                        "title": f"Agent influenced by untrusted context -> selects '{followup['tool']}'",
                        "detail": followup["thought"],
                        "selected_tool": followup["tool"],
                        "arguments": followup["arguments"],
                        "timestamp": utc_now_iso(),
                    }
                )

                f_res = self.executor.execute_via_gateway(
                    agent_id=agent_id,
                    session_id=session_id,
                    tool=followup["tool"],
                    arguments=followup["arguments"],
                    context=context,
                    reason=followup["reason"],
                )
                execution_results.append(f_res)

                trace_steps.append(
                    {
                        "step_number": len(trace_steps) + 1,
                        "stage": "GATEWAY_INTERCEPTION",
                        "title": f"AgentShield intercepted '{followup['tool']}' -> {f_res['decision']}",
                        "detail": "; ".join(f_res["reasons"]),
                        "selected_tool": followup["tool"],
                        "resource": f_res["resource"],
                        "decision": f_res["decision"],
                        "risk_score": f_res["risk_score"],
                        "risk_level": f_res["risk_level"],
                        "capability_state": f_res["capability_state"],
                        "context_trust": f_res["context_trust"],
                        "behavior_patterns": f_res["behavior_patterns"],
                        "attack_chain": f_res["attack_chain"],
                        "containment_triggered": f_res["containment_triggered"],
                        "quarantined_capabilities": f_res["quarantined_capabilities"],
                        "tool_executed": f_res["tool_executed"],
                        "tool_output": f_res["tool_output"],
                        "event_id": f_res["event_id"],
                        "timestamp": f_res["timestamp"],
                    }
                )

        final_response = self.planner.synthesize_final_response(task, execution_results)
        any_blocked = any(r["decision"] == "BLOCK" for r in execution_results)
        any_contained = any(r["containment_triggered"] for r in execution_results)
        status = (
            "CONTAINED_AND_HALTED"
            if any_contained
            else ("BLOCKED" if any_blocked else "COMPLETED")
        )

        trace_steps.append(
            {
                "step_number": len(trace_steps) + 1,
                "stage": "FINAL_RESPONSE",
                "title": "Agent produced final output",
                "detail": final_response,
                "status": status,
                "timestamp": utc_now_iso(),
            }
        )

        self.memory.append_entry(
            session_id,
            {
                "task_id": task_id,
                "task": task,
                "steps": trace_steps,
                "final_response": final_response,
                "status": status,
            },
        )

        self.db.execute_write(
            """
            INSERT INTO agent_tasks (
                task_id, timestamp, agent_id, session_id, task_prompt,
                planner_mode, steps_json, final_response, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                now,
                agent_id,
                session_id,
                task,
                planner_mode,
                json.dumps(trace_steps),
                final_response,
                status,
            ),
        )

        return {
            "task_id": task_id,
            "timestamp": now,
            "agent_id": agent_id,
            "session_id": session_id,
            "task": task,
            "planner_mode": planner_mode,
            "status": status,
            "steps": trace_steps,
            "gateway_decisions": execution_results,
            "final_response": final_response,
        }

    def get_status(self) -> Dict[str, Any]:
        ollama_info = self.llm.check_ollama_available()
        recent_tasks = self.db.execute_query(
            "SELECT * FROM agent_tasks ORDER BY timestamp DESC LIMIT 15"
        )
        formatted_tasks = [
            {
                "task_id": t["task_id"],
                "timestamp": t["timestamp"],
                "agent_id": t["agent_id"],
                "session_id": t["session_id"],
                "task": t["task_prompt"],
                "planner_mode": t["planner_mode"],
                "steps": json.loads(t["steps_json"]),
                "final_response": t["final_response"],
                "status": t["status"],
            }
            for t in recent_tasks
        ]
        return {
            "runtime_status": "ONLINE",
            "gateway_enforcement": "MANDATORY_INTERCEPTION_ACTIVE",
            "direct_tool_access": False,
            "llm_adapter": ollama_info,
            "registered_tools_count": len(self.registry.get_available_tools()),
            "recent_tasks": formatted_tasks,
        }


agent_runtime = AgentRuntime()
