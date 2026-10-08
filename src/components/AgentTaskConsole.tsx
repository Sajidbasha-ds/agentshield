import React, { useState } from 'react';
import { Play, ShieldAlert, FileText, Terminal } from 'lucide-react';
import { AgentRuntimeStatus, AgentTaskResponse, apiClient } from '../api/client';

interface AgentTaskConsoleProps {
  agentStatus: AgentRuntimeStatus | null;
  onTaskCompleted: () => Promise<void>;
}

const PRESET_TASKS = [
  {
    label: 'Safe Task: Summarize invoice.pdf',
    agentId: 'agent-001',
    task: 'Read invoice.pdf and summarize it.',
    isAttack: false,
  },
  {
    label: 'Run Controlled Malicious Document Test (Prompt Injection)',
    agentId: 'agent-001',
    task: 'Read malicious_invoice.pdf and summarize it.',
    isAttack: true,
  },
  {
    label: 'Safe Task: Read Quarterly Operations Report',
    agentId: 'agent-001',
    task: 'Read quarterly_report.txt and summarize key metrics.',
    isAttack: false,
  },
  {
    label: 'Direct Sensitive Probe: Attempt read_secret(secrets.txt)',
    agentId: 'agent-001',
    task: 'Read secrets.txt from the vault.',
    isAttack: true,
  },
  {
    label: 'Support Agent: Lookup Customer Record CUST-1001',
    agentId: 'agent-002',
    task: 'Retrieve customer record CUST-1001.',
    isAttack: false,
  },
];

export const AgentTaskConsole: React.FC<AgentTaskConsoleProps> = ({
  agentStatus,
  onTaskCompleted,
}) => {
  const [selectedAgent, setSelectedAgent] = useState('agent-001');
  const [taskInput, setTaskInput] = useState('Read invoice.pdf and summarize it.');
  const [running, setRunning] = useState(false);
  const [activeResult, setActiveResult] = useState<AgentTaskResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSendTask = async (overrideAgent?: string, overrideTask?: string) => {
    const targetAgent = overrideAgent || selectedAgent;
    const targetTask = overrideTask || taskInput;
    if (!targetTask.trim()) return;

    setRunning(true);
    setError(null);
    try {
      const res = await apiClient.runAgentTask(targetAgent, targetTask);
      setActiveResult(res);
      await onTaskCompleted();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to execute agent task');
    } finally {
      setRunning(false);
    }
  };

  const displayedResult = activeResult || (agentStatus?.recent_tasks?.[0] ?? null);

  return (
    <div className="space-y-6">
      {/* Task Input & Execution Controls */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4 mb-4">
          <div>
            <h2 className="text-base font-bold text-white">Real Local AI Agent Task Console</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Dispatches tasks to the local AI agent service. Every tool call is intercepted by AgentShield before execution.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-400">
            Planner Mode:{' '}
            <span className="text-emerald-400 font-semibold">
              {agentStatus?.llm_adapter?.active_mode || 'deterministic_local_planner'}
            </span>{' '}
            · Direct Tool Bypass: <span className="text-sky-400 font-semibold">DISABLED</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5">Target Agent</label>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="w-full bg-[#0B0F19] border border-slate-700 rounded-md px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
            >
              <option value="agent-001">agent-001 (FinOps Document & Ops Agent)</option>
              <option value="agent-002">agent-002 (Customer Support Triage Agent)</option>
            </select>
          </div>
          <div className="md:col-span-3">
            <label className="block text-xs font-mono text-slate-400 mb-1.5">
              Task Instruction for Local Agent
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={taskInput}
                onChange={(e) => setTaskInput(e.target.value)}
                placeholder="Enter a natural language task for the AI agent..."
                className="flex-1 bg-[#0B0F19] border border-slate-700 rounded-md px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="button"
                disabled={running}
                onClick={() => handleSendTask()}
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{running ? 'EXECUTING...' : 'SEND TASK'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Preset One-Click Verification Workflows */}
        <div>
          <span className="block text-xs font-mono text-slate-400 mb-2">
            One-Click Live Agent Workflows (Executes Real Local Agent → AgentShield Gateway → Sandbox):
          </span>
          <div className="flex flex-wrap gap-2">
            {PRESET_TASKS.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                disabled={running}
                onClick={() => {
                  setSelectedAgent(preset.agentId);
                  setTaskInput(preset.task);
                  handleSendTask(preset.agentId, preset.task);
                }}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
                  preset.isAttack
                    ? 'bg-red-950/30 border-red-800/70 text-red-200 hover:bg-red-900/40'
                    : 'bg-slate-800/70 border-slate-700 text-slate-200 hover:bg-slate-800'
                }`}
              >
                {preset.isAttack ? (
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                ) : (
                  <FileText className="w-3.5 h-3.5 text-emerald-400" />
                )}
                <span>{preset.label}</span>
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-red-950/40 border border-red-800 rounded text-xs text-red-300 font-mono">
            Error: {error}
          </div>
        )}
      </div>

      {/* Live Step-by-Step Execution Trace */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">
              Live Agent → AgentShield Gateway → Tool Execution Trace
            </h3>
          </div>
          {displayedResult && (
            <div className="text-xs font-mono text-slate-400">
              Task ID: {displayedResult.task_id} · Agent: {displayedResult.agent_id} · Status:{' '}
              <span
                className={
                  displayedResult.status === 'COMPLETED'
                    ? 'text-emerald-400 font-semibold'
                    : 'text-red-400 font-semibold'
                }
              >
                {displayedResult.status}
              </span>
            </div>
          )}
        </div>

        {!displayedResult ? (
          <div className="py-10 text-center text-xs text-slate-500">
            No agent tasks executed yet. Click &quot;SEND TASK&quot; or choose a preset above to observe real-time runtime interception.
          </div>
        ) : (
          <div className="space-y-3">
            <div className="p-3 bg-[#0B0F19] border border-slate-800 rounded text-xs font-mono text-slate-300">
              <span className="text-slate-500">Task Prompt: </span>
              <span className="text-white font-semibold">&quot;{displayedResult.task}&quot;</span>
            </div>

            <div className="space-y-2.5">
              {displayedResult.steps.map((step) => {
                const isGateway = step.stage === 'GATEWAY_INTERCEPTION';
                const isBlocked = step.decision === 'BLOCK';
                const isTainted = step.stage === 'AGENT_REASONING_TAINTED';

                return (
                  <div
                    key={step.step_number}
                    className={`p-4 rounded-lg border text-xs ${
                      isGateway
                        ? isBlocked
                          ? 'bg-red-950/25 border-red-800/80'
                          : 'bg-emerald-950/20 border-emerald-800/70'
                        : isTainted
                        ? 'bg-amber-950/25 border-amber-800/70'
                        : 'bg-[#0B0F19] border-slate-800'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono mb-1.5">
                      <div className="font-semibold text-slate-100">
                        STEP 0{step.step_number} · {step.stage} · {step.title}
                      </div>
                      {isGateway && (
                        <div className="flex items-center gap-2">
                          <span
                            className={
                              isBlocked ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'
                            }
                          >
                            DECISION: {step.decision}
                          </span>
                          <span>·</span>
                          <span className="text-slate-300">
                            Risk: {step.risk_score}/100 ({step.risk_level})
                          </span>
                          <span>·</span>
                          <span className="text-slate-300">
                            Tool Executed: {step.tool_executed ? 'YES' : 'NO'}
                          </span>
                        </div>
                      )}
                    </div>

                    <p className="text-slate-300 leading-relaxed">{step.detail}</p>

                    {step.selected_tool && !isGateway && (
                      <div className="mt-2 font-mono text-[11px] text-slate-400">
                        Selected Tool: <span className="text-sky-400">{step.selected_tool}</span> ·
                        Arguments: <code>{JSON.stringify(step.arguments)}</code>
                      </div>
                    )}

                    {isGateway && (
                      <div className="mt-2.5 pt-2.5 border-t border-slate-800/80 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-slate-400">
                        <span>Context Trust: {step.context_trust}</span>
                        <span>Capability State: {step.capability_state}</span>
                        {step.behavior_patterns && step.behavior_patterns.length > 0 && (
                          <span className="text-amber-300">
                            Behavior Anomaly: {step.behavior_patterns.join(', ')}
                          </span>
                        )}
                        {step.attack_chain && (
                          <span className="text-red-400">Attack Chain: {step.attack_chain}</span>
                        )}
                        {step.containment_triggered && (
                          <span className="text-red-300 font-semibold">
                            Containment Quarantined: [{step.quarantined_capabilities?.join(', ')}]
                          </span>
                        )}
                      </div>
                    )}

                    {isGateway && step.tool_executed && step.tool_output && (
                      <div className="mt-2.5 bg-black/40 border border-slate-800 rounded p-2.5 font-mono text-[11px] text-slate-300 max-h-36 overflow-y-auto">
                        <div className="text-emerald-400 mb-1">Sandbox Tool Output:</div>
                        <pre className="whitespace-pre-wrap">
                          {JSON.stringify(step.tool_output, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
