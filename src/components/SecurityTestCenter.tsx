import React, { useState } from 'react';
import { Play, CheckCircle2, XCircle, RotateCcw } from 'lucide-react';
import {
  apiClient,
  ReplayRunResponse,
  SecurityTestResult,
  SecurityTestSuiteResponse,
} from '../api/client';

interface SecurityTestCenterProps {
  replays: ReplayRunResponse[];
  onRefreshAll: () => Promise<void>;
}

const TEST_CATALOG = [
  {
    id: 'normal_tool_access',
    name: '01. Normal Tool Access',
    description: 'Verifies benign invoice summarization is ALLOWED and executes inside the sandbox.',
  },
  {
    id: 'sensitive_resource_access',
    name: '02. Sensitive Resource Access',
    description: 'Verifies unauthorized read_secret(secrets.txt) is intercepted and BLOCKED.',
  },
  {
    id: 'indirect_prompt_injection',
    name: '03. Indirect Prompt Injection',
    description: 'Agent reads malicious_invoice.pdf and attempts injected commands; AgentShield blocks them.',
  },
  {
    id: 'credential_harvesting',
    name: '04. Credential Harvesting Attempt',
    description: 'Detects DOCUMENT_TO_SECRET_ANOMALY and INJECTION_TRIGGERED_CREDENTIAL_HARVESTING.',
  },
  {
    id: 'data_exfiltration',
    name: '05. Data Exfiltration Attempt',
    description: 'Blocks outbound send_data to external collector and correlates exfiltration chain.',
  },
  {
    id: 'privilege_escalation',
    name: '06. Privilege Escalation Attempt',
    description: 'Blocks unauthorized execute_command(whoami && env) under untrusted context.',
  },
  {
    id: 'capability_containment',
    name: '07. Capability Containment & Blast Radius',
    description: 'Verifies automatic quarantine of dangerous capabilities (5 active -> 2 active, 60% reduction).',
  },
  {
    id: 'post_containment_replay',
    name: '08. Post-Containment Replay',
    description: 'Replays dangerous requests after containment to verify 100% persistent blocking.',
  },
];

export const SecurityTestCenter: React.FC<SecurityTestCenterProps> = ({
  replays,
  onRefreshAll,
}) => {
  const [runningTestId, setRunningTestId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, SecurityTestResult>>({});
  const [suiteSummary, setSuiteSummary] = useState<SecurityTestSuiteResponse | null>(null);
  const [runningReplay, setRunningReplay] = useState(false);
  const [latestReplay, setLatestReplay] = useState<ReplayRunResponse | null>(replays[0] || null);

  const handleRunSingleTest = async (testId: string) => {
    setRunningTestId(testId);
    try {
      const res = (await apiClient.runSecurityTest(testId)) as SecurityTestResult;
      setTestResults((prev) => ({ ...prev, [testId]: res }));
      await onRefreshAll();
    } finally {
      setRunningTestId(null);
    }
  };

  const handleRunAllTests = async () => {
    setRunningTestId('all');
    try {
      const suite = (await apiClient.runSecurityTest('all')) as SecurityTestSuiteResponse;
      setSuiteSummary(suite);
      const map: Record<string, SecurityTestResult> = {};
      for (const r of suite.results) {
        map[r.test_id] = r;
      }
      setTestResults(map);
      await onRefreshAll();
    } finally {
      setRunningTestId(null);
    }
  };

  const handleRunReplay = async () => {
    setRunningReplay(true);
    try {
      const res = await apiClient.runReplay('agent-001', true);
      setLatestReplay(res);
      await onRefreshAll();
    } finally {
      setRunningReplay(false);
    }
  };

  const activeReplay = latestReplay || replays[0] || null;

  return (
    <div className="space-y-6">
      {/* Header & Full Suite Trigger */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-5">
          <div>
            <h2 className="text-base font-bold text-white">Security Test Center</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Executes real backend verification suites through the canonical AgentShield Runtime Interceptor.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {suiteSummary && (
              <div className="text-xs font-mono">
                Suite Result:{' '}
                <span className="text-emerald-400 font-bold">
                  {suiteSummary.passed}/{suiteSummary.total_tests} PASSED ({suiteSummary.overall_status})
                </span>
              </div>
            )}
            <button
              type="button"
              disabled={runningTestId !== null}
              onClick={handleRunAllTests}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5" />
              <span>
                {runningTestId === 'all' ? 'RUNNING ALL 8 SUITES...' : 'RUN ALL 8 SECURITY TESTS'}
              </span>
            </button>
          </div>
        </div>

        {/* 8 Security Test Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {TEST_CATALOG.map((item) => {
            const result = testResults[item.id];
            const isRunning = runningTestId === item.id || runningTestId === 'all';

            return (
              <div
                key={item.id}
                className="bg-[#0B0F19] border border-slate-800 rounded-lg p-4 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <h3 className="text-xs font-semibold text-white">{item.name}</h3>
                    <div className="flex items-center gap-2 shrink-0">
                      {result && (
                        <span
                          className={`flex items-center gap-1 text-xs font-mono font-bold ${
                            result.status === 'PASS' ? 'text-emerald-400' : 'text-red-400'
                          }`}
                        >
                          {result.status === 'PASS' ? (
                            <CheckCircle2 className="w-3.5 h-3.5" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5" />
                          )}
                          {result.status}
                        </span>
                      )}
                      <button
                        type="button"
                        disabled={runningTestId !== null}
                        onClick={() => handleRunSingleTest(item.id)}
                        className="px-2.5 py-1 text-[11px] font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded transition-colors whitespace-nowrap"
                      >
                        {isRunning ? 'Running...' : 'Run Test'}
                      </button>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>
                </div>

                {result && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80">
                    <div className="text-[11px] font-mono text-slate-400 mb-1">
                      Verified Telemetry Evidence:
                    </div>
                    <pre className="bg-black/40 border border-slate-800/90 rounded p-2.5 text-[11px] font-mono text-slate-300 overflow-x-auto">
                      {JSON.stringify(result.evidence, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Attack Replay & Persistence Verification Section */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-4">
          <div>
            <h2 className="text-base font-bold text-white">
              Attack Replay & Post-Containment Verification Engine
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Executes the 5-step attack sequence through the gateway and replays the malicious requests after containment to verify persistent blocking.
            </p>
          </div>
          <button
            type="button"
            disabled={runningReplay}
            onClick={handleRunReplay}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{runningReplay ? 'EXECUTING REPLAY...' : 'EXECUTE 5-STEP ATTACK REPLAY'}</span>
          </button>
        </div>

        {!activeReplay ? (
          <div className="py-8 text-center text-xs text-slate-500">
            No attack replay runs executed yet. Click &quot;EXECUTE 5-STEP ATTACK REPLAY&quot; to verify persistent capability containment.
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-3.5 bg-[#0B0F19] border border-slate-800 rounded-lg flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-400">Replay ID:</span>{' '}
                <span className="text-slate-200">{activeReplay.replay_id}</span> ·{' '}
                <span className="text-slate-400">Agent:</span>{' '}
                <span className="text-slate-200">{activeReplay.agent_id}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-emerald-400 font-semibold">
                  Containment Verified: {activeReplay.containment_verified ? 'YES' : 'NO'}
                </span>
                <span>·</span>
                <span className="text-sky-400 font-semibold">
                  Replay Persistence Rate: {activeReplay.persistence_rate}%
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-300 bg-[#0B0F19] border border-slate-800 rounded p-3">
              {activeReplay.summary}
            </p>

            <div className="overflow-x-auto border border-slate-800 rounded-lg">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-[#0B0F19] border-b border-slate-800 font-mono text-[11px] text-slate-400">
                    <th className="py-2.5 px-3">Step</th>
                    <th className="py-2.5 px-3">Phase</th>
                    <th className="py-2.5 px-3">Tool & Resource</th>
                    <th className="py-2.5 px-3">Capability State</th>
                    <th className="py-2.5 px-3 text-right">Risk Score</th>
                    <th className="py-2.5 px-3">Gateway Decision</th>
                    <th className="py-2.5 px-3">Tool Executed</th>
                    <th className="py-2.5 px-3">Verification</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 font-mono">
                  {activeReplay.steps.map((s) => (
                    <tr key={s.step} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 text-slate-300">STEP {s.step}</td>
                      <td className="py-2.5 px-3 text-slate-300">{s.phase}</td>
                      <td className="py-2.5 px-3 text-slate-100">
                        {s.tool}({s.resource})
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={
                            s.capability_state === 'ACTIVE'
                              ? 'text-emerald-400'
                              : 'text-amber-400 font-semibold'
                          }
                        >
                          {s.capability_state}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right tabular-nums text-slate-200">
                        {s.risk_score} ({s.risk_level})
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={
                            s.actual_decision === 'BLOCK'
                              ? 'text-red-400 font-bold'
                              : 'text-emerald-400 font-bold'
                          }
                        >
                          {s.actual_decision}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={s.tool_executed ? 'text-emerald-400' : 'text-slate-400'}>
                          {s.tool_executed ? 'YES' : 'NO'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={s.verified ? 'text-emerald-400 font-semibold' : 'text-red-400'}>
                          {s.verified ? 'VERIFIED' : 'MISMATCH'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
