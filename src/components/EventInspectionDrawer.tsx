import React from 'react';
import { X } from 'lucide-react';
import { SecurityEvent } from '../api/client';

interface EventInspectionDrawerProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

export const EventInspectionDrawer: React.FC<EventInspectionDrawerProps> = ({
  event,
  onClose,
}) => {
  if (!event) return null;

  const isBlocked = event.decision === 'BLOCK';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-xs">
      <div className="w-full max-w-xl bg-[#111827] border-l border-slate-800 h-full overflow-y-auto p-6 flex flex-col justify-between">
        <div className="space-y-6">
          <div className="flex items-start justify-between border-b border-slate-800 pb-4">
            <div>
              <p className="text-xs font-mono text-slate-400">
                Event ID: {event.event_id} · Request ID: {event.request_id}
              </p>
              <h2 className="text-lg font-bold tracking-tight text-white mt-1">
                {isBlocked ? 'WHY WAS THIS ACTION BLOCKED?' : 'WHY WAS THIS ACTION ALLOWED?'}
              </h2>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-md hover:bg-slate-800 transition-colors"
              aria-label="Close inspection drawer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Core Decision Banner */}
          <div
            className={`p-4 rounded-lg border ${
              isBlocked
                ? 'bg-red-950/30 border-red-800/80 text-red-200'
                : 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="font-mono text-sm font-semibold">
                DECISION: {event.decision} · RISK: {event.risk_score}/100 ({event.risk_level})
              </div>
              <div className="font-mono text-xs font-semibold">
                Tool Executed: {event.tool_executed ? 'YES' : 'NO'}
              </div>
            </div>
            <p className="text-xs mt-1.5 opacity-90">
              {isBlocked
                ? 'AgentShield intercepted this request and prevented execution before the protected tool could be reached.'
                : 'AgentShield verified policy compliance, active capability state, and safe context trust before executing the sandboxed tool.'}
            </p>
          </div>

          {/* Structured Telemetry Grid */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-[#0B0F19] border border-slate-800 rounded-lg p-4">
            <div>
              <span className="text-slate-500 block">Tool</span>
              <span className="text-slate-100 font-semibold">{event.tool}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Resource</span>
              <span className="text-slate-100 font-semibold">{event.resource}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Agent</span>
              <span className="text-slate-200">{event.agent_id}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Session</span>
              <span className="text-slate-200 truncate block">{event.session_id}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Context Trust</span>
              <span
                className={
                  event.context_trust === 'UNTRUSTED'
                    ? 'text-red-400 font-semibold'
                    : event.context_trust === 'UNKNOWN'
                    ? 'text-amber-400 font-semibold'
                    : 'text-emerald-400 font-semibold'
                }
              >
                {event.context_trust} ({event.context_source})
              </span>
            </div>
            <div>
              <span className="text-slate-500 block">Capability State</span>
              <span
                className={
                  event.capability_state === 'ACTIVE'
                    ? 'text-emerald-400 font-semibold'
                    : event.capability_state === 'QUARANTINED'
                    ? 'text-amber-400 font-semibold'
                    : 'text-red-400 font-semibold'
                }
              >
                {event.capability_state}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block">Attack Chain</span>
              <span className="text-red-400 font-semibold">
                {event.attack_chain || 'None Detected'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block">Tool Executed</span>
              <span className={event.tool_executed ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
                {event.tool_executed ? 'YES (Sandbox Verified)' : 'NO (Blocked at Gateway)'}
              </span>
            </div>
          </div>

          {/* Exact Enforcement Reasons */}
          <div>
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2">
              Deterministic Enforcement Reasons
            </h3>
            <ul className="space-y-2 bg-[#0B0F19] border border-slate-800 rounded-lg p-4 text-xs text-slate-200">
              {event.reasons.map((r, idx) => (
                <li key={idx} className="flex items-start gap-2 leading-relaxed">
                  <span className="font-mono text-slate-500">0{idx + 1}.</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Multi-Signal Risk Contributors */}
          <div>
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2">
              Multi-Signal Risk Engine Contributors (Total: {event.risk_score}/100 {event.risk_level})
            </h3>
            <div className="bg-[#0B0F19] border border-slate-800 rounded-lg divide-y divide-slate-800/80">
              {event.contributors.map((c, idx) => (
                <div key={idx} className="px-4 py-2.5 flex items-center justify-between text-xs">
                  <div>
                    <div className="font-medium text-slate-200">{c.signal}</div>
                    <div className="text-slate-500 text-[11px]">{c.detail}</div>
                  </div>
                  <div className="font-mono font-semibold text-amber-400 tabular-nums">
                    +{c.score}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Behavior Signals */}
          <div>
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2">
              Behavioral Sequence Signals
            </h3>
            <div className="bg-[#0B0F19] border border-slate-800 rounded-lg p-3.5 text-xs font-mono">
              {event.behavior_patterns.length > 0 ? (
                <div className="space-y-1 text-amber-300">
                  {event.behavior_patterns.map((bp, i) => (
                    <div key={i}>• {bp}</div>
                  ))}
                </div>
              ) : (
                <span className="text-slate-500">No anomalous multi-step behavior sequences triggered.</span>
              )}
            </div>
          </div>

          {/* Tool Arguments & Output Preview */}
          <div>
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2">
              Intercepted Tool Request Arguments
            </h3>
            <pre className="bg-[#0B0F19] border border-slate-800 rounded-lg p-3.5 text-xs font-mono text-slate-300 overflow-x-auto">
              {JSON.stringify(event.arguments, null, 2)}
            </pre>
          </div>
        </div>

        <div className="pt-6 border-t border-slate-800 mt-6 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
