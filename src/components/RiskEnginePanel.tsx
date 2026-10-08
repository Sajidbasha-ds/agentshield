import React from 'react';
import { SecurityEvent } from '../api/client';

interface RiskEnginePanelProps {
  event: SecurityEvent | null;
}

export const RiskEnginePanel: React.FC<RiskEnginePanelProps> = ({ event }) => {
  const score = event ? event.risk_score : 0;
  const level = event ? event.risk_level : 'LOW';
  const contributors = event ? event.contributors : [];

  const barColor =
    score >= 75
      ? 'bg-red-500'
      : score >= 50
      ? 'bg-amber-500'
      : score >= 25
      ? 'bg-yellow-500'
      : 'bg-emerald-500';

  const textColor =
    score >= 75
      ? 'text-red-400'
      : score >= 50
      ? 'text-amber-400'
      : 'text-emerald-400';

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">Multi-Signal Risk Engine</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {event
                ? `Evaluating ${event.tool}(${event.resource}) · Event ${event.event_id}`
                : 'Awaiting intercepted tool request telemetry'}
            </p>
          </div>
          <div className="text-right font-mono tabular-nums">
            <span className={`text-2xl font-bold ${textColor}`}>{score}</span>
            <span className="text-xs text-slate-500"> / 100</span>
            <div className={`text-xs font-semibold ${textColor}`}>{level}</div>
          </div>
        </div>

        {/* 0-100 Gauge Bar */}
        <div className="mb-4">
          <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${barColor} transition-all duration-150`}
              style={{ width: `${Math.min(100, Math.max(2, score))}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] font-mono text-slate-500 mt-1.5">
            <span>0–24 LOW</span>
            <span>25–49 MEDIUM</span>
            <span>50–74 HIGH</span>
            <span>75–100 CRITICAL</span>
          </div>
        </div>

        {/* Contributor Breakdown */}
        <div className="space-y-2">
          <div className="text-xs font-mono text-slate-400">Independent Signal Contributors:</div>
          {contributors.length === 0 ? (
            <div className="text-xs text-slate-500 py-4 text-center bg-[#0B0F19] border border-slate-800/80 rounded">
              No risk signals recorded yet. Execute a task in the Agent Console to inspect real-time risk scoring.
            </div>
          ) : (
            <div className="bg-[#0B0F19] border border-slate-800/80 rounded divide-y divide-slate-800/70">
              {contributors.map((c, idx) => (
                <div key={idx} className="px-3.5 py-2 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-medium text-slate-200">{c.signal}</span>
                    <span className="text-slate-500 block text-[11px]">{c.detail}</span>
                  </div>
                  <span className="font-mono font-semibold text-slate-200 tabular-nums">
                    +{c.score}
                  </span>
                </div>
              ))}
              <div className="px-3.5 py-2 flex items-center justify-between text-xs font-mono font-semibold bg-slate-900/60">
                <span className="text-slate-300">Total Risk Score</span>
                <span className={textColor}>
                  {score} {level}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
