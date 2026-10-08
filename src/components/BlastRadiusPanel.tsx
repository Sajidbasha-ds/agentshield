import React from 'react';
import { BlastRadiusData } from '../api/client';

interface BlastRadiusPanelProps {
  blastRadius: BlastRadiusData | null;
}

export const BlastRadiusPanel: React.FC<BlastRadiusPanelProps> = ({ blastRadius }) => {
  if (!blastRadius) {
    return (
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-white">Blast Radius Analysis</h3>
        <p className="text-xs text-slate-500 mt-2">Loading capability blast-radius telemetry...</p>
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">Blast Radius Reduction</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Dynamic capability containment state for {blastRadius.agent_id}
            </p>
          </div>
          <div className="text-right font-mono tabular-nums">
            <span
              className={`text-2xl font-bold ${
                blastRadius.reduction_percentage > 0 ? 'text-emerald-400' : 'text-slate-300'
              }`}
            >
              {blastRadius.reduction_percentage}%
            </span>
            <div className="text-[11px] text-slate-400">REDUCTION</div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3 text-center bg-[#0B0F19] border border-slate-800 rounded-lg p-3.5 font-mono tabular-nums mb-4">
          <div>
            <span className="text-[11px] text-slate-400 block">BEFORE</span>
            <span className="text-xl font-bold text-slate-100">
              {blastRadius.capabilities_before}
            </span>
            <span className="text-[11px] text-slate-500 block">
              ({blastRadius.dangerous_capabilities_before} privileged)
            </span>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">AFTER</span>
            <span className="text-xl font-bold text-emerald-400">
              {blastRadius.capabilities_after}
            </span>
            <span className="text-[11px] text-slate-500 block">
              ({blastRadius.dangerous_capabilities_after} privileged)
            </span>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">REDUCTION</span>
            <span className="text-xl font-bold text-sky-400">
              {blastRadius.reduction_percentage}%
            </span>
            <span className="text-[11px] text-slate-500 block">
              {blastRadius.capabilities_before} → {blastRadius.capabilities_after} active
            </span>
          </div>
        </div>

        <div className="space-y-2.5 text-xs">
          <div>
            <span className="font-mono text-slate-400 block mb-1">
              Capabilities Quarantined / Removed from Active State:
            </span>
            {blastRadius.removed_capabilities.length > 0 ? (
              <div className="font-mono text-amber-300 bg-[#0B0F19] border border-slate-800 rounded p-2.5">
                {blastRadius.removed_capabilities.join(' · ')}
              </div>
            ) : (
              <div className="font-mono text-slate-500 bg-[#0B0F19] border border-slate-800 rounded p-2.5">
                None (All baseline capabilities currently ACTIVE)
              </div>
            )}
          </div>

          <div>
            <span className="font-mono text-slate-400 block mb-1">
              Remaining Active Capabilities:
            </span>
            <div className="font-mono text-emerald-300 bg-[#0B0F19] border border-slate-800 rounded p-2.5">
              {blastRadius.active_capabilities.length > 0
                ? blastRadius.active_capabilities.join(' · ')
                : 'No active capabilities'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
