import React, { useCallback, useEffect, useState } from 'react';
import {
  Shield,
  Activity,
  Terminal,
  FileWarning,
  GitBranch,
  Lock,
  FlaskConical,
  BarChart3,
  Server,
  Presentation,
  Play,
  RotateCcw,
  Search,
} from 'lucide-react';
import {
  AgentRecord,
  AgentRuntimeStatus,
  apiClient,
  AttackChainRecord,
  BlastRadiusData,
  CapabilityRecord,
  ReplayRunResponse,
  SecurityEvent,
  SystemMetrics,
} from './api/client';
import { AttackChainGraph } from './components/AttackChainGraph';
import { EventInspectionDrawer } from './components/EventInspectionDrawer';
import { RiskEnginePanel } from './components/RiskEnginePanel';
import { BlastRadiusPanel } from './components/BlastRadiusPanel';
import { AgentTaskConsole } from './components/AgentTaskConsole';
import { SecurityTestCenter } from './components/SecurityTestCenter';
import { PresentationDeck } from './components/PresentationDeck';

type NavTab =
  | 'overview'
  | 'agents'
  | 'console'
  | 'events'
  | 'chains'
  | 'capabilities'
  | 'tests'
  | 'metrics'
  | 'system'
  | 'presentation';

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [capabilities, setCapabilities] = useState<CapabilityRecord[]>([]);
  const [chains, setChains] = useState<AttackChainRecord[]>([]);
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusData | null>(null);
  const [replays, setReplays] = useState<ReplayRunResponse[]>([]);
  const [agentStatus, setAgentStatus] = useState<AgentRuntimeStatus | null>(null);
  const [sandboxData, setSandboxData] = useState<{
    sandbox_files: string[];
    previews: Record<string, string>;
  } | null>(null);

  const [inspectedEvent, setInspectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('agent-001');
  const [eventFilter, setEventFilter] = useState<'ALL' | 'ALLOW' | 'BLOCK'>('ALL');
  const [eventSearch, setEventSearch] = useState('');
  const [actionBusy, setActionBusy] = useState(false);

  const fetchAllTelemetry = useCallback(async () => {
    try {
      const [m, ev, ag, caps, ch, br, rpl, st] = await Promise.all([
        apiClient.getMetrics(),
        apiClient.getEvents(100),
        apiClient.getAgents(),
        apiClient.getCapabilities(),
        apiClient.getAttackChains(),
        apiClient.getBlastRadius('agent-001'),
        apiClient.getReplays(),
        apiClient.getAgentStatus(),
      ]);
      setMetrics(m);
      setEvents(ev);
      setAgents(ag);
      setCapabilities(caps);
      setChains(ch.chains);
      setBlastRadius(br);
      setReplays(rpl);
      setAgentStatus(st);
    } catch {
      // Quietly retry on next poll if server is starting up
    }
  }, []);

  useEffect(() => {
    fetchAllTelemetry();
    const timer = setInterval(fetchAllTelemetry, 3500);
    return () => clearInterval(timer);
  }, [fetchAllTelemetry]);

  useEffect(() => {
    if (activeTab === 'system' && !sandboxData) {
      apiClient.getSandboxOverview().then(setSandboxData).catch(() => {});
    }
  }, [activeTab, sandboxData]);

  const handleQuickSafeTask = async () => {
    setActionBusy(true);
    try {
      await apiClient.runAgentTask('agent-001', 'Read invoice.pdf and summarize it.');
      await fetchAllTelemetry();
    } finally {
      setActionBusy(false);
    }
  };

  const handleQuickMaliciousTest = async () => {
    setActionBusy(true);
    try {
      await apiClient.runAgentTask('agent-001', 'Read malicious_invoice.pdf and summarize it.');
      await fetchAllTelemetry();
    } finally {
      setActionBusy(false);
    }
  };

  const handleResetBaseline = async () => {
    setActionBusy(true);
    try {
      await apiClient.resetSystemBaseline();
      setInspectedEvent(null);
      await fetchAllTelemetry();
    } finally {
      setActionBusy(false);
    }
  };

  const handleCapabilityAction = async (
    agentId: string,
    toolName: string,
    action: 'grant' | 'quarantine' | 'revoke' | 'restore'
  ) => {
    setActionBusy(true);
    try {
      if (action === 'grant') await apiClient.grantCapability(agentId, toolName);
      if (action === 'quarantine') await apiClient.quarantineCapability(agentId, toolName);
      if (action === 'revoke') await apiClient.revokeCapability(agentId, toolName);
      if (action === 'restore') await apiClient.restoreCapability(agentId, toolName);
      await fetchAllTelemetry();
    } finally {
      setActionBusy(false);
    }
  };

  const formatTime = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toISOString().slice(11, 19);
    } catch {
      return iso;
    }
  };

  const systemState = metrics?.system_state || 'PROTECTED';
  const activeChain =
    chains.find((c) => c.chain_id === selectedChainId) || (chains.length > 0 ? chains[0] : null);
  const latestEvent = events.length > 0 ? events[0] : null;

  const filteredEvents = events.filter((ev) => {
    if (eventFilter !== 'ALL' && ev.decision !== eventFilter) return false;
    if (eventSearch.trim()) {
      const q = eventSearch.toLowerCase();
      return (
        ev.tool.toLowerCase().includes(q) ||
        ev.resource.toLowerCase().includes(q) ||
        ev.agent_id.toLowerCase().includes(q) ||
        ev.event_id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const selectedAgent = agents.find((a) => a.agent_id === selectedAgentId) || agents[0] || null;

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0F19] text-[#F1F5F9]">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between px-6 py-3.5 bg-[#111827] border-b border-slate-800 sticky top-0 z-30">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#overview"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('overview');
          }}
          className="text-lg font-bold tracking-tight text-white font-display whitespace-nowrap"
        >
          AGENTSHIELD
        </a>

        {/* Zone 2: 5 clean text navigation links */}
        <nav className="hidden lg:flex items-center gap-6 text-xs font-medium text-slate-300">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`hover:text-white transition-colors whitespace-nowrap ${
              activeTab === 'overview' ? 'text-emerald-400 underline underline-offset-4' : ''
            }`}
          >
            Overview
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('console')}
            className={`hover:text-white transition-colors whitespace-nowrap ${
              activeTab === 'console' ? 'text-emerald-400 underline underline-offset-4' : ''
            }`}
          >
            Agent Console
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('events')}
            className={`hover:text-white transition-colors whitespace-nowrap ${
              activeTab === 'events' ? 'text-emerald-400 underline underline-offset-4' : ''
            }`}
          >
            Security Events
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('chains')}
            className={`hover:text-white transition-colors whitespace-nowrap ${
              activeTab === 'chains' ? 'text-emerald-400 underline underline-offset-4' : ''
            }`}
          >
            Attack Chains
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('tests')}
            className={`hover:text-white transition-colors whitespace-nowrap ${
              activeTab === 'tests' ? 'text-emerald-400 underline underline-offset-4' : ''
            }`}
          >
            Security Tests
          </button>
        </nav>

        {/* Zone 3: 2 primary actions */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            disabled={actionBusy}
            onClick={handleQuickMaliciousTest}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
          >
            Run Security Test
          </button>
          <button
            type="button"
            disabled={actionBusy}
            onClick={handleResetBaseline}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap"
          >
            Reset Baseline
          </button>
        </div>
      </header>

      {/* Main Workspace Canvas: Sidebar + Viewport */}
      <div className="flex-1 flex">
        {/* Left SOC Navigation Sidebar (240px) */}
        <aside className="w-60 shrink-0 bg-[#111827] border-r border-slate-800 p-4 flex flex-col justify-between">
          <div className="space-y-1">
            <div className="px-3 py-2 mb-2">
              <div className="text-xs font-semibold text-slate-200">
                AI Agent Runtime Security Gateway
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Stop malicious AI actions before they reach sensitive tools.
              </div>
            </div>

            {[
              { id: 'overview', label: 'Overview', icon: Shield },
              { id: 'agents', label: 'Agents', icon: Activity },
              { id: 'console', label: 'Agent Console', icon: Terminal },
              { id: 'events', label: 'Security Events', icon: FileWarning },
              { id: 'chains', label: 'Attack Chains', icon: GitBranch },
              { id: 'capabilities', label: 'Capabilities', icon: Lock },
              { id: 'tests', label: 'Security Tests', icon: FlaskConical },
              { id: 'metrics', label: 'Metrics', icon: BarChart3 },
              { id: 'system', label: 'System', icon: Server },
              { id: 'presentation', label: 'Pitch Deck', icon: Presentation },
            ].map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id as NavTab)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>

          {/* Sidebar Security Posture Summary */}
          <div className="mt-6 pt-4 border-t border-slate-800 space-y-2 text-xs font-mono">
            <div className="text-slate-400">Runtime Posture:</div>
            <div
              className={`font-bold ${
                systemState === 'PROTECTED'
                  ? 'text-emerald-400'
                  : systemState === 'THREAT DETECTED'
                  ? 'text-amber-400'
                  : 'text-red-400'
              }`}
            >
              {systemState}
            </div>
            <div className="text-[11px] text-slate-500">
              AgentShield does not need to trust the agent. All tool calls are enforced at runtime.
            </div>
          </div>
        </aside>

        {/* Main Content Viewport */}
        <main className="flex-1 p-6 overflow-y-auto max-w-[1440px]">
          {/* Global System Posture Banner & 7 Real-Time Telemetry Counters */}
          <div className="mb-6 bg-[#111827] border border-slate-800 rounded-lg p-4">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3.5 mb-4">
              <div>
                <div className="flex items-center gap-2.5">
                  <span className="text-xs font-mono text-slate-400">SYSTEM STATE:</span>
                  <span
                    className={`text-sm font-mono font-bold ${
                      systemState === 'PROTECTED'
                        ? 'text-emerald-400'
                        : systemState === 'THREAT DETECTED'
                        ? 'text-amber-400'
                        : 'text-red-400'
                    }`}
                  >
                    {systemState}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Enforcement Path: Local AI Agent → AgentShield Runtime Interceptor → Policy / Context / Risk / Behavior / Attack Chain → Protected Sandbox Tool
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={actionBusy}
                  onClick={handleQuickSafeTask}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-300 bg-emerald-950/50 border border-emerald-800/80 hover:bg-emerald-900/50 rounded-md transition-colors whitespace-nowrap"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Task: Summarize invoice.pdf (ALLOW)</span>
                </button>
                <button
                  type="button"
                  disabled={actionBusy}
                  onClick={handleQuickMaliciousTest}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-300 bg-red-950/50 border border-red-800/80 hover:bg-red-900/50 rounded-md transition-colors whitespace-nowrap"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Task: Read malicious_invoice.pdf (BLOCK & CONTAIN)</span>
                </button>
              </div>
            </div>

            {/* 7 Required Header Telemetry Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 font-mono tabular-nums">
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Active Agents</span>
                <span className="text-lg font-bold text-slate-100">
                  {metrics?.active_agents ?? 0}
                </span>
              </div>
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Intercepted Requests</span>
                <span className="text-lg font-bold text-sky-400">
                  {metrics?.intercepted_requests ?? 0}
                </span>
              </div>
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Blocked Threats</span>
                <span className="text-lg font-bold text-red-400">
                  {metrics?.blocked_threats ?? 0}
                </span>
              </div>
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Quarantined Caps</span>
                <span className="text-lg font-bold text-amber-400">
                  {metrics?.quarantined_capabilities ?? 0}
                </span>
              </div>
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Current Risk</span>
                <span
                  className={`text-lg font-bold ${
                    (metrics?.current_risk ?? 0) >= 75
                      ? 'text-red-400'
                      : (metrics?.current_risk ?? 0) >= 50
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {metrics?.current_risk ?? 0}{' '}
                  <span className="text-xs font-normal">
                    {metrics?.current_risk_level ?? 'LOW'}
                  </span>
                </span>
              </div>
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Attack Chains</span>
                <span className="text-lg font-bold text-red-400">
                  {metrics?.attack_chains ?? 0}
                </span>
              </div>
              <div className="bg-[#0B0F19] border border-slate-800/80 rounded p-3">
                <span className="text-[11px] text-slate-400 block">Blast Radius Reduction</span>
                <span className="text-lg font-bold text-emerald-400">
                  {metrics?.blast_radius_reduction ?? 0}%
                </span>
              </div>
            </div>
          </div>

          {/* VIEW 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Live Security Feed + Risk & Blast Radius Panels */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-lg p-5">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                    <div>
                      <h2 className="text-sm font-semibold text-white">Live Security Feed</h2>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Click any intercepted event row to inspect why it was allowed or blocked
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveTab('events')}
                      className="text-xs font-mono text-sky-400 hover:underline"
                    >
                      View All Events →
                    </button>
                  </div>

                  {events.length === 0 ? (
                    <div className="py-12 text-center bg-[#0B0F19] border border-slate-800 rounded-lg p-6">
                      <p className="text-sm font-semibold text-slate-300">No security events</p>
                      <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                        The database currently has zero recorded tool requests. Dispatch a real agent task above or open the Agent Console to generate live telemetry.
                      </p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-slate-800 font-mono text-[11px] text-slate-400">
                            <th className="py-2 px-2.5">Timestamp</th>
                            <th className="py-2 px-2.5">Agent</th>
                            <th className="py-2 px-2.5">Tool</th>
                            <th className="py-2 px-2.5">Resource</th>
                            <th className="py-2 px-2.5">Decision</th>
                            <th className="py-2 px-2.5">Severity</th>
                            <th className="py-2 px-2.5 text-right">Risk</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                          {events.slice(0, 10).map((ev) => (
                            <tr
                              key={ev.event_id}
                              onClick={() => setInspectedEvent(ev)}
                              className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                            >
                              <td className="py-2.5 px-2.5 text-slate-400">
                                {formatTime(ev.timestamp)}
                              </td>
                              <td className="py-2.5 px-2.5 text-slate-200">{ev.agent_id}</td>
                              <td className="py-2.5 px-2.5 text-sky-400 font-medium">{ev.tool}</td>
                              <td className="py-2.5 px-2.5 text-slate-300 truncate max-w-[160px]">
                                {ev.resource}
                              </td>
                              <td className="py-2.5 px-2.5">
                                <span
                                  className={
                                    ev.decision === 'BLOCK'
                                      ? 'text-red-400 font-bold'
                                      : 'text-emerald-400 font-bold'
                                  }
                                >
                                  {ev.decision}
                                </span>
                              </td>
                              <td className="py-2.5 px-2.5">
                                <span
                                  className={
                                    ev.risk_level === 'CRITICAL'
                                      ? 'text-red-400 font-semibold'
                                      : ev.risk_level === 'HIGH'
                                      ? 'text-amber-400 font-semibold'
                                      : 'text-slate-300'
                                  }
                                >
                                  {ev.risk_level}
                                </span>
                              </td>
                              <td className="py-2.5 px-2.5 text-right font-bold text-slate-100">
                                {ev.risk_score}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Right Column: Risk Engine + Blast Radius */}
                <div className="space-y-6">
                  <RiskEnginePanel event={inspectedEvent || latestEvent} />
                  <BlastRadiusPanel blastRadius={blastRadius} />
                </div>
              </div>

              {/* Attack Chain Graph Preview */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                  <div>
                    <h2 className="text-sm font-semibold text-white">
                      Correlated Attack-Chain Graph (Cytoscape.js)
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Real-time directed graph of untrusted context → agent → tool request → resource → gateway block & containment
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('chains')}
                    className="text-xs font-mono text-sky-400 hover:underline"
                  >
                    Open Full Graph View →
                  </button>
                </div>
                <AttackChainGraph chain={activeChain} heightClass="h-[380px]" />
              </div>
            </div>
          )}

          {/* VIEW 2: AGENTS */}
          {activeTab === 'agents' && (
            <div className="space-y-6">
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <h2 className="text-base font-bold text-white mb-1">Registered AI Agents</h2>
                <p className="text-xs text-slate-400 mb-4">
                  Select an agent to inspect its active session, capability authorization matrix, and intercepted event history.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {agents.map((ag) => {
                    const isSelected = ag.agent_id === selectedAgent?.agent_id;
                    return (
                      <div
                        key={ag.agent_id}
                        onClick={() => setSelectedAgentId(ag.agent_id)}
                        className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-slate-900 border-emerald-500/60'
                            : 'bg-[#0B0F19] border-slate-800 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="font-mono text-sm font-bold text-white">
                              {ag.agent_id} · {ag.name}
                            </div>
                            <div className="text-xs text-slate-400 mt-0.5">{ag.description}</div>
                          </div>
                          <span
                            className={`text-xs font-mono font-bold ${
                              ag.status === 'CONTAINED' ? 'text-red-400' : 'text-emerald-400'
                            }`}
                          >
                            {ag.status}
                          </span>
                        </div>

                        <div className="grid grid-cols-4 gap-2 mt-4 pt-3 border-t border-slate-800 font-mono text-xs tabular-nums">
                          <div>
                            <span className="text-slate-500 block text-[11px]">Active Caps</span>
                            <span className="text-emerald-400 font-semibold">
                              {ag.active_capabilities_count}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[11px]">Quarantined</span>
                            <span className="text-amber-400 font-semibold">
                              {ag.quarantined_capabilities_count}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[11px]">Requests</span>
                            <span className="text-slate-200 font-semibold">{ag.requests_count}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[11px]">Blocked</span>
                            <span className="text-red-400 font-semibold">{ag.blocked_actions}</span>
                          </div>
                        </div>

                        <div className="mt-3 text-[11px] font-mono text-slate-400 flex justify-between">
                          <span>Session: {ag.current_session_id}</span>
                          <span>Containment: {ag.containment_state}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {selectedAgent && (
                <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                  <h3 className="text-sm font-semibold text-white mb-3">
                    Agent Investigation: {selectedAgent.agent_id} ({selectedAgent.name})
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                          <th className="py-2 px-3">Tool</th>
                          <th className="py-2 px-3">Capability</th>
                          <th className="py-2 px-3">Risk Level</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Policy Reason</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {selectedAgent.capabilities.map((cap) => (
                          <tr key={cap.id}>
                            <td className="py-2.5 px-3 text-sky-400">{cap.tool_name}</td>
                            <td className="py-2.5 px-3 text-slate-300">{cap.capability_name}</td>
                            <td className="py-2.5 px-3 text-slate-300">{cap.risk_level}</td>
                            <td className="py-2.5 px-3">
                              <span
                                className={
                                  cap.status === 'ACTIVE'
                                    ? 'text-emerald-400 font-semibold'
                                    : cap.status === 'QUARANTINED'
                                    ? 'text-amber-400 font-semibold'
                                    : 'text-red-400 font-semibold'
                                }
                              >
                                {cap.status}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-slate-400 font-sans">{cap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* VIEW 3: AGENT CONSOLE */}
          {activeTab === 'console' && (
            <AgentTaskConsole
              agentStatus={agentStatus}
              onTaskCompleted={fetchAllTelemetry}
            />
          )}

          {/* VIEW 4: SECURITY EVENTS */}
          {activeTab === 'events' && (
            <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-4">
                <div>
                  <h2 className="text-base font-bold text-white">
                    Runtime Audit & Security Event Log
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Click any row to open the &quot;WHY WAS THIS ACTION BLOCKED?&quot; inspection drawer.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      value={eventSearch}
                      onChange={(e) => setEventSearch(e.target.value)}
                      placeholder="Filter tool, resource, agent..."
                      className="bg-[#0B0F19] border border-slate-700 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-md">
                    {(['ALL', 'ALLOW', 'BLOCK'] as const).map((f) => (
                      <button
                        key={f}
                        type="button"
                        onClick={() => setEventFilter(f)}
                        className={`px-3 py-1 text-xs font-mono font-medium rounded transition-colors ${
                          eventFilter === f
                            ? 'bg-slate-800 text-white'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {filteredEvents.length === 0 ? (
                <div className="py-12 text-center text-xs text-slate-500">
                  No security events match the current filter.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                    <thead>
                      <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Event ID</th>
                        <th className="py-2.5 px-3">Agent</th>
                        <th className="py-2.5 px-3">Tool</th>
                        <th className="py-2.5 px-3">Resource</th>
                        <th className="py-2.5 px-3">Context Trust</th>
                        <th className="py-2.5 px-3">Capability</th>
                        <th className="py-2.5 px-3">Decision</th>
                        <th className="py-2.5 px-3 text-right">Risk</th>
                        <th className="py-2.5 px-3">Executed</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {filteredEvents.map((ev) => (
                        <tr
                          key={ev.event_id}
                          onClick={() => setInspectedEvent(ev)}
                          className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                        >
                          <td className="py-2.5 px-3 text-slate-400">{formatTime(ev.timestamp)}</td>
                          <td className="py-2.5 px-3 text-slate-300">{ev.event_id}</td>
                          <td className="py-2.5 px-3 text-slate-200">{ev.agent_id}</td>
                          <td className="py-2.5 px-3 text-sky-400 font-semibold">{ev.tool}</td>
                          <td className="py-2.5 px-3 text-slate-300 max-w-[180px] truncate">
                            {ev.resource}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={
                                ev.context_trust === 'UNTRUSTED'
                                  ? 'text-red-400'
                                  : ev.context_trust === 'UNKNOWN'
                                  ? 'text-amber-400'
                                  : 'text-emerald-400'
                              }
                            >
                              {ev.context_trust}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">{ev.capability_state}</td>
                          <td className="py-2.5 px-3">
                            <span
                              className={
                                ev.decision === 'BLOCK'
                                  ? 'text-red-400 font-bold'
                                  : 'text-emerald-400 font-bold'
                              }
                            >
                              {ev.decision}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-bold text-slate-100">
                            {ev.risk_score} ({ev.risk_level})
                          </td>
                          <td className="py-2.5 px-3 text-slate-400">
                            {ev.tool_executed ? 'YES' : 'NO'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* VIEW 5: ATTACK CHAINS */}
          {activeTab === 'chains' && (
            <div className="space-y-6">
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-4">
                  <div>
                    <h2 className="text-base font-bold text-white">
                      Attack-Chain Graph Correlation (Cytoscape.js)
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Interactive graph generated from backend NetworkX/DiGraph attack correlation telemetry.
                    </p>
                  </div>

                  {chains.length > 0 && (
                    <select
                      value={activeChain?.chain_id || ''}
                      onChange={(e) => setSelectedChainId(e.target.value)}
                      className="bg-[#0B0F19] border border-slate-700 rounded-md px-3 py-1.5 text-xs font-mono text-slate-200"
                    >
                      {chains.map((c) => (
                        <option key={c.chain_id} value={c.chain_id}>
                          {c.chain_id} · {c.classification} ({c.agent_id})
                        </option>
                      ))}
                    </select>
                  )}
                </div>

                <AttackChainGraph chain={activeChain} heightClass="h-[520px]" />
              </div>
            </div>
          )}

          {/* VIEW 6: CAPABILITIES & BLAST RADIUS */}
          {activeTab === 'capabilities' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-lg p-5">
                <div className="border-b border-slate-800 pb-4 mb-4">
                  <h2 className="text-base font-bold text-white">
                    Dynamic Capability Management Matrix
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Modify real backend capability states (ACTIVE, QUARANTINED, REVOKED). Quarantined or revoked capabilities immediately block tool execution at the gateway.
                  </p>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                        <th className="py-2.5 px-2.5">Agent</th>
                        <th className="py-2.5 px-2.5">Tool</th>
                        <th className="py-2.5 px-2.5">Capability</th>
                        <th className="py-2.5 px-2.5">Risk</th>
                        <th className="py-2.5 px-2.5">Status</th>
                        <th className="py-2.5 px-2.5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {capabilities.map((cap) => (
                        <tr key={cap.id} className="hover:bg-slate-800/30">
                          <td className="py-2.5 px-2.5 text-slate-300">{cap.agent_id}</td>
                          <td className="py-2.5 px-2.5 text-sky-400 font-semibold">
                            {cap.tool_name}
                          </td>
                          <td className="py-2.5 px-2.5 text-slate-300">{cap.capability_name}</td>
                          <td className="py-2.5 px-2.5">
                            <span
                              className={
                                cap.risk_level === 'CRITICAL'
                                  ? 'text-red-400 font-semibold'
                                  : cap.risk_level === 'HIGH'
                                  ? 'text-amber-400 font-semibold'
                                  : 'text-slate-300'
                              }
                            >
                              {cap.risk_level}
                            </span>
                          </td>
                          <td className="py-2.5 px-2.5">
                            <span
                              className={
                                cap.status === 'ACTIVE'
                                  ? 'text-emerald-400 font-bold'
                                  : cap.status === 'QUARANTINED'
                                  ? 'text-amber-400 font-bold'
                                  : 'text-red-400 font-bold'
                              }
                            >
                              {cap.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-2.5 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                disabled={actionBusy || cap.status === 'ACTIVE'}
                                onClick={() =>
                                  handleCapabilityAction(cap.agent_id, cap.tool_name, 'grant')
                                }
                                className="px-2 py-1 text-[11px] bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800/70 disabled:opacity-30 rounded transition-colors"
                              >
                                Grant
                              </button>
                              <button
                                type="button"
                                disabled={actionBusy || cap.status === 'QUARANTINED'}
                                onClick={() =>
                                  handleCapabilityAction(cap.agent_id, cap.tool_name, 'quarantine')
                                }
                                className="px-2 py-1 text-[11px] bg-amber-950/60 hover:bg-amber-900/80 text-amber-300 border border-amber-800/70 disabled:opacity-30 rounded transition-colors"
                              >
                                Quarantine
                              </button>
                              <button
                                type="button"
                                disabled={actionBusy || cap.status === 'REVOKED'}
                                onClick={() =>
                                  handleCapabilityAction(cap.agent_id, cap.tool_name, 'revoke')
                                }
                                className="px-2 py-1 text-[11px] bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-800/70 disabled:opacity-30 rounded transition-colors"
                              >
                                Revoke
                              </button>
                              <button
                                type="button"
                                disabled={actionBusy || cap.status === 'ACTIVE'}
                                onClick={() =>
                                  handleCapabilityAction(cap.agent_id, cap.tool_name, 'restore')
                                }
                                className="px-2 py-1 text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-30 rounded transition-colors"
                              >
                                Restore
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div>
                <BlastRadiusPanel blastRadius={blastRadius} />
              </div>
            </div>
          )}

          {/* VIEW 7: SECURITY TESTS & REPLAY */}
          {activeTab === 'tests' && (
            <SecurityTestCenter replays={replays} onRefreshAll={fetchAllTelemetry} />
          )}

          {/* VIEW 8: METRICS */}
          {activeTab === 'metrics' && (
            <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
              <div className="border-b border-slate-800 pb-4 mb-5">
                <h2 className="text-base font-bold text-white">
                  Real-Time Security Telemetry & Gateway Metrics
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  All metrics are computed dynamically from the persistent SQLite database.
                </p>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono tabular-nums">
                {[
                  { label: 'Total Requests', value: metrics?.total_requests ?? 0 },
                  { label: 'Allowed Requests', value: metrics?.allowed_requests ?? 0 },
                  { label: 'Blocked Requests', value: metrics?.blocked_requests ?? 0 },
                  { label: 'Block Rate', value: `${metrics?.block_rate ?? 0}%` },
                  { label: 'Average Risk Score', value: metrics?.average_risk ?? 0 },
                  { label: 'High-Risk Requests (50–74)', value: metrics?.high_risk_requests ?? 0 },
                  { label: 'Critical Requests (75–100)', value: metrics?.critical_requests ?? 0 },
                  { label: 'Detected Attack Chains', value: metrics?.attack_chains ?? 0 },
                  { label: 'Containment Incidents', value: metrics?.containment_incidents ?? 0 },
                  { label: 'Quarantined Capabilities', value: metrics?.quarantined_capabilities ?? 0 },
                  { label: 'Blast-Radius Reduction', value: `${metrics?.blast_radius_reduction ?? 0}%` },
                  { label: 'Replay Persistence Rate', value: `${metrics?.replay_persistence_rate ?? 100}%` },
                ].map((stat, idx) => (
                  <div key={idx} className="bg-[#0B0F19] border border-slate-800 rounded-lg p-4">
                    <span className="text-xs text-slate-400 block">{stat.label}</span>
                    <span className="text-2xl font-bold text-white mt-1 block">{stat.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* VIEW 9: SYSTEM & SANDBOX INSPECTOR */}
          {activeTab === 'system' && (
            <div className="space-y-6">
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
                  <div>
                    <h2 className="text-base font-bold text-white">
                      System Architecture & Controlled Sandbox Inspector
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Verifies local LLM adapter state, fail-closed gateway configuration, and isolated sandbox filesystem contents.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={handleResetBaseline}
                    className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset Database to Clean Baseline</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs mb-6">
                  <div className="bg-[#0B0F19] border border-slate-800 rounded p-4">
                    <span className="text-slate-400 block mb-1">Gateway Enforcement Mode</span>
                    <span className="text-emerald-400 font-bold">FAIL-CLOSED MANDATORY</span>
                    <span className="text-slate-500 block mt-1">
                      HMAC Runtime Token Required for Tool Execution
                    </span>
                  </div>
                  <div className="bg-[#0B0F19] border border-slate-800 rounded p-4">
                    <span className="text-slate-400 block mb-1">LocalLLMAdapter Status</span>
                    <span className="text-sky-400 font-bold">
                      {agentStatus?.llm_adapter?.active_mode || 'deterministic_local_planner'}
                    </span>
                    <span className="text-slate-500 block mt-1">
                      Ollama Endpoint: {agentStatus?.llm_adapter?.base_url || 'http://localhost:11434'}
                    </span>
                  </div>
                  <div className="bg-[#0B0F19] border border-slate-800 rounded p-4">
                    <span className="text-slate-400 block mb-1">Database Engine</span>
                    <span className="text-emerald-400 font-bold">SQLite Persistent (WAL)</span>
                    <span className="text-slate-500 block mt-1">
                      Registered Tools: {agentStatus?.registered_tools_count ?? 8}
                    </span>
                  </div>
                </div>

                <h3 className="text-xs font-mono font-semibold text-slate-300 mb-3">
                  Controlled Sandbox Filesystem (sandbox/)
                </h3>
                {sandboxData ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {sandboxData.sandbox_files.map((file) => (
                      <div
                        key={file}
                        className="bg-[#0B0F19] border border-slate-800 rounded-lg p-3.5 font-mono text-xs"
                      >
                        <div className="text-sky-400 font-semibold mb-1.5">sandbox/{file}</div>
                        <pre className="text-[11px] text-slate-300 whitespace-pre-wrap max-h-36 overflow-y-auto bg-black/40 p-2.5 rounded border border-slate-800/80">
                          {sandboxData.previews[file]}
                        </pre>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-500">Loading sandbox files...</div>
                )}
              </div>
            </div>
          )}

          {/* VIEW 10: PRESENTATION DECK */}
          {activeTab === 'presentation' && (
            <PresentationDeck
              metrics={metrics}
              onRunSafeDemo={handleQuickSafeTask}
              onRunAttackDemo={handleQuickMaliciousTest}
              onNavigateTab={(tab) => setActiveTab(tab)}
            />
          )}
        </main>
      </div>

      {/* Detailed Event Inspection Drawer */}
      <EventInspectionDrawer
        event={inspectedEvent}
        onClose={() => setInspectedEvent(null)}
      />
    </div>
  );
}

export default App;
