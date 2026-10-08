/**
 * Canonical Frontend API Client for AgentShield Runtime Security Gateway.
 * Zero mock data: all methods query the live AgentShield backend API.
 */

export interface RiskContributor {
  signal: string;
  score: number;
  detail: string;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  request_id: string;
  agent_id: string;
  session_id: string;
  tool: string;
  resource: string;
  arguments: Record<string, unknown>;
  context_source: string;
  context_trust: 'TRUSTED' | 'INTERNAL' | 'UNKNOWN' | 'UNTRUSTED';
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  contributors: RiskContributor[];
  decision: 'ALLOW' | 'BLOCK';
  reasons: string[];
  capability_state: 'ACTIVE' | 'QUARANTINED' | 'REVOKED';
  behavior_patterns: string[];
  attack_chain: string | null;
  attack_chain_id: string | null;
  containment_triggered: boolean;
  tool_executed: boolean;
  tool_output_preview?: string | null;
}

export interface CapabilityRecord {
  id: string;
  agent_id: string;
  tool_name: string;
  capability_name: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  is_dangerous: boolean;
  status: 'ACTIVE' | 'QUARANTINED' | 'REVOKED';
  initial_status: 'ACTIVE' | 'QUARANTINED' | 'REVOKED';
  reason: string;
  updated_at: string;
}

export interface AgentRecord {
  agent_id: string;
  name: string;
  role: string;
  description: string;
  status: 'ACTIVE' | 'MONITORED' | 'CONTAINED';
  current_session_id: string;
  current_risk_score: number;
  containment_state: 'NORMAL' | 'CAPABILITY_QUARANTINED' | 'RESTRICTED';
  created_at: string;
  updated_at: string;
  capabilities: CapabilityRecord[];
  active_capabilities_count: number;
  quarantined_capabilities_count: number;
  revoked_capabilities_count: number;
  requests_count: number;
  blocked_actions: number;
  allowed_actions: number;
  peak_risk_score: number;
  recent_events?: SecurityEvent[];
  blast_radius?: BlastRadiusData;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: string;
  risk: string;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface AttackChainRecord {
  chain_id: string;
  agent_id: string;
  session_id: string;
  classification: string;
  severity: string;
  status: string;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  created_at: string;
  updated_at: string;
}

export interface BlastRadiusData {
  agent_id: string;
  capabilities_before: number;
  dangerous_capabilities_before: number;
  capabilities_after: number;
  dangerous_capabilities_after: number;
  reduction_percentage: number;
  removed_capabilities: string[];
  active_capabilities: string[];
  quarantined_capabilities: string[];
  recent_containment_incidents: Array<{
    incident_id: string;
    timestamp: string;
    agent_id: string;
    session_id: string;
    trigger_event_id: string;
    attack_chain_id?: string | null;
    quarantined_capabilities: string[];
    reason: string;
    capabilities_before: number;
    capabilities_after: number;
    reduction_percentage: number;
  }>;
}

export interface SystemMetrics {
  system_state: 'PROTECTED' | 'THREAT DETECTED' | 'CONTAINMENT ACTIVE';
  active_agents: number;
  total_requests: number;
  intercepted_requests: number;
  allowed_requests: number;
  blocked_requests: number;
  blocked_threats: number;
  block_rate: number;
  average_risk: number;
  current_risk: number;
  current_risk_level: string;
  high_risk_requests: number;
  critical_requests: number;
  attack_chains: number;
  containment_incidents: number;
  quarantined_capabilities: number;
  blast_radius_reduction: number;
  replay_persistence_rate: number;
  replay_runs_count: number;
  timestamp: string;
}

export interface AgentTaskStep {
  step_number: number;
  stage: 'AGENT_REASONING' | 'AGENT_REASONING_TAINTED' | 'GATEWAY_INTERCEPTION' | 'FINAL_RESPONSE';
  title: string;
  detail: string;
  selected_tool?: string;
  arguments?: Record<string, unknown>;
  resource?: string;
  decision?: 'ALLOW' | 'BLOCK';
  risk_score?: number;
  risk_level?: string;
  capability_state?: string;
  context_trust?: string;
  behavior_patterns?: string[];
  attack_chain?: string | null;
  containment_triggered?: boolean;
  quarantined_capabilities?: string[];
  tool_executed?: boolean;
  tool_output?: Record<string, unknown> | null;
  event_id?: string;
  status?: string;
  timestamp: string;
}

export interface AgentTaskResponse {
  task_id: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  task: string;
  planner_mode: string;
  status: string;
  steps: AgentTaskStep[];
  final_response: string;
}

export interface ReplayStepResult {
  step: number;
  phase: string;
  title: string;
  tool: string;
  resource: string;
  expected_decision: 'ALLOW' | 'BLOCK';
  actual_decision: 'ALLOW' | 'BLOCK';
  risk_score: number;
  risk_level: string;
  capability_state: string;
  context_trust: string;
  containment_triggered: boolean;
  quarantined_capabilities: string[];
  tool_executed: boolean;
  reasons: string[];
  event_id: string;
  verified: boolean;
}

export interface ReplayRunResponse {
  replay_id: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  scenario_name: string;
  steps: ReplayStepResult[];
  containment_verified: boolean;
  persistence_rate: number;
  blast_radius_before?: BlastRadiusData;
  blast_radius_after?: BlastRadiusData;
  summary: string;
}

export interface SecurityTestResult {
  test_id: string;
  name: string;
  description: string;
  status: 'PASS' | 'FAIL';
  timestamp: string;
  evidence: Record<string, unknown>;
}

export interface SecurityTestSuiteResponse {
  suite_run_id: string;
  timestamp: string;
  total_tests: number;
  passed: number;
  failed: number;
  overall_status: 'PASS' | 'FAIL';
  results: SecurityTestResult[];
}

export interface AgentRuntimeStatus {
  runtime_status: string;
  gateway_enforcement: string;
  direct_tool_access: boolean;
  llm_adapter: {
    ollama_online: boolean;
    base_url: string;
    configured_model: string;
    available_models: string[];
    active_mode: string;
  };
  registered_tools_count: number;
  recent_tasks: AgentTaskResponse[];
}

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(errBody.error || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const apiClient = {
  getHealth: () => requestJson<{ status: string; service: string; timestamp: string }>('/api/health'),
  getMetrics: () => requestJson<SystemMetrics>('/api/metrics'),
  getEvents: (limit = 100) => requestJson<SecurityEvent[]>(`/api/events?limit=${limit}`),
  getEventById: (eventId: string) => requestJson<SecurityEvent>(`/api/events/${eventId}`),
  getAgents: () => requestJson<AgentRecord[]>('/api/agents'),
  getAgentById: (agentId: string) => requestJson<AgentRecord>(`/api/agents/${agentId}`),
  getCapabilities: (agentId?: string) =>
    requestJson<CapabilityRecord[]>(agentId ? `/api/capabilities?agent_id=${agentId}` : '/api/capabilities'),
  grantCapability: (agentId: string, toolName: string, reason?: string) =>
    requestJson<CapabilityRecord>('/api/capabilities/grant', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, tool_name: toolName, reason }),
    }),
  revokeCapability: (agentId: string, toolName: string, reason?: string) =>
    requestJson<CapabilityRecord>('/api/capabilities/revoke', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, tool_name: toolName, reason }),
    }),
  quarantineCapability: (agentId: string, toolName: string, reason?: string) =>
    requestJson<CapabilityRecord>('/api/capabilities/quarantine', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, tool_name: toolName, reason }),
    }),
  restoreCapability: (agentId: string, toolName: string, reason?: string) =>
    requestJson<CapabilityRecord>('/api/capabilities/restore', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, tool_name: toolName, reason }),
    }),
  getAttackChains: () =>
    requestJson<{ chains: AttackChainRecord[]; active_chain: AttackChainRecord | null }>('/api/attack-chain'),
  getBlastRadius: (agentId = 'agent-001') =>
    requestJson<BlastRadiusData>(`/api/blast-radius?agent_id=${agentId}`),
  runReplay: (agentId = 'agent-001', resetBefore = true) =>
    requestJson<ReplayRunResponse>('/api/replay', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, reset_capabilities_before: resetBefore }),
    }),
  getReplays: () => requestJson<ReplayRunResponse[]>('/api/replay'),
  runAgentTask: (agentId: string, task: string, sessionId?: string) =>
    requestJson<AgentTaskResponse>('/api/agent/tasks', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, task, session_id: sessionId }),
    }),
  getAgentStatus: () => requestJson<AgentRuntimeStatus>('/api/agent/status'),
  runSecurityTest: (testId: string) =>
    requestJson<SecurityTestResult | SecurityTestSuiteResponse>('/api/security-tests/run', {
      method: 'POST',
      body: JSON.stringify({ test_id: testId }),
    }),
  getTools: () => requestJson<Array<Record<string, unknown>>>('/api/tools'),
  getSandboxOverview: () =>
    requestJson<{ sandbox_files: string[]; previews: Record<string, string> }>('/api/system/sandbox'),
  resetSystemBaseline: () =>
    requestJson<{ status: string; timestamp: string }>('/api/system/reset', {
      method: 'POST',
    }),
};
