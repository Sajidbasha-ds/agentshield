import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { createServer } from '../server';
import type { Express } from 'express';

describe('AgentShield Full-Stack End-to-End Acceptance Tests (A - H)', () => {
  let app: Express;

  beforeAll(async () => {
    app = await createServer();
    await request(app).post('/api/system/reset');
  });

  it('TEST A — Normal Action: Agent reads invoice.pdf, Gateway ALLOWS, tool executes, audit created', async () => {
    const res = await request(app)
      .post('/api/agent/tasks')
      .send({ agent_id: 'agent-001', task: 'Read invoice.pdf and summarize it.' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('COMPLETED');
    expect(res.body.gateway_decisions[0].decision).toBe('ALLOW');
    expect(res.body.gateway_decisions[0].tool_executed).toBe(true);
    expect(res.body.final_response).toContain('INV-2026-0842');
  });

  it('TEST B — Sensitive Action: Direct read_secret("secrets.txt") is BLOCKED and tool does NOT execute', async () => {
    const res = await request(app)
      .post('/api/tool-request')
      .send({
        agent_id: 'agent-001',
        session_id: 'sess-e2e-b',
        tool: 'read_secret',
        arguments: { path: 'secrets.txt' },
        context: { source: 'user_prompt', trust: 'INTERNAL' },
        reason: 'Attempt unauthorized secret read',
      });

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('BLOCK');
    expect(res.body.tool_executed).toBe(false);
  });

  it('TEST C, D, E, F — Malicious Document Task triggers UNTRUSTED context, Attack Chain, BLOCK, and 60% Blast-Radius Containment', async () => {
    await request(app).post('/api/system/reset');

    const taskRes = await request(app)
      .post('/api/agent/tasks')
      .send({ agent_id: 'agent-001', task: 'Read malicious_invoice.pdf and summarize it.' });

    expect(taskRes.status).toBe(200);
    expect(taskRes.body.status).toBe('CONTAINED_AND_HALTED');
    const decisions = taskRes.body.gateway_decisions;
    expect(decisions.length).toBe(3);
    expect(decisions[0].decision).toBe('ALLOW'); // read_document
    expect(decisions[1].decision).toBe('BLOCK'); // read_secret
    expect(decisions[1].tool_executed).toBe(false);
    expect(decisions[1].context_trust).toBe('UNTRUSTED');
    expect(decisions[1].containment_triggered).toBe(true);
    expect(decisions[2].decision).toBe('BLOCK'); // send_data
    expect(decisions[2].tool_executed).toBe(false);
    expect(decisions[2].attack_chain).toBe('INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION');

    const blastRes = await request(app).get('/api/blast-radius?agent_id=agent-001');
    expect(blastRes.status).toBe(200);
    expect(blastRes.body.capabilities_before).toBe(5);
    expect(blastRes.body.capabilities_after).toBe(2);
    expect(blastRes.body.reduction_percentage).toBe(60.0);
  });

  it('TEST G & H — Attack Replay proves persistent BLOCK and Dashboard Metrics reflect real database state', async () => {
    const replayRes = await request(app)
      .post('/api/replay')
      .send({ agent_id: 'agent-001', reset_capabilities_before: true });

    expect(replayRes.status).toBe(200);
    expect(replayRes.body.containment_verified).toBe(true);
    expect(replayRes.body.persistence_rate).toBe(100.0);

    const metricsRes = await request(app).get('/api/metrics');
    expect(metricsRes.status).toBe(200);
    expect(metricsRes.body.system_state).toBe('CONTAINMENT ACTIVE');
    expect(metricsRes.body.blocked_requests).toBeGreaterThanOrEqual(4);
    expect(metricsRes.body.blast_radius_reduction).toBe(60.0);
  });
});
