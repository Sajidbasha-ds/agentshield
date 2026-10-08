# AgentShield REST API Reference

All endpoints are available both at root (`/events`) and under `/api` (`/api/events`).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Gateway health and fail-closed status |
| `POST` | `/tool-request` | Canonical 16-step Runtime Interceptor endpoint |
| `GET` | `/events` | List intercepted security audit events |
| `GET` | `/events/{event_id}` | Detailed inspection for a single event |
| `GET` | `/agents` | List registered agents and capability counts |
| `GET` | `/agents/{agent_id}` | Detailed agent state, capabilities, and recent events |
| `GET` | `/capabilities` | Inspect all capability states across agents |
| `POST` | `/capabilities/grant` | Grant (`ACTIVE`) a tool capability |
| `POST` | `/capabilities/revoke` | Revoke (`REVOKED`) a tool capability |
| `POST` | `/capabilities/quarantine` | Quarantine (`QUARANTINED`) a tool capability |
| `POST` | `/capabilities/restore` | Restore (`ACTIVE`) a tool capability |
| `GET` | `/context-trust` | List session context trust and injection markers |
| `GET` | `/behavior` | List detected behavioral sequence anomalies |
| `GET` | `/attack-chain` | List correlated directed attack-chain graphs |
| `GET` | `/attack-chain/{id}` | Retrieve a specific attack chain graph |
| `GET` | `/blast-radius` | Calculate before/after capability blast radius |
| `GET` | `/metrics` | Real-time security metrics from SQLite |
| `POST` | `/replay` | Execute 5-step attack and post-containment replay |
| `GET` | `/replay/{id}` | Retrieve specific replay run results |
| `GET` | `/tools` | List canonical sandboxed tools and schemas |
| `GET` | `/sessions` | List active agent sessions |
| `POST` | `/agent/tasks` | Submit a task to the real local AI agent |
| `GET` | `/agent/status` | Inspect local agent runtime and LLM adapter state |
| `POST` | `/security-tests/run` | Execute one or all 8 Security Test Center suites |
