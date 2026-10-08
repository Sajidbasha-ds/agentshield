# AgentShield Security Whitepaper Summary

## Executive Summary
Autonomous AI agents introduce an architectural vulnerability: untrusted data read by a tool enters the same reasoning context that decides which privileged tool to invoke next. AgentShield addresses this by decoupling **agent reasoning** from **capability enforcement**.

## Key Architectural Properties
- **Non-Bypassable Mediation**: Protected tools verify a cryptographic HMAC token issued exclusively by the AgentShield Decision Engine upon an `ALLOW` verdict.
- **Deterministic Multi-Signal Risk Scoring**: Combines static tool sensitivity with dynamic session context taint, capability status, behavioral transition anomalies, and graph-correlated attack chains.
- **Capability-Level Containment**: Rather than terminating the entire service on suspicion, AgentShield dynamically quarantines high-risk capabilities (`read_secret`, `send_data`, `execute_command`) while preserving safe read-only capabilities (`read_document`, `list_files`), measurably reducing the blast radius while maintaining operational continuity.
