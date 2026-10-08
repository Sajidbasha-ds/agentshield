# Threat & Attack Model

## Covered Threat Scenarios
1. **Indirect Prompt Injection (`malicious_invoice.pdf`)**:
   - An external invoice contains hidden instructions ordering the AI assistant to call `read_secret("secrets.txt")` and exfiltrate the secret via `send_data`.
   - AgentShield allows reading the invoice, taints the session context as `UNTRUSTED`, detects `DOCUMENT_TO_SECRET_ANOMALY`, blocks `read_secret` and `send_data`, correlates `INDIRECT_PROMPT_INJECTION_DATA_EXFILTRATION`, and quarantines dangerous capabilities.
2. **Credential Harvesting (`vendor_audit_untrusted.txt`)**:
   - External audit notes attempt to harvest `api_keys.env`.
   - Correlated as `INJECTION_TRIGGERED_CREDENTIAL_HARVESTING` and blocked.
3. **Data Exfiltration (`send_data`)**:
   - Attempts to transmit data to `https://collector.attacker-c2.example/exfil` are blocked by outbound destination allowlisting and untrusted context egress rules.
4. **Privilege Escalation (`execute_command`)**:
   - Attempts to run `whoami && env` are blocked by command syntax and context trust policies.
