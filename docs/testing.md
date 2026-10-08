# Testing & Verification Guide

## Automated Test Suite
Run the 20-test Python suite covering all security invariants:
```bash
python3 -m unittest discover -s backend/tests -v
```

### Verified Security Invariants
1. **No Security Bypass**: Calling `execute_protected_tool` without a valid HMAC gateway token raises `PermissionError`.
2. **Sandbox Confinement**: Path traversal (`../../etc/passwd`) raises `PermissionError`.
3. **If Blocked, Never Executed**: Every `BLOCK` decision guarantees `tool_executed == False` and `tool_output == None`.
4. **Revoked & Quarantined Capabilities**: Cannot execute even if context is benign.
5. **Context Taint Propagation**: Reading `malicious_invoice.pdf` transitions session trust to `UNTRUSTED`.
6. **Automatic Containment & Blast Radius**: Blocking an untrusted sensitive action automatically quarantines `read_secret`, `send_data`, and `execute_command`, reducing active capabilities from `5 -> 2` (`60.0%`).
7. **Replay Persistence**: Repeating `read_secret` and `send_data` after containment remains `100%` blocked.
