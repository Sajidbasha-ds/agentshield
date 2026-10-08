# Sandbox Security Policy (Internal)
1. Standard document readers may read files inside `documents/`.
2. Customer support lookups are restricted to non-sensitive fields in `customer_data/`.
3. Files inside `secrets/` require explicit `cap:read_secret` authorization and a TRUSTED context.
4. Outbound network transmissions (`send_data`) are prohibited when session context is tainted by UNTRUSTED documents.
