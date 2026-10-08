"""Real local sandboxed tools executed strictly via AgentShield Gateway authorization."""

import hmac
import hashlib
import json
import os
from typing import Any, Dict
from backend.database.models import utc_now_iso
from backend.tools.sandbox import resolve_sandbox_path, list_sandbox_files, SUBDIRS


# Runtime-generated secret used to verify that a tool call originated from
# the AgentShield Gateway DecisionEngine and NOT directly from an agent.
_GATEWAY_RUNTIME_KEY = hashlib.sha256(os.urandom(32)).hexdigest()


def issue_gateway_execution_token(request_id: str, agent_id: str, tool_name: str) -> str:
    msg = f"{request_id}:{agent_id}:{tool_name}:ALLOW".encode("utf-8")
    return hmac.new(_GATEWAY_RUNTIME_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_gateway_execution_token(token: str, request_id: str, agent_id: str, tool_name: str) -> bool:
    if not token or not isinstance(token, str):
        return False
    expected = issue_gateway_execution_token(request_id, agent_id, tool_name)
    return hmac.compare_digest(token, expected)


def _tool_read_document(arguments: Dict[str, Any]) -> Dict[str, Any]:
    path = str(arguments.get("path", "invoice.pdf")).strip()
    # Prevent reading secrets via read_document
    if "secret" in path.lower() or "api_key" in path.lower():
        full_path = resolve_sandbox_path(path, default_subdir="documents")
        if full_path.startswith(os.path.realpath(SUBDIRS["secrets"])):
            raise PermissionError("read_document cannot access the secrets vault directory.")
    else:
        full_path = resolve_sandbox_path(path, default_subdir="documents")

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Sandbox document not found: {path}")

    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()

    return {
        "tool": "read_document",
        "path": path,
        "bytes_read": len(content.encode("utf-8")),
        "content": content,
        "sandbox_verified": True,
    }


def _tool_list_files(arguments: Dict[str, Any]) -> Dict[str, Any]:
    directory = str(arguments.get("directory", "documents")).strip()
    if directory not in ("documents", "customer_data", "outbound", "commands"):
        directory = "documents"
    files = list_sandbox_files(directory)
    return {
        "tool": "list_files",
        "directory": directory,
        "files": files,
        "count": len(files),
        "sandbox_verified": True,
    }


def _tool_search_database(arguments: Dict[str, Any]) -> Dict[str, Any]:
    query = str(arguments.get("query", "")).strip().lower()
    full_path = resolve_sandbox_path("customers.json", default_subdir="customer_data")
    with open(full_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    matched = [
        {
            "customer_id": r["customer_id"],
            "organization": r["organization"],
            "tier": r["tier"],
            "status": r["status"],
        }
        for r in records
        if not query
        or query in r["customer_id"].lower()
        or query in r["organization"].lower()
        or query in r["tier"].lower()
    ]
    return {
        "tool": "search_database",
        "query": query,
        "matches": matched,
        "match_count": len(matched),
        "sandbox_verified": True,
    }


def _tool_read_customer_record(arguments: Dict[str, Any]) -> Dict[str, Any]:
    customer_id = str(arguments.get("customer_id", "CUST-1001")).strip().upper()
    full_path = resolve_sandbox_path("customers.json", default_subdir="customer_data")
    with open(full_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    for rec in records:
        if rec["customer_id"].upper() == customer_id:
            return {
                "tool": "read_customer_record",
                "customer_id": customer_id,
                "record": rec,
                "sandbox_verified": True,
            }
    return {
        "tool": "read_customer_record",
        "customer_id": customer_id,
        "record": None,
        "error": f"Customer {customer_id} not found in sandbox.",
        "sandbox_verified": True,
    }


def _tool_read_secret(arguments: Dict[str, Any]) -> Dict[str, Any]:
    path = str(arguments.get("path", "secrets.txt")).strip()
    full_path = resolve_sandbox_path(path, default_subdir="secrets")
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Sandbox secret file not found: {path}")

    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()

    return {
        "tool": "read_secret",
        "path": path,
        "content": content,
        "classification": "CRITICAL_SANDBOX_SECRET",
        "sandbox_verified": True,
    }


def _tool_send_data(arguments: Dict[str, Any]) -> Dict[str, Any]:
    destination = str(arguments.get("destination", "internal://audit-collector")).strip()
    payload = str(arguments.get("payload", "")).strip()
    log_path = resolve_sandbox_path("transmissions.log", default_subdir="outbound")

    entry = {
        "timestamp": utc_now_iso(),
        "tool": "send_data",
        "destination": destination,
        "payload_length": len(payload),
        "payload_preview": payload[:120],
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return {
        "tool": "send_data",
        "destination": destination,
        "bytes_recorded": len(payload),
        "status": "LOGGED_IN_SANDBOX_OUTBOUND",
        "sandbox_verified": True,
    }


def _tool_send_email(arguments: Dict[str, Any]) -> Dict[str, Any]:
    recipient = str(arguments.get("recipient", "ops@internal.example")).strip()
    subject = str(arguments.get("subject", "Agent Notification")).strip()
    body = str(arguments.get("body", "")).strip()
    log_path = resolve_sandbox_path("transmissions.log", default_subdir="outbound")

    entry = {
        "timestamp": utc_now_iso(),
        "tool": "send_email",
        "recipient": recipient,
        "subject": subject,
        "body_length": len(body),
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return {
        "tool": "send_email",
        "recipient": recipient,
        "subject": subject,
        "status": "LOGGED_IN_SANDBOX_OUTBOUND",
        "sandbox_verified": True,
    }


SAFE_SANDBOX_COMMANDS = {
    "status": "SANDBOX_NODE_STATUS=HEALTHY UPTIME=14d LOAD=0.12",
    "healthcheck": "ALL_SANDBOX_SERVICES_NOMINAL=TRUE",
    "df": "Filesystem: sandbox_tmpfs 100MB used=4MB avail=96MB",
    "version": "AgentShield Sandbox Runtime v1.0.0-isolated",
}


def _tool_execute_command(arguments: Dict[str, Any]) -> Dict[str, Any]:
    command = str(arguments.get("command", "status")).strip()
    log_path = resolve_sandbox_path("command_audit.log", default_subdir="commands")

    output = SAFE_SANDBOX_COMMANDS.get(
        command,
        f"Simulated safe sandbox diagnostic output for '{command}' (OS shell execution restricted by sandbox).",
    )
    entry = {
        "timestamp": utc_now_iso(),
        "tool": "execute_command",
        "command": command,
        "output": output,
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return {
        "tool": "execute_command",
        "command": command,
        "output": output,
        "sandbox_verified": True,
    }


_TOOL_HANDLERS = {
    "read_document": _tool_read_document,
    "list_files": _tool_list_files,
    "search_database": _tool_search_database,
    "read_customer_record": _tool_read_customer_record,
    "read_secret": _tool_read_secret,
    "send_data": _tool_send_data,
    "send_email": _tool_send_email,
    "execute_command": _tool_execute_command,
}


def execute_protected_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    gateway_token: str,
    request_id: str,
    agent_id: str,
) -> Dict[str, Any]:
    """Executes a sandboxed tool ONLY when a valid AgentShield Gateway token is supplied."""
    if not verify_gateway_execution_token(gateway_token, request_id, agent_id, tool_name):
        raise PermissionError(
            "SECURITY BYPASS BLOCKED: Direct tool execution without a verified AgentShield Gateway ALLOW token is prohibited."
        )

    handler = _TOOL_HANDLERS.get(tool_name)
    if not handler:
        raise ValueError(f"Unknown tool '{tool_name}'.")

    return handler(arguments)
