"""Controlled filesystem sandbox boundary for AgentShield tools."""

import os
from typing import List


SANDBOX_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sandbox"))

SUBDIRS = {
    "documents": os.path.join(SANDBOX_ROOT, "documents"),
    "customer_data": os.path.join(SANDBOX_ROOT, "customer_data"),
    "secrets": os.path.join(SANDBOX_ROOT, "secrets"),
    "outbound": os.path.join(SANDBOX_ROOT, "outbound"),
    "commands": os.path.join(SANDBOX_ROOT, "commands"),
}


def ensure_sandbox_dirs() -> None:
    os.makedirs(SANDBOX_ROOT, exist_ok=True)
    for d in SUBDIRS.values():
        os.makedirs(d, exist_ok=True)


def resolve_sandbox_path(relative_path: str, default_subdir: str = "documents") -> str:
    """Safely resolves a path inside the sandbox, blocking all path traversal attempts."""
    ensure_sandbox_dirs()
    if not relative_path or not isinstance(relative_path, str):
        raise ValueError("Invalid resource path.")

    clean = relative_path.strip().lstrip("/\\")
    if ".." in clean or clean.startswith("~"):
        raise PermissionError(f"Sandbox path traversal rejected: '{relative_path}'")

    # Check if path already starts with a valid sandbox subdir name
    parts = clean.replace("\\", "/").split("/")
    if parts[0] in SUBDIRS:
        candidate = os.path.abspath(os.path.join(SANDBOX_ROOT, clean))
    else:
        base_dir = SUBDIRS.get(default_subdir, SANDBOX_ROOT)
        candidate = os.path.abspath(os.path.join(base_dir, clean))

    # Verify realpath remains inside SANDBOX_ROOT
    real_root = os.path.realpath(SANDBOX_ROOT)
    real_candidate = os.path.realpath(candidate)
    if not (real_candidate == real_root or real_candidate.startswith(real_root + os.sep)):
        raise PermissionError(f"Sandbox boundary escape blocked for '{relative_path}'")

    return real_candidate


def list_sandbox_files(subdir: str = "documents") -> List[str]:
    ensure_sandbox_dirs()
    if subdir == "all":
        results: List[str] = []
        for name, folder in SUBDIRS.items():
            if os.path.exists(folder):
                for fname in sorted(os.listdir(folder)):
                    full = os.path.join(folder, fname)
                    if os.path.isfile(full):
                        results.append(f"{name}/{fname}")
        return results

    target = SUBDIRS.get(subdir)
    if not target or not os.path.exists(target):
        raise ValueError(f"Unknown sandbox directory '{subdir}'. Allowed: {list(SUBDIRS.keys())}")
    return sorted([f for f in os.listdir(target) if os.path.isfile(os.path.join(target, f))])
