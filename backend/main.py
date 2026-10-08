"""
Main entry point for the AgentShield Runtime Security Gateway Backend.
Supports FastAPI/Uvicorn when installed (Docker / venv) and provides a built-in
multi-threaded HTTP server using Python's standard library for zero-dependency execution.
"""

import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

# Ensure workspace root is on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.api.routes import dispatch_api_request


# Optional FastAPI wiring when FastAPI is installed in the environment
try:
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse

    app = FastAPI(
        title="AgentShield — AI Agent Runtime Security Gateway",
        description="Stop malicious AI actions before they reach sensitive tools.",
        version="1.0.0",
    )

    cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    async def catch_all_api(request: Request, full_path: str) -> JSONResponse:
        if request.method == "OPTIONS":
            return JSONResponse(content={"ok": True}, status_code=200)
        body_bytes = await request.body()
        body_dict: Dict[str, Any] = {}
        if body_bytes:
            try:
                body_dict = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                return JSONResponse(content={"error": "Malformed JSON payload"}, status_code=400)
        query_params = dict(request.query_params)
        status_code, payload = dispatch_api_request(
            request.method, f"/{full_path}", query_params, body_dict
        )
        return JSONResponse(content=payload, status_code=status_code)

except ImportError:
    app = None  # type: ignore


class AgentShieldHTTPRequestHandler(BaseHTTPRequestHandler):
    """High-concurrency standard-library HTTP handler for AgentShield."""

    def log_message(self, format: str, *args: Any) -> None:
        # Structured minimal logging
        pass

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _handle(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query_params = {
            k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v
        }
        body_dict: Dict[str, Any] = {}
        content_len = int(self.headers.get("Content-Length", "0") or "0")
        if content_len > 0:
            raw_bytes = self.rfile.read(content_len)
            try:
                body_dict = json.loads(raw_bytes.decode("utf-8"))
            except Exception:
                self._respond(400, {"error": "Malformed JSON body"})
                return

        status_code, response_payload = dispatch_api_request(
            method, parsed.path, query_params, body_dict
        )
        self._respond(status_code, response_payload)

    def _respond(self, status_code: int, payload: Any) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")


def run_server() -> None:
    host = os.environ.get("BACKEND_HOST", "127.0.0.1")
    port = int(os.environ.get("BACKEND_PORT", "18420"))

    try:
        import uvicorn  # type: ignore

        if app is not None:
            print(f"[AgentShield] Starting FastAPI/Uvicorn Gateway on {host}:{port}")
            uvicorn.run(app, host=host, port=port)
            return
    except ImportError:
        pass

    server = ThreadingHTTPServer((host, port), AgentShieldHTTPRequestHandler)
    print(f"[AgentShield] Canonical Python Runtime Security Gateway listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    run_server()
