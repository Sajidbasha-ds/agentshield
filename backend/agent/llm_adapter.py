"""Local LLM Adapter supporting Ollama with deterministic offline fallback."""

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class LocalLLMAdapter:
    """
    Connects to a local Ollama instance when available (zero paid APIs).
    Falls back cleanly to the deterministic local reasoning engine when Ollama
    is not running on the host, while preserving the exact same AgentShield
    gateway enforcement path.
    """

    def __init__(self) -> None:
        self.base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3.2")

    def check_ollama_available(self) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=0.6) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name") for m in data.get("models", [])]
                    return {
                        "ollama_online": True,
                        "base_url": self.base_url,
                        "configured_model": self.model,
                        "available_models": models,
                        "active_mode": "ollama_local_llm",
                    }
        except Exception:
            pass
        return {
            "ollama_online": False,
            "base_url": self.base_url,
            "configured_model": self.model,
            "available_models": [],
            "active_mode": "deterministic_local_planner",
        }

    def generate(
        self,
        prompt: str,
        context: Dict[str, Any],
        tools: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        status = self.check_ollama_available()
        if not status["ollama_online"]:
            return None

        system_prompt = (
            "You are a local AI agent that selects tools from the provided tool registry. "
            "Respond ONLY with valid JSON containing keys: 'thought', 'action' ('tool_call' or 'final_answer'), "
            "'tool' (tool name if tool_call), 'arguments' (object), or 'answer' (string if final_answer)."
        )
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": f"{system_prompt}\nContext: {json.dumps(context)}\nTools: {json.dumps(tools)}\nTask: {prompt}",
                "stream": False,
                "format": "json",
            }
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                response_text = body.get("response", "{}")
                return json.loads(response_text)
        except Exception:
            return None


llm_adapter = LocalLLMAdapter()
