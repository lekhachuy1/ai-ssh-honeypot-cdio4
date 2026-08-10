from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LLMResult:
    text: str
    used_llm: bool


class OllamaClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def simulate_command(self, command: str, context: dict) -> LLMResult:
        if not self.settings.enable_llm:
            return LLMResult(f"bash: {command.split()[0]}: command not found", False)

        system = (
            "You simulate an Ubuntu terminal for a cybersecurity honeypot. "
            "Never explain, never provide markdown, and never claim to execute a real command. "
            "Return only short plausible terminal output. Do not reveal that this is a honeypot. "
            "Do not output real credentials, exploit instructions, or external network results."
        )
        user = (
            f"User: {context.get('username')}\n"
            f"Host: {context.get('hostname')}\n"
            f"Working directory: {context.get('cwd')}\n"
            f"Recent commands: {context.get('history', [])}\n"
            f"New command: {command}\n"
            "Terminal output:"
        )
        try:
            payload = {
                "model": self.settings.ollama_model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 300},
            }
            async with httpx.AsyncClient(timeout=self.settings.ollama_timeout_seconds) as client:
                response = await client.post(
                    f"{self.settings.ollama_base_url.rstrip('/')}/api/chat", json=payload
                )
                response.raise_for_status()
                data = response.json()
            text = str(data.get("message", {}).get("content", "")).strip()
            if not text:
                raise ValueError("Ollama returned an empty response")
            return LLMResult(text[: self.settings.max_response_length], True)
        except Exception as exc:  # graceful fallback is intentional for lab reliability
            logger.warning("Ollama command simulation failed: %s", exc)
            return LLMResult(f"bash: {command.split()[0]}: command not found", False)

    async def summarize_session(self, commands: list[str], heuristic_summary: str) -> str:
        if not self.settings.enable_llm or not commands:
            return heuristic_summary

        prompt = (
            "Analyze this SSH honeypot command history. Return Vietnamese JSON with keys "
            '"classification", "intent", and "summary". Keep it defensive and concise.\n'
            + json.dumps(commands[-30:], ensure_ascii=False)
        )
        try:
            payload = {
                "model": self.settings.ollama_model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": 350},
            }
            async with httpx.AsyncClient(timeout=self.settings.ollama_timeout_seconds) as client:
                response = await client.post(
                    f"{self.settings.ollama_base_url.rstrip('/')}/api/chat", json=payload
                )
                response.raise_for_status()
                data = response.json()
            content = str(data.get("message", {}).get("content", "")).strip()
            parsed = json.loads(content)
            summary = str(parsed.get("summary", "")).strip()
            intent = str(parsed.get("intent", "")).strip()
            return f"{summary} Ý định có thể: {intent}".strip()[:2000] or heuristic_summary
        except Exception as exc:
            logger.warning("Ollama session summary failed: %s", exc)
            return heuristic_summary
