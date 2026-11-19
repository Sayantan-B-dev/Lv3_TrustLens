"""Provider-independent AI layer.

The AI is an *explainer*, never an investigator or a judge. It receives only
deterministic evidence summaries (no raw message body, no page HTML), must
return a strict schema, and may only cite evidence IDs that exist. Any failure
falls back to a deterministic explanation and never changes the risk class.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx

from ..config import Settings


@dataclass
class ProviderResult:
    payload: dict | None
    provider: str
    model: str
    used: bool
    error: str | None = None


class AIProvider:
    name = "base"
    model = ""

    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResult:  # pragma: no cover
        raise NotImplementedError


class MockProvider(AIProvider):
    """Deterministic mock used in tests and explicit demo mode."""

    name = "mock"
    model = "mock-explainer-v1"

    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResult:
        try:
            evidence = json.loads(user_prompt)
            items = evidence.get("evidence", [])
        except (ValueError, AttributeError):
            items = []
        claims = [
            {
                "claim": str(item.get("summary", "Evidence was reviewed."))[:300],
                "evidence_ids": [str(item.get("check_id"))],
            }
            for item in items[:4]
            if item.get("check_id")
        ]
        if not claims:
            claims = [{"claim": "No completed checks were available to explain.", "evidence_ids": ["ai.explanation"]}]
        return ProviderResult(
            payload={
                "summary": "Mock explanation generated from deterministic evidence only.",
                "why": claims,
                "next_steps": ["Verify the domain through an official channel before sharing information."],
                "limitations": ["Mock provider: this is not a live model response."],
                "confidence_note": "Confidence comes from the deterministic evidence coverage.",
            },
            provider=self.name,
            model=self.model,
            used=True,
        )


class OpenAICompatibleProvider(AIProvider):
    name = "openai-compatible"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.model = settings.ai_model

    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResult:
        url = self.settings.ai_base_url.rstrip("/") + "/chat/completions"
        body = {
            "model": self.model,
            "temperature": 0.1,
            "max_tokens": 900,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.settings.ai_api_key}"}
        try:
            with httpx.Client(
                timeout=httpx.Timeout(self.settings.ai_timeout_seconds),
                trust_env=False,
            ) as client:
                response = client.post(url, json=body, headers=headers)
                if response.status_code == 400:
                    body.pop("response_format", None)
                    response = client.post(url, json=body, headers=headers)
            if response.status_code >= 400:
                return ProviderResult(None, self.name, self.model, False, f"AI provider HTTP {response.status_code}")
            data = response.json()
            content = data["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError) as exc:
            return ProviderResult(None, self.name, self.model, False, f"{exc.__class__.__name__}: {str(exc)[:160]}")

        if not isinstance(content, str):
            return ProviderResult(None, self.name, self.model, False, "AI provider returned non-text content")
        cleaned = re.sub(r"^```(?:json)?|```$", "", content.strip(), flags=re.MULTILINE).strip()
        try:
            payload = json.loads(cleaned)
        except ValueError:
            return ProviderResult(None, self.name, self.model, False, "AI provider returned invalid JSON")
        if not isinstance(payload, dict):
            return ProviderResult(None, self.name, self.model, False, "AI provider returned a non-object")
        return ProviderResult(payload, self.name, self.model, True)


def get_provider(settings: Settings) -> AIProvider | None:
    provider = settings.active_ai_provider
    if provider == "mock":
        return MockProvider()
    if provider == "openai":
        return OpenAICompatibleProvider(settings)
    return None
