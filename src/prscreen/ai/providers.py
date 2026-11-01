"""Model providers. Each one turns (system prompt, user message, JSON schema) into a JSON string.

Providers are deliberately dumb: they never see findings as objects and cannot change them. All
checking of what comes back happens in :mod:`prscreen.ai.validate`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

TIMEOUT_SECONDS = 180


class ProviderError(RuntimeError):
    pass


class Provider(ABC):
    name: str
    model: str

    @abstractmethod
    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str: ...


class ClaudeProvider(Provider):
    """Claude through the official ``anthropic`` SDK (install with ``pip install prscreen[claude]``).

    Credentials come from the SDK's usual sources (``ANTHROPIC_API_KEY``, ``ant auth login``).
    Structured outputs constrain the reply to the schema. Server-side fallbacks let the API retry
    on another model if this one declines a request about security-sensitive code.
    """

    name = "claude"
    DEFAULT_MODEL = "claude-opus-5-5"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or self.DEFAULT_MODEL

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderError("the Claude provider needs the SDK: pip install 'prscreen[claude]'") from exc
        client = anthropic.Anthropic(timeout=TIMEOUT_SECONDS, max_retries=2)
        try:
            response = client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"format": {"type": "json_schema", "schema": schema}, "effort": "medium"},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.AuthenticationError as exc:
            raise ProviderError("Claude rejected the credentials; set ANTHROPIC_API_KEY") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Claude API error {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("could not reach the Claude API") from exc
        if response.stop_reason == "refusal":
            raise ProviderError("the model declined to review this diff")
        if response.stop_reason == "max_tokens":
            raise ProviderError("the model's answer was cut off")
        text = next((block.text for block in response.content if block.type == "text"), None)
        if text is None:
            raise ProviderError("the model returned no text")
        return str(text)


class OllamaProvider(Provider):
    """A local model through Ollama's HTTP API: free, private, and weaker than a frontier model.

    The host comes from ``OLLAMA_HOST`` (default ``http://127.0.0.1:11434``). The JSON schema is
    passed as Ollama's ``format`` so the reply is constrained to it.
    """

    name = "ollama"
    DEFAULT_MODEL = "qwen2.5-coder:7b"

    def __init__(self, model: str | None = None, host: str | None = None) -> None:
        self.model = model or self.DEFAULT_MODEL
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        if "://" not in self.host:
            self.host = "http://" + self.host
        if urlsplit(self.host).scheme not in ("http", "https"):
            raise ProviderError(f"OLLAMA_HOST must be an http(s) URL, not {self.host!r}")

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "format": schema,
                "stream": False,
                "options": {"temperature": 0},
            }
        ).encode()
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            f"{self.host}/api/chat", data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
                reply = json.loads(response.read())
        except urllib.error.URLError as exc:
            raise ProviderError(f"could not reach Ollama at {self.host}: {exc.reason}") from exc
        except (TimeoutError, json.JSONDecodeError) as exc:
            raise ProviderError(f"bad response from Ollama: {exc}") from exc
        content = reply.get("message", {}).get("content") if isinstance(reply, dict) else None
        if not isinstance(content, str):
            raise ProviderError("Ollama returned no message content")
        return content


class FakeProvider(Provider):
    """Returns a canned reply. Used by tests and to demonstrate the AI layer offline."""

    name = "fake"

    def __init__(self, reply: str | Callable[[str, str], str], model: str = "fake-model") -> None:
        self.reply = reply
        self.model = model
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        self.calls.append((system, user))
        return self.reply(system, user) if callable(self.reply) else self.reply


def get_provider(name: str, model: str | None = None) -> Provider:
    if name == "claude":
        return ClaudeProvider(model)
    if name == "ollama":
        return OllamaProvider(model)
    raise ProviderError(f"unknown AI provider {name!r}; use claude or ollama")
