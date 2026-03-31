# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
AI Provider abstraction layer.

Supports: Ollama (self-hosted local LLM only).

Usage:
    from app.ai.provider import get_provider
    provider = get_provider()
    result = await provider.generate(prompt="...", system="...")
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AIResult:
    """Result from an AI generation call."""
    text: str
    tokens_used: int
    provider: str
    model: str


class AIProvider(ABC):
    """Abstract base class for all AI providers."""

    @abstractmethod
    async def generate(self, prompt: str, system: str) -> AIResult:
        """Generate text from a prompt."""
        pass


class OllamaProvider(AIProvider):
    """Ollama self-hosted local LLM provider."""

    def __init__(self):
        from flask import current_app
        self.base_url = current_app.config.get("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = current_app.config.get("OLLAMA_MODEL", "llama3.1")

    async def generate(self, prompt: str, system: str) -> AIResult:
        from app.utils.safe_fetch import safe_fetch
        resp = safe_fetch(
            f"{self.base_url}/api/generate",
            method="POST",
            json={
                "model": self.model,
                "prompt": f"{system}\n\n{prompt}",
                "stream": False,
            },
            timeout=(10, 120),
        )
        resp.raise_for_status()
        data = resp.json()
        text = data.get("response", "")
        tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
        return AIResult(text=text, tokens_used=tokens, provider="ollama", model=self.model)


_PROVIDERS = {
    "ollama": OllamaProvider,
}


def get_provider(name: Optional[str] = None) -> AIProvider:
    """
    Get an AI provider instance by name.

    Args:
        name: Provider name. Only "ollama" is supported.
              Defaults to AI_DEFAULT_PROVIDER from config (must be "ollama").

    Returns:
        OllamaProvider instance.

    Raises:
        ValueError: If provider name is unknown.
    """
    from flask import current_app
    if name is None:
        name = current_app.config.get("AI_DEFAULT_PROVIDER", "ollama")

    # Only Ollama is supported — reject any other provider name gracefully
    if name != "ollama":
        logger.warning("AI provider '%s' is not supported; falling back to ollama.", name)
        name = "ollama"

    provider_class = _PROVIDERS.get(name)
    if not provider_class:
        raise ValueError(f"Unknown AI provider: {name}. Only 'ollama' is supported.")

    return provider_class()


def get_configured_providers() -> list[str]:
    """
    Return list of configured AI providers (only Ollama is supported).

    Returns:
        ["ollama"] if OLLAMA_BASE_URL is set, else [].
    """
    from flask import current_app
    if current_app.config.get("OLLAMA_BASE_URL"):
        return ["ollama"]
    return []
