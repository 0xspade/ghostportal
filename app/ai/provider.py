# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
AI Provider abstraction layer.

Supports: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local).

Usage:
    from app.ai.provider import get_provider
    provider = get_provider("anthropic")
    result = await provider.generate(prompt="...", system="...")
"""

import logging
import os
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


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider."""

    def __init__(self):
        from flask import current_app
        self.api_key = current_app.config.get("ANTHROPIC_API_KEY", "")
        self.model = current_app.config.get("ANTHROPIC_MODEL", "claude-opus-4-5")

    async def generate(self, prompt: str, system: str) -> AIResult:
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured")
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text if message.content else ""
        tokens = (message.usage.input_tokens or 0) + (message.usage.output_tokens or 0)
        return AIResult(text=text, tokens_used=tokens, provider="anthropic", model=self.model)


class OpenAIProvider(AIProvider):
    """OpenAI GPT provider."""

    def __init__(self):
        from flask import current_app
        self.api_key = current_app.config.get("OPENAI_API_KEY", "")
        self.model = current_app.config.get("OPENAI_MODEL", "gpt-4o")

    async def generate(self, prompt: str, system: str) -> AIResult:
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not configured")
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=self.api_key)
        resp = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            max_tokens=4096,
        )
        text = resp.choices[0].message.content or ""
        tokens = resp.usage.total_tokens if resp.usage else 0
        return AIResult(text=text, tokens_used=tokens, provider="openai", model=self.model)


class GeminiProvider(AIProvider):
    """Google Gemini provider."""

    def __init__(self):
        from flask import current_app
        self.api_key = current_app.config.get("GEMINI_API_KEY", "")
        self.model = current_app.config.get("GEMINI_MODEL", "gemini-1.5-pro")

    async def generate(self, prompt: str, system: str) -> AIResult:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not configured")
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            model_name=self.model,
            system_instruction=system,
        )
        response = model.generate_content(prompt)
        text = response.text or ""
        tokens = getattr(response.usage_metadata, "total_token_count", 0)
        return AIResult(text=text, tokens_used=tokens, provider="gemini", model=self.model)


class OllamaProvider(AIProvider):
    """Ollama local LLM provider."""

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
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(name: Optional[str] = None) -> AIProvider:
    """
    Get an AI provider instance by name.

    Args:
        name: Provider name (anthropic, openai, gemini, ollama).
              Defaults to AI_DEFAULT_PROVIDER from config.

    Returns:
        AIProvider instance.

    Raises:
        ValueError: If provider name is unknown.
    """
    from flask import current_app
    if name is None:
        name = current_app.config.get("AI_DEFAULT_PROVIDER", "anthropic")

    provider_class = _PROVIDERS.get(name)
    if not provider_class:
        raise ValueError(f"Unknown AI provider: {name}. Valid: {list(_PROVIDERS.keys())}")

    return provider_class()


def get_configured_providers() -> list[str]:
    """
    Return list of AI providers that have API keys configured.

    Returns:
        List of provider name strings.
    """
    from flask import current_app

    configured = []
    checks = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "ollama": None,  # Ollama is always available if URL is set
    }

    for provider, key in checks.items():
        if key is None:
            if current_app.config.get("OLLAMA_BASE_URL"):
                configured.append(provider)
        elif current_app.config.get(key):
            configured.append(provider)

    return configured
