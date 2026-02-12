import os
from dataclasses import dataclass
from typing import Optional

import tiktoken
from omegaconf import OmegaConf

from lab_common.common import ROOT_PROJECT_FOLDER_PATH


MAX_TOKEN_LENGTH = 12000

# Default models per provider
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5-20250929"


@dataclass
class LLMClientConfig:
    model: Optional[str] = None
    provider: Optional[str] = None  # "openai", "anthropic", or None (auto-detect)
    api_key: Optional[str] = None
    system_prompt: str = "You are a helpful assistant."
    temperature: float = 0.7
    max_tokens: int = 256
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: Optional[float] = 120.0  # Request timeout in seconds (None = no timeout)

@dataclass
class LLMContext:
    """
    Data class to hold the response and token information from the Large Language Model (LLM).

    Attributes:
        response (str): The response text from the LLM.
        completion_tokens (int): The number of tokens in the completion.
        prompt_tokens (int): The number of tokens in the prompt.
        total_tokens (int): The total number of tokens used.
    """
    response: str
    completion_tokens: int
    prompt_tokens: int
    total_tokens: int

    def __str__(self):
        top_bottom_border = "=" * 100
        middle_border = "-" * 100
        return (f"\n{top_bottom_border}\n"
                f"{'RESPONSE:'.center(100)}\n"
                f"{middle_border}\n"
                f"{self.response.center(100)}\n"
                f"{middle_border}\n\n"
                f"Completion tokens: {self.completion_tokens}\n"
                f"Prompt tokens: {self.prompt_tokens}\n"
                f"Total tokens: {self.total_tokens}\n"
                f"{top_bottom_border}\n")


def _resolve_provider_and_model(
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> tuple:
    """
    Resolve the provider and model based on explicit settings and available API keys.

    Priority:
    1. If provider is explicitly set, use it (and pick default model if model is None).
    2. If model is explicitly set, infer provider from model name.
    3. Auto-detect from available API keys:
       - If only ANTHROPIC_API_KEY is set → anthropic + claude-sonnet-4-20250514
       - If only OPENAI_API_KEY is set → openai + gpt-4o-mini
       - If both are set → anthropic (preferred), unless provider is explicitly "openai"
       - If neither is set → openai + gpt-4o-mini (will fail at client init with clear error)

    Returns:
        (provider, model) tuple
    """
    has_anthropic_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_openai_key = bool(os.environ.get("OPENAI_API_KEY"))

    # Case 1: provider explicitly set
    if provider:
        provider = provider.lower()
        if model is None:
            if provider == "anthropic":
                model = DEFAULT_ANTHROPIC_MODEL
            else:
                model = DEFAULT_OPENAI_MODEL
        return provider, model

    # Case 2: model explicitly set — infer provider
    if model:
        if model.startswith("claude"):
            return "anthropic", model
        else:
            return "openai", model

    # Case 3: auto-detect from API keys
    if has_anthropic_key and has_openai_key:
        # Both available — default to anthropic
        return "anthropic", DEFAULT_ANTHROPIC_MODEL
    elif has_anthropic_key:
        return "anthropic", DEFAULT_ANTHROPIC_MODEL
    elif has_openai_key:
        return "openai", DEFAULT_OPENAI_MODEL
    else:
        # Neither key set — default to openai (will fail with clear error at client init)
        return "openai", DEFAULT_OPENAI_MODEL


def get_llm_client_config() -> LLMClientConfig:
    """
    Load the LLM client configuration from a YAML file.

    If model and provider are null in the YAML, they are auto-detected based on
    available API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY). See _resolve_provider_and_model().
    """
    config_path = os.path.join(ROOT_PROJECT_FOLDER_PATH, "lab_common","llm", "llm_client_config.yaml")

    cfg = OmegaConf.load(config_path)
    cfg = OmegaConf.to_container(cfg, resolve=True)
    config = LLMClientConfig(**cfg[LLMClientConfig.__name__])

    # Resolve provider and model if not explicitly set
    resolved_provider, resolved_model = _resolve_provider_and_model(
        provider=config.provider,
        model=config.model,
    )
    config.provider = resolved_provider
    config.model = resolved_model

    return config


def num_tokens_from_string(string: str) -> int:

    model_name = get_llm_client_config().model
    try:
        encoding = tiktoken.encoding_for_model(model_name)
    except KeyError:
        # Fallback for models not in tiktoken's registry (e.g., Claude)
        encoding = tiktoken.get_encoding("cl100k_base")
    num_tokens = len(encoding.encode(string))
    return num_tokens
