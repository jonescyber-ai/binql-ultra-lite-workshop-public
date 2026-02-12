"""
LLM client module for interacting with OpenAI and Anthropic chat completion APIs.

This module provides an LLMClient class that supports multiple instances with different
configurations, plus a convenience function for generating completions.

Multiple instances allow using different models simultaneously (e.g., gpt-4o-mini for
student evaluation and claude-sonnet-4-5-20250929 for instructor/teacher runs). A default
singleton instance is available via `get_default()` for backward compatibility with code
that expects a single shared client.

The client supports OpenAI and Anthropic (Claude):
    # Use OpenAI (default for gpt-* models)
    client = LLMClient()

    # Use Claude (auto-detected from model name)
    client = LLMClient(config=LLMClientConfig(model="claude-sonnet-4-5-20250929"))
"""

import argparse
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

import tiktoken
from openai import OpenAI

try:
    import anthropic as _anthropic_module
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

from lab_common.llm.llm_common import LLMClientConfig, LLMContext, get_llm_client_config

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)

# Default max tokens for chat completion prompts
# Most models support at least 4096 tokens, using conservative default
DEFAULT_COMPLETION_MAX_TOKENS = 4000


def _is_claude_model(model: str) -> bool:
    """Check if a model name refers to an Anthropic Claude model."""
    return model.startswith("claude")


class LLMClient:
    """
    Client for interacting with OpenAI or Anthropic (Claude) APIs.

    Supports multiple instances with different configurations. Each instance can be
    configured with a different model, temperature, and other parameters. This enables
    workflows that require different models (e.g., gpt-4o-mini for one task and
    claude-sonnet-4-5-20250929 for another).

    The client can operate in two modes:
    - OpenAI mode (default for gpt-* models): Uses OpenAI's API for completions
    - Anthropic mode (auto-detected for claude-* models): Uses Anthropic's API

    The provider is auto-detected from the model name:
    - Models starting with "claude" use the Anthropic API
    - All other models use the OpenAI API

    For backward compatibility, a default singleton instance is available via
    `LLMClient.get_default()` and the module-level convenience functions.

    Attributes:
        client: OpenAI or Anthropic API client instance.
        config: LLM client configuration containing model parameters and settings.
        _provider: The detected provider ('openai' or 'anthropic').

    Example:
        # Create OpenAI client
        mini_client = LLMClient(config=LLMClientConfig(model="gpt-4o-mini"))

        # Create Claude client (auto-detected from model name)
        claude_client = LLMClient(config=LLMClientConfig(model="claude-sonnet-4-5-20250929"))

        # Force a specific provider when both API keys are available
        openai_client = LLMClient(provider="openai")
        anthropic_client = LLMClient(provider="anthropic")

        # Use the default singleton (backward compatible)
        default_client = LLMClient.get_default()
    """

    _default_instance: Optional["LLMClient"] = None

    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[LLMClientConfig] = None,
        provider: Optional[str] = None,
    ) -> None:
        """
        Initialize the LLMClient with API credentials and configuration.

        Args:
            api_key: API key for OpenAI or Anthropic. If None, attempts to load from config
                    or the appropriate environment variable (OPENAI_API_KEY or ANTHROPIC_API_KEY).
            config: LLM client configuration. If None, loads from default YAML configuration file.
            provider: Explicitly select the provider ("openai" or "anthropic"). Overrides
                     auto-detection from model name and API keys. Useful when both API keys
                     are available and you want to force a specific provider.

        Raises:
            ValueError: If no API key is provided and the appropriate environment variable is not set.
            ImportError: If the anthropic package is not installed and a Claude model is configured.
        """
        self.client = None
        self._provider = "openai"

        self.config = config if config else get_llm_client_config()

        # Apply explicit provider override if given
        if provider:
            from lab_common.llm.llm_common import _resolve_provider_and_model
            # If the user explicitly chose a provider but the config model
            # belongs to a different provider, reset model to let
            # _resolve_provider_and_model pick the default for the requested provider.
            current_model = self.config.model
            if provider == "openai" and current_model and current_model.startswith("claude"):
                current_model = None
            elif provider == "anthropic" and current_model and not current_model.startswith("claude"):
                current_model = None
            resolved_provider, resolved_model = _resolve_provider_and_model(
                provider=provider, model=current_model
            )
            self.config.provider = resolved_provider
            self.config.model = resolved_model

        if _is_claude_model(self.config.model):
            # Anthropic (Claude) mode
            self._provider = "anthropic"
            if not _HAS_ANTHROPIC:
                raise ImportError(
                    "The 'anthropic' package is required for Claude models. "
                    "Install it with: pip install anthropic"
                )

            resolved_api_key = api_key or self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")
            if resolved_api_key is None:
                raise ValueError(
                    "Anthropic API key not found. Provide via api_key parameter, "
                    "configuration file, or ANTHROPIC_API_KEY environment variable."
                )

            client_kwargs = {"api_key": resolved_api_key}
            if self.config.timeout is not None:
                client_kwargs["timeout"] = self.config.timeout

            self.client = _anthropic_module.Anthropic(**client_kwargs)
            logger.debug(
                "LLMClient initialized with Anthropic model: %s, timeout: %s",
                self.config.model,
                self.config.timeout,
            )
        else:
            # OpenAI mode
            self._provider = "openai"

            resolved_api_key = api_key or self.config.api_key or os.environ.get("OPENAI_API_KEY")
            if resolved_api_key is None:
                raise ValueError(
                    "OpenAI API key not found. Provide via api_key parameter, "
                    "configuration file, or OPENAI_API_KEY environment variable."
                )

            client_kwargs = {"api_key": resolved_api_key}
            if self.config.timeout is not None:
                client_kwargs["timeout"] = self.config.timeout

            self.client = OpenAI(**client_kwargs)
            logger.debug(
                "LLMClient initialized with OpenAI model: %s, timeout: %s",
                self.config.model,
                self.config.timeout,
            )

    @classmethod
    def get_default(
        cls,
        api_key: Optional[str] = None,
        config: Optional[LLMClientConfig] = None,
        provider: Optional[str] = None,
    ) -> "LLMClient":
        """
        Get the default singleton instance, creating it if necessary.

        This method provides backward compatibility for code that expects a single
        shared LLMClient instance. The default instance is lazily initialized on
        first call.

        Args:
            api_key: API key (only used if creating a new default instance).
            config: LLM client configuration (only used if creating a new default instance).
            provider: Explicitly select the provider ("openai" or "anthropic").

        Returns:
            The default singleton LLMClient instance.

        Note:
            If the default instance already exists, the parameters are ignored.
            Use `reset_default()` first if you need to reconfigure.
        """
        if cls._default_instance is None:
            cls._default_instance = cls(api_key=api_key, config=config, provider=provider)
        return cls._default_instance

    @classmethod
    def reset_default(cls) -> None:
        """
        Reset the default singleton instance.

        This is useful for testing or when you need to reconfigure the default client.
        After calling this method, the next call to `get_default()` will create a
        new instance with fresh configuration.
        """
        cls._default_instance = None
        logger.debug("Default LLMClient instance reset")

    def complete(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        system_prompt: Optional[str] = None,
        max_prompt_tokens: Optional[int] = None,
        truncate: bool = False,
    ) -> LLMContext:
        """
        Generate a completion response from the configured backend (OpenAI or Anthropic).

        Args:
            prompt: Either a string prompt or a list of message dictionaries with 'role' and 'content' keys.
            system_prompt: Optional system prompt to override the default from configuration.
                          Only used when prompt is a string.
            max_prompt_tokens: Optional maximum token count for the prompt. If specified and exceeded,
                              behavior depends on truncate flag. If None, no truncation is performed.
            truncate: Whether to truncate prompt that exceeds max_prompt_tokens. Only applies when
                     max_prompt_tokens is specified. If False, raises ValueError for oversized prompts.

        Returns:
            LLMContext containing the response text and token usage statistics.

        Raises:
            TypeError: If prompt is neither a string nor a list of message dictionaries.
            ValueError: If max_prompt_tokens is exceeded and truncate is False.
        """
        if self._provider == "anthropic":
            return self._complete_anthropic(prompt, system_prompt, max_prompt_tokens, truncate)
        else:
            return self._complete_openai(prompt, system_prompt, max_prompt_tokens, truncate)

    def _complete_anthropic(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        system_prompt: Optional[str] = None,
        max_prompt_tokens: Optional[int] = None,
        truncate: bool = False,
    ) -> LLMContext:
        """
        Generate a completion using Anthropic's Messages API.

        Args:
            prompt: Either a string prompt or a list of message dictionaries.
            system_prompt: Optional system prompt to override the default.
            max_prompt_tokens: Optional maximum token count for the prompt.
            truncate: Whether to truncate prompt that exceeds max_prompt_tokens.

        Returns:
            LLMContext containing the response text and token usage statistics.
        """
        messages = self._build_messages(prompt, system_prompt)

        # Apply token truncation if requested
        if max_prompt_tokens is not None:
            messages = self._truncate_messages(messages, max_prompt_tokens, truncate)

        # Anthropic uses a separate system parameter instead of a system message
        anthropic_system = None
        anthropic_messages = []
        for msg in messages:
            if msg["role"] == "system":
                anthropic_system = msg["content"]
            else:
                anthropic_messages.append(msg)

        logger.debug(
            "Sending completion request to Anthropic with model=%s, messages=%d",
            self.config.model,
            len(anthropic_messages),
        )

        request_params = {
            "model": self.config.model,
            "messages": anthropic_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }
        if anthropic_system:
            request_params["system"] = anthropic_system

        # Use streaming to avoid network idle timeouts on long requests
        # (see https://docs.anthropic.com/en/api/errors#long-requests)
        with self.client.messages.stream(**request_params) as stream:
            response = stream.get_final_message()

        response_content = response.content[0].text.strip()
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

        logger.debug(
            "Anthropic completion received: tokens=%d (input=%d, output=%d)",
            input_tokens + output_tokens,
            input_tokens,
            output_tokens,
        )

        return LLMContext(
            response=response_content,
            completion_tokens=output_tokens,
            prompt_tokens=input_tokens,
            total_tokens=input_tokens + output_tokens,
        )

    def _complete_openai(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        system_prompt: Optional[str] = None,
        max_prompt_tokens: Optional[int] = None,
        truncate: bool = False,
    ) -> LLMContext:
        """
        Generate a completion using OpenAI's API.

        Args:
            prompt: Either a string prompt or a list of message dictionaries.
            system_prompt: Optional system prompt to override the default.
            max_prompt_tokens: Optional maximum token count for the prompt.
            truncate: Whether to truncate prompt that exceeds max_prompt_tokens.

        Returns:
            LLMContext containing the response text and token usage statistics.
        """
        messages = self._build_messages(prompt, system_prompt)

        # Apply token truncation if requested
        if max_prompt_tokens is not None:
            messages = self._truncate_messages(messages, max_prompt_tokens, truncate)

        logger.debug(
            "Sending completion request with model=%s, messages=%d",
            self.config.model,
            len(messages),
        )

        # Build request parameters based on model type
        request_params = {
            "model": self.config.model,
            "messages": messages,
        }

        # Check if this is an o1-series or GPT-5 model
        is_o1_or_gpt5 = self.config.model.startswith("o1") or "gpt-5" in self.config.model

        if is_o1_or_gpt5:
            # o1 and GPT-5 models use different parameter names and don't support all parameters
            request_params["max_completion_tokens"] = self.config.max_tokens
        else:
            # Standard GPT-4 and earlier models
            request_params["max_tokens"] = self.config.max_tokens
            request_params["temperature"] = self.config.temperature
            request_params["top_p"] = self.config.top_p
            request_params["frequency_penalty"] = self.config.frequency_penalty
            request_params["presence_penalty"] = self.config.presence_penalty

        response = self.client.chat.completions.create(**request_params)

        response_content = response.choices[0].message.content.strip()
        token_usage = response.usage

        logger.debug(
            "Completion received: tokens=%d (prompt=%d, completion=%d)",
            token_usage.total_tokens,
            token_usage.prompt_tokens,
            token_usage.completion_tokens,
        )

        return LLMContext(
            response=response_content,
            completion_tokens=token_usage.completion_tokens,
            prompt_tokens=token_usage.prompt_tokens,
            total_tokens=token_usage.total_tokens,
        )

    def _build_messages(
        self,
        prompt: Union[str, List[Dict[str, str]]],
        system_prompt: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """
        Build the messages list for the chat completion API.

        Args:
            prompt: Either a string prompt or a list of message dictionaries.
            system_prompt: Optional system prompt to use instead of the default.

        Returns:
            List of message dictionaries with 'role' and 'content' keys.

        Raises:
            TypeError: If prompt is neither a string nor a list.
        """
        if isinstance(prompt, str):
            effective_system_prompt = system_prompt if system_prompt is not None else self.config.system_prompt
            return [
                {"role": "system", "content": effective_system_prompt},
                {"role": "user", "content": prompt},
            ]
        elif isinstance(prompt, list):
            return prompt
        else:
            raise TypeError(
                f"Prompt must be a string or a list of message dictionaries, got {type(prompt).__name__}"
            )

    def _truncate_messages(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int,
        truncate: bool,
    ) -> List[Dict[str, str]]:
        """
        Truncate messages to fit within token limit.

        Truncates the last user message to stay within the token budget while preserving
        system messages and conversation structure.

        Args:
            messages: List of message dictionaries to potentially truncate
            max_tokens: Maximum token count for all messages
            truncate: Whether to truncate or raise error if limit exceeded

        Returns:
            List of messages, potentially with the last user message truncated

        Raises:
            ValueError: If max_tokens is exceeded and truncate is False
        """
        # Get tokenizer for the model
        try:
            encoding = tiktoken.encoding_for_model(self.config.model)
        except KeyError:
            # Fallback to cl100k_base encoding (used by most modern models)
            encoding = tiktoken.get_encoding("cl100k_base")

        # Count total tokens across all messages
        total_tokens = 0
        message_tokens = []
        for message in messages:
            content = message.get("content", "")
            tokens = encoding.encode(content)
            message_tokens.append(tokens)
            total_tokens += len(tokens)

        # Check if truncation is needed
        if total_tokens <= max_tokens:
            return messages

        if not truncate:
            raise ValueError(
                f"Prompt token count ({total_tokens}) exceeds maximum ({max_tokens}). "
                "Set truncate=True to automatically truncate."
            )

        # Truncate the last user message to fit within budget
        logger.warning(
            "Prompt truncated from %d to %d tokens for completion",
            total_tokens,
            max_tokens,
        )

        # Calculate how many tokens we need to remove
        tokens_to_remove = total_tokens - max_tokens

        # Find the last user message to truncate
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") == "user":
                user_tokens = message_tokens[i]
                if len(user_tokens) > tokens_to_remove:
                    # Truncate this message
                    truncated_tokens = user_tokens[: len(user_tokens) - tokens_to_remove]
                    truncated_content = encoding.decode(truncated_tokens)
                    messages[i]["content"] = truncated_content
                    break

        return messages


# =============================================================================
# Module-level convenience functions (use default singleton instance)
# =============================================================================


def llm_completion(
    prompt: Union[str, List[Dict[str, str]]],
    system_prompt: Optional[str] = None,
    max_prompt_tokens: Optional[int] = None,
    truncate: bool = False,
) -> LLMContext:
    """
    Generate a completion using the default singleton LLMClient instance.

    This is a convenience function that uses `LLMClient.get_default()` to obtain a shared
    client instance. For workflows requiring multiple models, instantiate LLMClient directly
    with different configurations.

    Args:
        prompt: Either a string prompt or a list of message dictionaries with 'role' and 'content' keys.
        system_prompt: Optional system prompt to override the default from configuration.
        max_prompt_tokens: Optional maximum token count for the prompt. If specified and exceeded,
                          behavior depends on truncate flag.
        truncate: Whether to truncate prompt that exceeds max_prompt_tokens. Defaults to False.

    Returns:
        LLMContext containing the response text and token usage statistics.

    Raises:
        ValueError: If API key is not configured or max_prompt_tokens exceeded with truncate=False.
        TypeError: If prompt format is invalid.

    Example:
        >>> response = llm_completion("What is the capital of France?")
    """
    return LLMClient.get_default().complete(prompt, system_prompt, max_prompt_tokens, truncate)


def main() -> None:
    """
    Command-line interface for testing LLM completions.

    Accepts an optional --prompt argument to send a custom prompt, or runs example queries.
    """
    parser = argparse.ArgumentParser(
        description="LLM Completion Script - Test OpenAI or Anthropic completions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--prompt",
        type=str,
        help="Prompt string to send to the LLM",
    )
    args = parser.parse_args()

    # Log which provider and model are being used
    client = LLMClient.get_default()
    logger.info("Provider: %s | Model: %s", client._provider, client.config.model)

    if args.prompt:
        logger.info("Processing custom prompt")
        response = llm_completion(args.prompt)
        print("Assistant:", response.response)
        print(f"Tokens used: {response.total_tokens} (prompt: {response.prompt_tokens}, "
              f"completion: {response.completion_tokens})")
    else:
        logger.info("Running example completions")

        # Example 1: Using a simple string prompt
        print("=" * 80)
        print("Example 1: Simple string prompt")
        print("=" * 80)
        response = llm_completion("What is the capital of France?")
        print("Assistant:", response.response)
        print(f"Tokens: {response.total_tokens}\n")

        # Example 2: Using a list of message dictionaries
        print("=" * 80)
        print("Example 2: Multi-turn conversation")
        print("=" * 80)
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Can you explain the theory of relativity in one sentence?"},
        ]
        response = llm_completion(messages)
        print("Assistant:", response.response)
        print(f"Tokens: {response.total_tokens}\n")


if __name__ == "__main__":
    module_name = Path(__file__).stem

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Override the logger to use the file name
    logger = logging.getLogger(module_name)

    main()
