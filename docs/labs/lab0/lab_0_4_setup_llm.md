# 🔹 Lab 0.4 — LLM Client Setup and Validation

> 🔧 **This is a tool-running lab.** You will configure an API key and verify that the LLM client works.
>
> 🔑 **Bring Your Own API Key** — No API key is provided with this workshop. You must supply your own key for **OpenAI** ([get one here](https://platform.openai.com/api-keys)) or **Anthropic** ([get one here](https://console.anthropic.com/settings/keys)). You need at least one to proceed.
>
> 💰 **Disclaimer:** You are responsible for all API costs incurred. By using the materials in this workshop, you agree to the terms described in the [LLM Token Usage Disclaimer](../../token_usage_disclaimer.md).

---

## Overview

- **Goal:** Configure the LLM client so the workshop labs can call an LLM for natural-language reasoning.
- **Inputs:** A valid OpenAI or Anthropic API key.
- **Outputs:** A working `python -m lab_common.llm.client` run that returns a completion.

---

## 🎯 What You Need To Do

### Step 1: Obtain an API key

You need **at least one** of the following:

| Provider | Where to get a key |
|---|---|
| **OpenAI** | <https://platform.openai.com/api-keys> |
| **Anthropic** | <https://console.anthropic.com/settings/keys> |

### Step 2: Add your key and provider to the config file

Open the configuration file:

```
lab_common/llm/llm_client_config.yaml
```

Edit the two fields at the top of the `LLMClientConfig` section:

1. **`provider`** — set to `"openai"` or `"anthropic"` (case-insensitive).
2. **`api_key`** — paste your API key.

For example, if you are using Anthropic:

```yaml
LLMClientConfig:
  provider: "anthropic"
  api_key: "sk-ant-..."
  model: null
  # ... rest of the defaults ...
```

Or if you are using OpenAI:

```yaml
LLMClientConfig:
  provider: "openai"
  api_key: "sk-..."
  model: null
  # ... rest of the defaults ...
```

Leave `model` as `null` to use the default model for your provider:

| Provider | Default model |
|---|---|
| OpenAI | `gpt-4o-mini` |
| Anthropic | `claude-sonnet-4-5-20250929` |

<details>
<summary>ℹ️ <strong>Alternative — environment variables</strong> (click to expand)</summary>

Instead of putting the key in the YAML file, you can export it as an environment variable and leave `api_key` as `null`:

```bash
# Linux/macOS — pick one:
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

```powershell
# Windows (PowerShell) — pick one:
$env:OPENAI_API_KEY = "sk-..."
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

To make it permanent, add the export to `~/.bashrc` / `~/.zshrc` (Linux/macOS) or set it via **System → Advanced → Environment Variables** (Windows).

> ℹ️ **Auto-detection:** If `provider` is also left as `null` in the YAML file, the client will automatically detect the provider based on whichever API key environment variable is set (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`). So you only need to set the environment variable for your key — no need to configure `provider` at all.

</details>

### Step 3: Test the LLM client

With your virtual environment activated, run the client test from the project root:

#### Linux/macOS

```bash
source venv/bin/activate
python -m lab_common.llm.client
```

#### Windows (PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
python -m lab_common.llm.client
```

You should see output similar to:

```
================================================================================
Example 1: Simple string prompt
================================================================================
Assistant: The capital of France is Paris.
Tokens: 25

================================================================================
Example 2: Multi-turn conversation
================================================================================
Assistant: The theory of relativity ...
Tokens: 42
```

You can also send a custom prompt:

```bash
python -m lab_common.llm.client --prompt "What is 2 + 2?"
```

---

## ✅ Success Criteria

You're done when:
- [ ] `provider` and `api_key` are set in `llm_client_config.yaml` (or the equivalent environment variable is exported)
- [ ] `python -m lab_common.llm.client` runs without errors and returns LLM completions
- [ ] Token counts are displayed for each response

---

## Summary

The LLM client is configured and working. Proceed to Lab 1.
