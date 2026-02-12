# 💰 LLM Token Usage Disclaimer

## Overview

The **binql-ultra-lite** workshop uses Large Language Models (LLMs) to provide a natural-language interface for binary analysis. To use these features, you must provide your own API key for **OpenAI** or **Anthropic**.

## Best Effort Token Efficiency

We make a **best-effort attempt** to be token-friendly and minimize costs for students by:
- Defaulting to cost-effective "mini" or "balanced" models (e.g., `gpt-4o-mini`, `claude-sonnet-4.5`).
- Implementing prompt truncation to prevent runaway token consumption.
- Providing efficient, schema-grounded prompts to reduce redundant reasoning.

## Responsibility for Costs

By participating in this workshop and using your own API keys, you acknowledge and agree to the following:

1.  **Usage Costs:** You are solely responsible for any and all costs, fees, or charges incurred through your OpenAI or Anthropic accounts as a result of running the lab exercises, tests, or examples provided in this workshop.
2.  **No Compensation:** The workshop authors, instructors, and maintainers are not responsible for, and will not provide compensation or reimbursement for, any LLM API usage costs.
3.  **Monitoring Usage:** You are responsible for monitoring your own usage and setting spend limits or alerts within your provider's dashboard (OpenAI Platform or Anthropic Console) to prevent unexpected charges.
4.  **No Guarantee:** While we strive for efficiency, we do not guarantee any specific cost level. Token usage can vary based on the complexity of queries, binary artifacts, and model responses.

## Recommendations

- **Set Spend Limits:** We strongly recommend setting a monthly budget or hard usage limit in your LLM provider's billing settings before starting the workshop.
- **Check Your Balance:** Review your usage dashboard periodically during the labs to understand your consumption patterns.
- **Use Default Models:** Unless you have a specific reason to switch, stick to the default models configured in `lab_common/llm/llm_client_config.yaml` as they are chosen for their cost-to-performance ratio.
