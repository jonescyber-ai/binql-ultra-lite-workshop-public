# binql-ultra-lite: Asking Questions About Software in Natural Language

> **What if you — or an agent in your workflow — could ask plain-English questions about binaries (i.e., compiled software), malware, or vulnerabilities — and receive precise, evidence-backed answers?**

That's the idea behind **binql-ultra-lite** (`binql-ul`): a hands-on workshop where you build a system that combines **graphs**, **large language models (LLMs)**, and **program analysis** to answer questions about binaries — without writing complex query syntax.

While reverse engineering is our concrete application, the core pattern (**graph-grounded security analysis + natural-language querying / NL2GQL**) generalizes across cybersecurity domains (cloud/IAM graphs, incident correlation, attack paths, supply chain, and more).

<table><tr><td>📌 <sub><em>binql-ultra-lite</em> is the workshop edition of <b>binql</b>. A richer <em>binql-lite</em> powers our 4-day courses (<a href="https://recon.cx/2026/en/trainingAutomatingREwithAIML.html">upcoming: Automating Reverse Engineering with AI/ML, Graphs, and LLM Agents — RECON 2026</a> · <a href="docs/syllabus/syllabus_4day_course.md">4-day course syllabus</a>); a full open-source release is planned after the current training cycle (2026). See <em>Additional Reading</em> → <em>"Versions of binql"</em></sub></td></tr></table>

---

## ⭐ Start Here

Go to **Lab 0 — Environment Setup** to validate your environment and credentials:
- [docs/labs/lab0/lab_0_0_overview.md](docs/labs/lab0/lab_0_0_overview.md)

If you're reading this asynchronously, completing Lab 0 is the fastest way to get oriented.

---

## ✅ No Prior Experience Required

This workshop is designed to be accessible to a wide audience:

- **New to graphs?** Lab 1 introduces nodes, relationships, properties, and basic queries from scratch.
- **New to LLMs?** Lab 2 shows how NL2GQL works and how to make it reliable (grounding + validation).
- **New to reverse engineering?** We use pre-processed binaries (**BCC** files; precomputed analysis artifacts) so you can focus on analysis instead of tool setup.

**Not an RE specialist?** That’s totally fine.
- We use reverse engineering as a **concrete, hands-on application** of a broader idea: **graph-grounded security analysis + natural-language querying (NL2GQL)**.
- The same pattern generalizes to other security domains (IAM graphs, attack paths, incident correlation, supply chain, etc.).

If you can run Python and follow step-by-step lab instructions, you can complete the workshop.

---

## 💡 The Idea

Programs are naturally **graph-structured** — functions call other functions, basic blocks branch to other blocks, binaries import shared libraries. When you load these structures into a graph database like Neo4j, questions like *"Which functions call `strcpy`?"* or *"Do any binaries share a vulnerable library?"* become straightforward queries.

The catch is that writing those queries by hand — in a language called **Cypher** — requires expertise and doesn't scale. Every new question means crafting new syntax. That's where **LLMs** come in: instead of writing Cypher yourself, you — or an agent in your workflow — ask your question in plain English, and the system translates it into a graph query automatically. The graph ensures the answer is grounded in real program structure, not hallucinated.

```
1. EXTRACT          2. QUERY               3. ANSWER
   Binary code  →      Graph database  →      Natural language
   (Ghidra)            (Neo4j)                (LLM + NL2GQL)
```

**Workshop note:** we use pre-processed **BCC** artifacts so you can focus on graph querying and NL2GQL without needing to run extraction tooling during the workshop.

> **Structure first, then automate.** Organize program facts into a graph, then let LLMs handle the query syntax so you can focus on analysis.
>
> 🌐 **This pattern extends beyond reverse engineering.** The same approach — graph-grounded analysis + natural-language querying — applies wherever cybersecurity questions involve structured relationships.
>
> | Domain | Graph Structure | Example Question |
> |--------|----------------|------------------|
> | 🔍 **Threat Intelligence** | Attack graphs, kill chains | *"Which threat actors target this sector via phishing?"* |
> | 🌐 **Network Security** | Host/flow graphs | *"What lateral movement paths exist from the DMZ?"* |
> | ☁️ **Cloud Security** | Infrastructure dependency graphs | *"Which services are exposed if this IAM role is compromised?"* |
> | 🚨 **Incident Response** | Event correlation graphs | *"What sequence of events led to this alert?"* |

---

## 🧪 What You'll Do in This Workshop

> 🔑 **Bring Your Own API Key** — This workshop requires an API key for **OpenAI** ([get one here](https://platform.openai.com/api-keys)) or **Anthropic** ([get one here](https://console.anthropic.com/settings/keys)). No API key is provided — you must supply your own. See **Lab 0.4** for setup instructions.
>
> 💰 **Disclaimer:** While we make a best-effort attempt to be token-friendly, you are solely responsible for any API costs incurred using your own keys. By using the materials in this workshop, you agree to the terms described in the [LLM Token Usage Disclaimer](docs/token_usage_disclaimer.md).

The labs follow the story above — build the graph, experience the query friction, then solve it:

| Lab | What You'll Learn |
|-----|-------------------|
| **Lab 0** *(pre-work)* | Set up Python, Neo4j, and the tools you'll use — **complete before the workshop** |
| **Lab 1** | Load binaries into a graph and explore them — first visually, then with code. Experience the power of graph queries *and* the friction of writing Cypher by hand |
| **Lab 2** | Build NL2GQL: ask questions in English, get graph-backed Cypher queries — solving the query friction from Lab 1 |
| **Lab 3** | Use the graph to find vulnerabilities: unsafe APIs, exploit paths, complex code — across systems of binaries |

By the end, you'll understand:
- How compiled software can be represented as a **program graph** (a security-focused knowledge graph)
- Why querying that graph is powerful but **manual Cypher doesn't scale**
- How **NL2GQL** lets humans and agents ask questions in natural language and receive grounded, accurate results
- How the system prevents hallucinations by grounding LLMs in the **program graph**
- How this enables **system-level reasoning** across many binaries

**Success looks like:** you can ask 3–5 RE questions in English, inspect the generated Cypher, and explain the answer as **graph-backed evidence**.

---

## 🚀 Quick Start

- Windows 11 or Linux (Ubuntu) — *Tested*
- macOS — *It should work™*

```bash
git clone https://github.com/jonescyber-ai/binql-ultra-lite-workshop.git
cd binql-ultra-lite-workshop
```

> ℹ️ If you clone into a different folder name, that's fine — just `cd` into your cloned folder.

Then head to **Lab 0 — Environment Setup** ([docs/labs/lab0/lab_0_0_overview.md](docs/labs/lab0/lab_0_0_overview.md)) to get started.

### Before you begin (quick checklist)

- ✅ Neo4j Desktop installed; you can create/start a local database
- ✅ Python **3.12** available
- ✅ An LLM API key ready (OpenAI or Anthropic) — used in Labs 2–3

### Repository map (where to look)

- `docs/labs/` — step-by-step lab instructions
- `lab_common/` — shared Python code used across labs (BinQL/NL2GQL scaffolding)
- `dataset/` — sample artifacts used in labs (including `.bcc` files)
- `Blackfyre/` — extraction tooling and utilities (not required for most workshop runs)

---

## 📋 Prerequisites

### Operating System
- Windows 11 or Linux (Ubuntu) — *Tested*
- macOS — *It should work™*
- **64-bit x86_64** architecture required (needed for `pyvex` dependency in Blackfyre; ARM support is currently experimental/problematic)

### Software and Access
- **Python 3.12**
- **Neo4j Desktop** — https://neo4j.com/download/
- An IDE such as **VS Code** or **PyCharm Community Edition**
- **Blackfyre** — https://github.com/jonescyber-ai/Blackfyre
- **🔑 Bring Your Own API Key** — You must have an API key for **OpenAI** ([get one here](https://platform.openai.com/api-keys)) or **Anthropic** ([get one here](https://console.anthropic.com/settings/keys)). The workshop uses LLMs for natural-language querying; no API key is provided — you need to supply your own. See **Lab 0.4** for setup instructions.

### LLMs and Token Efficiency

To keep the workshop accessible and **token-cost friendly**, we intentionally use **gpt-4o-mini** (OpenAI) and **claude-sonnet-4-5-20250929** (Anthropic) as defaults. These models offer a powerful balance of reasoning capability and low cost for student use.

### Common gotchas (read this if setup is painful)

- **Neo4j Desktop vs. Neo4j Server:** the labs assume you can create/start a local DB and have its Bolt URL + credentials.
- **API keys:** if requests fail, confirm your provider key is loaded where Lab 0.4 expects it.
- **Architecture:** `x86_64` is required; ARM/macOS can be tricky due to binary-analysis dependencies.
- **First run time:** the first graph load/function extraction can take a while; later runs are faster.

---

## ❓ Quick FAQ

- **Do I need to be a reverse engineer?** No. RE is the concrete example, but the graph + NL2GQL pattern generalizes to many security domains.
- **Do I need to run Ghidra or extraction tooling?** Not for most workshop runs. We provide **BCC** artifacts so you can focus on querying and workflows.
- **Will this cost money?** Possibly. Labs that call LLM APIs use your own key; you’re responsible for any provider costs.
- **Do I need to know Cypher?** Not upfront. You’ll learn basic query patterns in Lab 1, and NL2GQL reduces the syntax burden.

---

## ▶️ Ready to Start?

Head to **Lab 0 — Environment Setup** ([docs/labs/lab0/lab_0_0_overview.md](docs/labs/lab0/lab_0_0_overview.md)) to get your environment configured and validated. **Lab 0 is pre-work — complete it before the workshop starts** so we can jump straight into Lab 1 on day one.

---


## 📚 Additional Reading

<details>
<summary><strong>The Story: Why binql and Graph-Grounded Analysis?</strong></summary>

### 1. Beyond "one binary at a time"

Historically, reverse engineering has centered on analyzing individual binaries one at a time. Tools like **Ghidra**, **IDA Pro**, and **Binary Ninja** reflect this: you load a single executable, recover its internal structure, and reason about it in isolation.

But in practice, most security questions are **system-level**:
- How do multiple binaries in a firmware image **interact**?
- Do different binaries **share vulnerable code** (common libraries, copied functions)?
- How does behavior emerge across an **entire software family**?

**binql** addresses this by shifting from isolated analysis to system-level reasoning. By representing systems of binaries as a unified graph, it makes cross-binary relationships explicit—allowing you to reason about systems *as systems*.

### 2. Programs are graphs — use them

Programs are naturally **graph-structured**. The representations that compilers, disassemblers, and analyzers already produce are graphs:

| Representation | Nodes | Edges | Domain |
|----------------|-------|-------|--------|
| **Call graph** | Functions | "calls" relationships | Who calls whom across the binary |
| **Control flow graph (CFG)** | Basic blocks | Branch / fall-through edges | How execution flows within a function |
| **Abstract syntax tree (AST)** | Syntax nodes | Parent–child edges | Source-code structure |

When you load these structures into a graph database like Neo4j, powerful questions become straightforward queries:
- **"Which functions call `strcpy`?"** — follow call edges in the call graph.
- **"Do any binaries share the same vulnerable library?"** — match import patterns across binaries.
- **"What's the path from user input to a dangerous API?"** — traverse control flow edges in the CFG.

Without a graph, answering these requires manually piecing together information from separate tools. With a graph, they become one query.

### 3. The challenge: the query bottleneck

Graph queries are powerful—but they require learning **Cypher** (Neo4j's query language). Every question you want to ask means hand-crafting a query like:

```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
      -[:ENTRY_BLOCK]->(bb:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
WHERE imp.name = 'strcpy'
RETURN b.name, f.name, imp.name
```

This works, but it doesn't scale. Analysts spend more effort on syntax than on analysis, and LLM-powered agents can't write reliable Cypher without deep schema knowledge.

### 4. LLMs as a natural-language interface

**NL2GQL** (Natural Language → Graph Query Language) solves this bottleneck: you (or an agent) ask a question in plain English, and the system translates it to Cypher and executes it against the graph.

```
You ask:    "Which binaries import the strcpy function?"
NL2GQL:      MATCH (b:Binary)-[:IMPORTS_SYMBOL]->(i:ImportSymbol)
             WHERE i.name = 'strcpy' RETURN b.name
You get:     bison_arm, libpng16, ...
```

The graph ensures the answer is **grounded in real facts**—not invented by the LLM. The LLM handles the syntax; the graph provides the evidence.

> 🛡️ **Trust and Accuracy:** A common concern with LLMs in security is "hallucination"—the model inventing facts. binql-ul mitigates this by using **NL2GQL** to ground every answer in a graph query. The LLM doesn't "answer" the question directly from its internal weights; instead, it generates a Cypher query that is executed against the ground-truth facts in Neo4j. If the graph doesn't contain the evidence, the system returns no results rather than "making up" an answer. This transforms the problem from *trusting a black box* to *verifying a generated query*.

> 💡 **Exploratory vs. Deterministic:**
> - **Exploratory (NL2GQL):** Ideal for "speed-to-insight" during discovery. When a human or agent needs to pivot quickly ("Are there any network APIs?", "What calls this function?"), NL2GQL handles the syntax burden.
> - **Deterministic (Explicit Cypher):** Essential for "production-grade" pipelines. For repeatable objectives like the vulnerability analysis in Lab 3, we use pre-defined Cypher queries. This ensures consistent, reliable outcomes that are unaffected by LLM non-determinism, providing the stable foundation needed for high-confidence security reporting.

</details>

<details>
<summary><strong>North Star: Where BinQL is headed (and the challenges)</strong></summary>

### ⭐ The north star: graph-first workflows (beyond one-shot NL2GQL)

```text
Question → Decompose → Bounded query chain → Evidence → (Optional) Summary
```

**Important scope note (this workshop):** we focus on **read-only** graph operations.
- Treat the graph database as a **source of truth** for extracted program facts.
- Generated queries should be safe: bounded (`LIMIT`/depth caps), validated, and **non-mutating**.

In this workshop, we start with the simplest (and extremely useful) case:
- **one question → one generated query → results**

That works surprisingly often—but it’s only step 1.

**North star:** using the graph to answer your question even when there is *no single clean query*.

In real investigations, you usually need a workflow:

- 🧩 **Decompose the question** into sub-questions the graph can answer.
  - Example: “Can network input reach `memcpy`?” becomes:
    1) what are the network entry points?
    2) what’s reachable from those entry points (bounded depth)?
    3) which of those reachable functions call a sink?
- 🧭 **Run multiple small, bounded queries** and combine results (set intersection / path extraction / ranking).
- 💬 **Use dialogue** (human ↔ agent) to clarify missing assumptions:
  - which entry point class (network/file/IPC)?
  - direct calls only or wrappers too?
  - any path or shortest path? depth/time budget?

⚠️ **Key challenges BinQL is working toward solving:**
- Underspecified questions (requires clarifications)
- Incomplete representations (indirect calls, partial dataflow)
- Query cost/performance (must enforce bounds)
- Correctness and trust (schema grounding + validation)

**Beyond this workshop (advanced direction): write-back analytics**
- In richer BinQL systems, analysis isn’t only “read facts” — it can also **persist derived artifacts** back into the graph.
- Examples of write-back artifacts:
  - reachability summaries, rankings, and risk scores
  - discovered source/sink pairs and validated paths
  - analyst annotations, triage decisions, and tags
  - normalized entities extracted from strings (domains, file paths, mutexes)
- Why this helps: some questions become easier and faster when the graph contains **precomputed analytics** and **human/agent context**.

This is why BinQL is best thought of as a **system** (schema + guardrails + pipeline), not a single prompt.

### 🔧 Fine-tuning: why it helps NL2GQL

Even with good prompts and schema grounding, general-purpose LLMs can still:
- drift from your schema naming conventions,
- choose inefficient query shapes,
- or “nearly” match the intended pattern but miss a key constraint.

In the more advanced BinQL variants (see *Versions of binql* below), we use **fine-tuning** to improve NL2GQL reliability by teaching the model:
- the *exact* schema vocabulary (labels/edges/properties),
- preferred/efficient query templates,
- and common RE question → Cypher mappings.

Fine-tuning doesn’t remove the need for guardrails, but it reduces the error rate and the number of retries needed.

</details>

<details>
<summary><strong>Versions of binql</strong></summary>

This project is part of a family of related tools:

```
binql-ultra-lite (binql-ul)  →  binql-lite  →  binql (full)
         ↑                          ↑              ↑
     this repo                   course        long-term
     (workshop)                 materials      open-source
```

> **Reading the diagram:** Start here with **binql-ul** (this workshop), then level up to **binql-lite** (4-day course) or **binql** (full system) as needed.

### Quick Comparison

| | **binql-ul** | **binql-lite** | **binql** |
|---|---|---|---|
| **Status** | **This repository** (3–4 hour workshop) | Used in 4-day Black Hat / RECON courses | Open-source release planned (post-training cycle) |
| **Graph schema** | Minimal subset | Full (functions, BBs, CFG, call graph, imports, strings, cross-binary) | Full + similarity edges, n-gram entities, enriched string nodes |
| **NL2GQL** | ✅ Schema + examples + constraints | ✅ Prompting patterns + iterative refinement | ✅ With guardrails + fine-tuned models |
| **Fine-tuning support** | ❌ | ✅ Fine-tune LLaMA for NL2GQL on A6000 GPUs | ✅ Production fine-tuned models |
| **Embeddings & similarity** | ❌ | ✅ Longformer MLM, function/binary similarity, LSH | ✅ Full embedding pipelines |
| **BasicBlockRank (BBR)** | ❌ | ✅ PageRank-inspired block ranking for artifact prioritization | ✅ Integrated into all workflows |
| **Ingestion automation** | Manual | ✅ Interactive + headless Ghidra via Blackfyre | ✅ |
| **Malware analysis** | ❌ | ✅ Capability mapping, clustering, behavioral similarity, enriched string NER | ✅ + family-level agent workflows |
| **Vulnerability analysis** | ✅ Graph-based (Lab 3) | ✅ Unsafe APIs, reachability, patch-diff, N-day triage, code reuse | ✅ + agent-driven triage |
| **Firmware analysis** | ❌ | ✅ Multi-binary ecosystem analysis, shared-library tracking | ✅ + multi-agent ecosystem workflows |
| **LLM summarization & RAG** | ❌ | ✅ Function/binary summarization with KnowledgeRAG | ✅ |
| **Agentic workflows** | ❌ | ✅ AutoGen + MCP agents for triage, YARA rules, patch analysis | ✅ Production agent pipelines |

### What's In Each

**binql-ultra-lite (binql-ul)** — this repository:
- Graph-grounded questions + LLM-assisted querying
- NL2GQL with schema, examples, and constraints
- Vulnerability analysis: user-input detection, source-to-sink paths, complexity/dark-code analysis, LLM-powered triage reports
- Workshop-friendly scaffolding and examples
- Easy to extend (add questions, schema pieces, prompts)
- Upcoming training: [Automating Reverse Engineering with AI/ML, Graphs, and LLM Agents](https://recon.cx/2026/en/trainingAutomatingREwithAIML.html) at **RECON 2026**

**binql-lite** — 4-day course materials ([full syllabus](docs/syllabus/syllabus_4day_course.md)) (everything in binql-ul, plus):

*Graph & cross-binary analysis:*
- Full program-graph schema (functions, basic blocks, CFG, call graph, imports, strings, cross-binary relationships)
- **BasicBlockRank (BBR)** — PageRank-inspired algorithm that ranks basic blocks by execution relevance, propagating importance to referenced imports, strings, and functions
- Behavioral binary similarity via graph-sampled import call traces (compiler/architecture-stable fingerprints)
- Scalable function and binary similarity using **locality-sensitive hashing (LSH)** and approximate nearest-neighbor search

*Malware analysis:*
- Capability mapping and structural detection of obfuscation/anti-analysis features
- Malware family clustering using shared components and behavioral similarity
- Enriched string nodes via NER (domains, IPs, URLs, mutexes, registry keys) for cross-family behavioral insights

*Vulnerability analysis (beyond binql-ul):*
- **Patch impact analysis** — diff unpatched vs. patched binaries to locate affected code regions and validate root-cause fixes
- **N-day vulnerability triage** — treat CVEs as hypotheses, filter using structural/semantic constraints from actual execution paths
- Code reuse and variant discovery across binaries via similarity edges

*Firmware analysis:*
- Multi-binary ecosystem analysis — treat firmware images as systems of interacting binaries rather than isolated programs
- Shared-library and import-relationship mapping to uncover attack surfaces and high-risk components

*Embeddings & neural approaches:*
- **Longformer MLM** trained on binary-derived strings for context-aware embeddings
- Function name prediction using BBR-weighted basic block embeddings + transformer decoder
- Embeddings written back into the program graph for downstream retrieval and clustering

*LLM & agent workflows:*
- **KnowledgeRAG** — RAG grounded in the program graph for function-level and whole-binary summarization
- **Fine-tuning LLaMA** on A6000 GPUs to improve NL2GQL accuracy for BinQL queries
- **Agentic pipelines** using AutoGen and MCP for patch impact analysis, N-day triage, firmware ecosystem analysis, graph-grounded summarization, and automated YARA rule generation

**binql (full)** — long-term open-source goal (everything in binql-lite, plus):
- Production-grade extraction → graph → analysis workflows (end-to-end)
- Production fine-tuned NL2GQL models with guardrails and validation
- Full agent pipelines for automated large-scale triage and recursive malware family exploration
- N-gram entity integration for graph-driven YARA signature synthesis
- Designed for deployment beyond training environments

</details>

---

## 👤 About the Author

**Malachi Jones, PhD** — Creator of **binql** and instructor for **Automating Reverse Engineering with AI/ML, Graphs, and LLM Agents** at **Black Hat** and **RECON**.

- LinkedIn: https://www.linkedin.com/in/malachijonesphd/
- GitHub: https://github.com/jonescyber-ai
- Email: malachi.jones@jonescyber-ai.com
- Upcoming training: https://recon.cx/2026/en/trainingAutomatingREwithAIML.html

---

## 📦 Repository Status

> **Short name:** We sometimes use **binql-ul** as shorthand for **binql-ultra-lite**.

This repository contains the workshop materials and example code needed to follow along. As content is added/updated, this README will be expanded with additional exercises and troubleshooting notes.
