# binql-ultra-lite: Asking Questions About Software in Natural Language

> **What if you — or an agent in your workflow — could ask plain-English questions about binaries (i.e., compiled software), malware, or vulnerabilities — and receive precise, evidence-backed answers?**

That's the idea behind **binql-ultra-lite** (`binql-ul`): a hands-on workshop where you build a system that combines **graphs**, **large language models (LLMs)**, and **program analysis** to answer questions about binaries — without writing complex query syntax.

<table><tr><td>📌 <sub><em>binql-ultra-lite</em> is the workshop edition of <b>binql</b>. A richer <em>binql-lite</em> powers our 4-day courses (<a href="https://recon.cx/2026/en/trainingAutomatingREwithAIML.html">upcoming: Automating Reverse Engineering with AI/ML, Graphs, and LLM Agents — RECON 2026</a> · <a href="docs/syllabus/syllabus_4day_course.md">4-day course syllabus</a>); a full open-source release is planned after the current training cycle (2026). <a href="#-additional-reading">Additional Reading</a> → <em>"Versions of binql"</em></sub></td></tr></table>

---

## 💡 The Idea

Programs are naturally **graph-structured** — functions call other functions, basic blocks branch to other blocks, binaries import shared libraries. When you load these structures into a graph database like Neo4j, questions like *"Which functions call `strcpy`?"* or *"Do any binaries share a vulnerable library?"* become straightforward queries.

The catch is that writing those queries by hand — in a language called **Cypher** — requires expertise and doesn't scale. Every new question means crafting new syntax. That's where **LLMs** come in: instead of writing Cypher yourself, you ask your question in plain English, and the system translates it into a graph query automatically. The graph ensures the answer is grounded in real program structure, not hallucinated.

```
1. EXTRACT          2. QUERY               3. ANSWER
   Binary code  →      Graph database  →      Natural language
   (Ghidra)            (Neo4j)                (LLM + NL2GQL)
```

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
- How compiled software can be represented as a **knowledge graph**
- Why querying that graph is powerful but **manual Cypher doesn't scale**
- How **NL2GQL** lets humans and agents ask questions in natural language and receive grounded, accurate results
- How the system prevents hallucinations by grounding LLMs in the **program graph**
- How this enables **system-level reasoning** across many binaries

No prior experience with graphs or LLMs is required — the labs build up from scratch.

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

### No Prior Experience Required

- **New to graphs?** Lab 1 introduces graph concepts from scratch — nodes, relationships, properties, and queries.
- **New to LLMs?** Lab 2 walks you through how LLMs generate queries and how to make them reliable.
- **New to reverse engineering?** The workshop uses pre-processed binaries (BCC files) so you can focus on analysis, not tool setup.

---

## ▶️ Ready to Start?

Head to **Lab 0 — Environment Setup** ([docs/labs/lab0/lab_0_0_overview.md](docs/labs/lab0/lab_0_0_overview.md)) to get your environment configured and validated. **Lab 0 is pre-work — complete it before the workshop starts** so we can jump straight into Lab 1 on day one.

---

## 📚 Additional Reading

<details>
<summary><strong>The full story: from binaries to natural-language answers</strong></summary>

### 1. Programs are graphs — use them

Programs are naturally **graph-structured**. The representations that compilers, disassemblers, and analyzers already produce are graphs:

| Representation | Nodes | Edges | Domain |
|----------------|-------|-------|--------|
| **Call graph** | Functions | "calls" relationships | Who calls whom across the binary |
| **Control flow graph (CFG)** | Basic blocks | Branch / fall-through edges | How execution flows within a function |
| **Abstract syntax tree (AST)** | Syntax nodes (expressions, statements) | Parent–child edges | Source-code structure (pre-compilation) |

In reverse engineering we focus on **call graphs** and **CFGs** because they are what we can recover from compiled binaries. But the same graph-grounded approach extends naturally to **source code** (via ASTs), **intermediate representations**, and even **cross-language** analysis — the underlying principle is the same: represent program structure as connected nodes and relationships, then query it.

> 🌐 **Beyond reverse engineering:** The graph + NL2GQL pattern you learn here is domain-agnostic. Swap out the binary program graph for an attack graph, a network topology, or a cloud infrastructure model — the same approach (structure → query → automate) applies. See the table in the main README for specific examples.

When you load binaries into a graph database like Neo4j, powerful questions become straightforward queries:

- **"Which functions call `strcpy`?"** — follow call edges in the call graph
- **"Do any binaries share the same vulnerable library?"** — match import patterns across binaries
- **"What's the path from user input to a dangerous API?"** — traverse control flow edges in the CFG
- **"Which basic blocks are reachable from the entry point?"** — walk the CFG from the entry block

Without a graph, answering these questions requires manually piecing together information from separate tools. With a graph, they become one query.

### 2. The challenge: querying the graph

Graph queries are powerful — but they require learning **Cypher** (Neo4j's query language). Every question you want to ask means hand-crafting a query like:

```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
      -[:ENTRY_BLOCK]->(bb:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
WHERE imp.name = 'strcpy'
RETURN b.name, f.name, imp.name
```

This works, but it doesn't scale:

- **For analysts:** Writing Cypher takes time and expertise. You spend more effort on syntax than on analysis.
- **For automation:** An LLM-powered agent can't write reliable Cypher without deep schema knowledge.
- **For systems of binaries:** As you add more binaries — firmware images, software families, build variants — the number of questions grows faster than you can write queries.

### 3. Use LLMs as a natural-language interface

**NL2GQL** (Natural Language → Graph Query Language) solves this: you ask a question in plain English, the system translates it to Cypher, executes it against the graph, and returns the results.

```
You ask:    "Which binaries import the strcpy function?"

NL2GQL:      MATCH (b:Binary)-[:IMPORTS_SYMBOL]->(i:ImportSymbol)
             WHERE i.name = 'strcpy' RETURN b.name

You get:     bison_arm, libpng16, ...
```

The graph ensures the answer is **grounded in real program structure** — not invented by the LLM. The LLM handles the syntax; the graph provides the facts.

> 🛡️ **Trust and Accuracy:** A common concern with LLMs in security is "hallucination"—the model inventing facts. binql-ul mitigates this by using **NL2GQL** to ground every answer in a graph query. The LLM doesn't "answer" the question directly from its internal weights; instead, it generates a Cypher query that is executed against the ground-truth facts in Neo4j. If the graph doesn't contain the evidence, the system can't "hallucinate" an answer.

This same interface works for:
- **Human analysts** — ask questions quickly, iterate faster, no Cypher expertise needed
- **LLM-powered agents** — query the graph programmatically in a loop, refine investigations automatically
- **Systems of binaries** — ask cross-binary questions ("Which binaries in this firmware share a vulnerable library?") without writing a new query for each one

> 💡 **Exploratory vs. Deterministic:** NL2GQL is ideal for exploratory discovery. However, for repeatable, production-grade analysis pipelines (like those in Lab 3), explicit Cypher queries are preferred to ensure consistent and deterministic outcomes.

**Going further: fine-tuning.** This workshop uses schema-grounded prompting to translate English into Cypher. An advanced approach — out of scope here — is to **fine-tune** the LLM on domain-specific question–Cypher pairs derived from the graph ontology, which significantly improves translation accuracy for complex queries. The full binql system supports this; see the comparison table below.

### 4. Enabling systems-level reasoning

The real payoff comes when you move beyond single-binary analysis. Traditional reverse engineering is **one binary at a time** — load an executable, recover its structure, reason about it in isolation. But real-world security questions are **system-level**:

- How do multiple binaries in a firmware image **interact**?
- Do different binaries **share vulnerable code** (common libraries, copied functions)?
- What **attack surface** does an entire software system expose?

A graph database makes these cross-binary relationships explicit. Combined with natural-language querying, you can ask system-level questions as easily as single-binary ones — and get answers backed by the actual program structure.

</details>

<details>
<summary><strong>Why binql? The problem with binary-at-a-time analysis</strong></summary>

### The Traditional Model

Historically, reverse engineering has centered on analyzing individual binaries one at a time. Disassembler tools such as **Ghidra**, **IDA Pro**, and **Binary Ninja** reflect this model: load a single executable, recover its internal structure, and reason about it in isolation.

Programs begin as human-readable source code and are compiled into machine code that computers execute. That compilation process is inherently lossy, discarding much of the original structure and intent. Disassemblers work in reverse to recover enough structure to make binaries readable and analyzable again — though the result remains incomplete.

### The Gap: System-Level Questions

In practice, many security questions are **system-level**. Analysts often care about:
- How multiple binaries **interact** or **relate** to one another
- How binaries form **families** (malware variants, shared codebases)
- How behavior emerges across an **entire system**

But answering those questions requires piecing together many separate analyses, each based on incomplete information.

### How binql Addresses This

**binql** addresses this gap using **graph analysis** — specifically, the challenge of reasoning across many partial analyses to answer system-level questions.

Because programs are naturally graph-structured — control flow, call relationships, data dependencies, and component interactions — binql:
1. **Consumes disassembler output** (Ghidra in this case)
2. **Represents systems of binaries as a unified graph** backed by Neo4j
3. **Makes cross-binary, system-level structure explicit**

This makes it easier to reason about systems *as systems* rather than as disconnected executables.

### Natural Language on Top

On top of this representation, binql allows analysts to **ask high-level questions about binaries and systems in natural language**, shifting effort away from query syntax and toward analysis.

This approach grew out of material from **Black Hat** and **RECON** courses and translates well into a **4-hour hands-on workshop**. **binql-ultra-lite is a stepping stone toward a future full open-source release of binql** — the goal is to make the core concepts usable and teachable now, while building toward a more complete production-grade system.

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
