# binql-ultra-lite Workshop Syllabus

## Description

This 4-hour workshop teaches how to answer **system-level reverse engineering questions in natural language** by representing binary program structure in a **Neo4j graph** and using an **LLM** to translate analyst intent into graph queries.

Participants build and use **binql-ultra-lite** (`binql-ul`) to ingest pre-generated BCC files into a program graph, explore it visually and programmatically, build an **NL2GQL pipeline** that translates English questions into Cypher, and apply graph-based **vulnerability analysis** with LLM-powered triage reports.

**Prerequisites:** Comfort with Python. Familiarity with basic RE concepts. Graph database experience helpful but not required.

---

## Learning Objectives

By the end, participants should be able to:

1. Explain why a **graph** is a natural representation for binary program structure and system-level RE questions.
2. Ingest binaries into Neo4j and write Cypher queries — and understand the cost of doing so manually.
3. Build an **NL2GQL pipeline** (schema export → enrichment → prompt → parse → execute with retry).
4. Apply **graph-based vulnerability analysis**: input detection, source-to-sink paths, complexity analysis, LLM-powered triage.
5. Describe failure modes (hallucinated queries, missing constraints) and mitigations (schemas, validation, retries).

---

## Environment

- Python 3.12+, Neo4j Desktop (APOC + GDS), Blackfyre, OpenAI API key
- See `README.md` for full details.

---

## Schedule (~3.5 hours)

| Block | Duration | What Happens |
|-------|----------|--------------|
| **Lab 0** — Environment Setup *(pre-work)* | 20 min | Python venv, Blackfyre, Neo4j + plugins, `--check-db` — **complete before the workshop** |
| **Lecture** — Graphs, LLMs, and Natural-Language Interfaces <sup>📎</sup> | 45 min | Programs are naturally graphs — call graphs, control flow, and data dependencies — so a graph database like Neo4j is a natural fit for querying them. The catch is that writing Cypher by hand requires expertise and doesn't scale to large codebases or automated workflows. LLMs solve this by translating plain-English questions into Cypher automatically (the NL2GQL pattern), grounded in the graph schema so answers stay accurate. |
| **Lab 1** — Program Graph Foundations | 40 min | Ingest BCCs, explore in Neo4j Browser, write Python query functions, build triage + vuln analysis scripts |
| **Lab 2** — NL2GQL Pipeline | 40 min | Schema export, enrichment, prompt builder, response parser, query executor with retry |
| **Lab 3** — Vulnerability Analysis | 40 min | Input source detection, source-to-sink paths, complexity/dark code, LLM triage reports |

---

## Story Arc

1. **Lab 0** *(pre-work)* — Get a known-good environment before the workshop starts.
2. **Lecture** — Why programs are graphs, the query bottleneck, and how LLMs + NL2GQL solve it.
3. **Lab 1** — Build the program graph, query it by hand, feel the Cypher friction.
4. **Lab 2** — Remove the friction: build NL2GQL so questions become automatic Cypher.
5. **Lab 3** — Apply everything: detect attack surfaces, trace exploit paths, generate LLM-powered triage reports.

> **Core principle:** *Structure first, then automate.* The graph provides the structure; NL2GQL and LLMs provide the automation.

---

## Notes

- **Benign binaries only** in lab datasets — same techniques apply to malware, but we avoid AV/Defender false positives on student machines.
- 🌐 **Beyond reverse engineering:** The graph-grounded analysis pattern taught here — represent structured relationships in a graph, then query with natural language — applies across cybersecurity: threat intelligence, network security, cloud infrastructure, incident response, and more.
- **Fine-tuning** the LLM on domain-specific question–Cypher pairs is an advanced approach to improve NL2GQL translation accuracy — out of scope for this workshop, but supported in the full binql system.
- `binql-ul` is a stepping stone toward a future **full open-source release of binql**.
> 📎 **Lecture slides** are not yet included in this repository. A PDF of the lecture will be added in the coming weeks.
