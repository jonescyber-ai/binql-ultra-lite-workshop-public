# 🧪 Lab 1 Overview — Program Graph Foundations: Ingest and Explore Binaries in Neo4j (`binql-ul`)

Lab 1 introduces `binql-ul`: a minimal but practical ingestion pipeline that converts pre-generated `*.bcc` files
into a Neo4j-backed knowledge graph. By the end of this lab, you will be able to ingest BCC files,
attach metadata, explore the graph visually and programmatically, and write analysis scripts that query the graph.

This lab is the on-ramp to the course's core shift in workflow:

- **From single-binary RE → system-level reasoning.** Instead of answering questions by manually clicking around in a disassembler,
  we will accumulate partial program facts (functions, basic blocks, control flow, call edges, imports, strings, metadata) into a
  single shared graph.
- **From notes → explicit evidence.** The Neo4j program graph becomes a persistent "source of truth" that supports repeatable,
  evidence-driven analysis across many binaries.
- **From ad-hoc queries → reusable query patterns (and later, NL2GQL).** In Lab 1.2 you will craft Cypher queries by hand — powerful,
  but requiring expertise. Lab 2 introduces natural-language querying that removes that friction.

In other words, Lab 1 is not only about ingestion. It is about learning the **program-graph mental model** and the **baseline query
vocabulary** that everything else in the course will build on. You will also experience firsthand the cost of manual Cypher authoring —
the motivation for NL2GQL in Lab 2.

---

## ⚡ TL;DR

> ⚠️ **Lab 1.1 requires executing commands and queries.** It has a "🎯 What You Need To Do" section with the critical tasks you must complete, and a "✅ Success Criteria" checklist to verify completion.
>
> ✏️ **Labs 1.2–1.4 require writing code.** You will implement Python functions in `student_labs/lab1/` and run tests to verify your implementation.

- You will ingest BCC files into Neo4j using `python -m lab_common.binql.binql_ul`.
- You will learn two ingestion modes:
  - **Single BCC ingestion** (ingest one `*.bcc` file).
  - **Directory BCC ingestion** (ingest all `*.bcc` files in a directory with optional metadata).
- You will explore the graph visually in **Neo4j Desktop Browser** (Lab 1.1).
- You will write Python functions that query the graph programmatically using the Neo4j driver (Lab 1.2).
- You will write Python scripts that query the graph and produce analysis reports (Labs 1.3–1.4).

---

> ⚠️ **SETUP REQUIRED:** Before starting any Lab 1 sub-labs, you must complete the **🔧 Lab Setup** section below to reset the database.

---

### 📂 Student-Accessible Folders

| Folder | Purpose |
|--------|---------|
| `dataset/` | Lab datasets (BCCs, metadata files) |
| `student_labs/` | Your implementation files (Labs 1.3, 1.4) |
| `lab_common/` | Shared utilities and the `binql_ul` CLI |
| `venv/` | Python virtual environment |
| `docs/` | Documentation and lab instructions |

---

### Prerequisites

- Lab 0 completed (Python 3.12+, Blackfyre, Neo4j with APOC + GDS).
- Neo4j running and reachable (URI/user/password).

### Setup

```bash
source venv/bin/activate
```

---

## 🎯 Why a binary knowledge graph?

Reverse engineering often starts as "one binary at a time," but real-world work quickly becomes **corpus-level**:
firmware images, software families, build variants, and cross-architecture ports.

In a knowledge graph, binaries, functions, basic blocks, strings, imports, exports, and call edges become explicit entities.
That structure enables repeatable analysis and scalable triage (e.g., "show me all call paths to a risky function across a corpus").

This lab also establishes a second, equally important idea: **querying is the bottleneck**.

- Cypher is powerful, but crafting good graph queries takes time, attention, and expertise.
- In Lab 1.2 you will hand-craft Cypher queries to answer analysis questions. They work — but the effort required to write
  each one highlights the friction of manual graph querying.

That friction is exactly why **NL2GQL** (natural language → graph query language) is so valuable:

- For a human analyst, it lowers the "syntax tax" so you can ask the question you mean and iterate faster.
- For an autonomous agent, it enables a direct interface: the agent can ask questions, get graph-backed answers, and refine its
  investigation loop without you hand-writing every Cypher query.

In Lab 2, we will build toward natural-language querying on top of the same graph you create here. Lab 1 gives you the
ground truth: the schema, the invariants, and the canonical query patterns that NL2GQL needs to be reliable.

---

## 🔧 Lab Setup: Reset Database and Verify Connectivity

> ⚠️ **REQUIRED:** You must complete this setup before starting any Lab 1 sub-labs.

### Step 1: Reset the database

#### Linux/macOS

```bash
source venv/bin/activate
python -m lab_common.binql.binql_ul --reset
```

#### Windows (PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
python -m lab_common.binql.binql_ul --reset
```

### Step 2: Verify connectivity

#### Linux/macOS

```bash
source venv/bin/activate
python -m lab_common.binql.binql_ul --check-db
```

#### Windows (PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
python -m lab_common.binql.binql_ul --check-db
```

You should see:

```
✓ Neo4j liveness check passed (connectivity + credentials OK)
```

---

## 🧱 Lab Breakdown

### 📖 Reading & Exploration Lab (1.1)

This lab focuses on understanding concepts, running provided tools, and exploring the Neo4j graph. You will execute commands and queries but **do not need to write code**.

| Lab | Description | What You Do |
|-----|-------------|-------------|
| **Lab 1.1** | Ingest & Explore in Neo4j Browser | Ingest BCCs, explore the graph visually in Neo4j Desktop |

### ✏️ Implementation Labs (1.2–1.4)

These labs require you to **write Python code** in `student_labs/lab1/`. You will implement functions that query the Neo4j graph and produce analysis reports.

| Lab | Description | Your Task |
|-----|-------------|-----------|
| **Lab 1.2** | Graph Queries (Python) | Implement `student_labs/lab1/graph_queries.py` |
| **Lab 1.3** | Binary Triage Script | Implement `student_labs/lab1/malware_triage.py` |
| **Lab 1.4** | Vulnerability Analysis | Implement `student_labs/lab1/vuln_analysis.py` |

---

## 🧠 Key Concepts

| Concept | Description |
|---------|-------------|
| **BCC (Binary Context Container)** | A serialized container of lifted binary context used for consistent downstream ingestion and analysis. |
| **Neo4j property graph** | A graph data model of nodes/relationships with properties used for scalable querying and analysis. |
| **Corpus metadata** | Labels like `classification` and `tags` that enable later filtering, clustering, and evaluation. |
| **Idempotent ingestion** | Re-running ingestion should not create duplicate graph entities for the same binary SHA256. |
| **Programmatic graph querying** | Using Python + Neo4j driver to query the graph and produce analysis reports. |
| **NL2GQL (Natural Language → Graph Query Language)** | Translates plain-English questions into Cypher queries automatically — introduced in Lab 2 to remove the manual Cypher friction you will experience in this lab. |

---

## 🧭 Looking Ahead: From Manual Cypher to NL2GQL

Lab 1 is your **graph foundation** — the Neo4j program graph you build here becomes the shared data layer for all downstream analysis, from similarity search to agent-driven triage.

But Lab 1 also reveals a friction point: every question you want to ask the graph requires you to **hand-craft a Cypher query**. That works for a handful of queries, but it doesn't scale — not for a human analyst exploring a large corpus, and certainly not for an autonomous agent that needs to ask hundreds of questions in a loop.

**Lab 2 introduces NL2GQL** (Natural Language → Graph Query Language) to solve exactly this problem:

- Instead of writing `MATCH (b:Binary)-[:IMPORTS_SYMBOL]->(i:ImportSymbol) WHERE i.name = 'system' RETURN b.name`, you ask: *"Which binaries import the system function?"*
- NL2GQL translates your natural-language question into valid Cypher, executes it against the graph, and returns the results.
- The same interface works for human analysts (faster iteration) and for LLM-powered agents (no Cypher expertise required).

The clean, well-labeled graph and the canonical query patterns you learn in Lab 1 are what make NL2GQL reliable — it needs schema knowledge and ground-truth examples to generate correct queries.

| Lab 1 Skill | Where It's Used | Why It Matters |
|-------------|-----------------|----------------|
| **Graph ingestion** | Every graph-based lab | All analysis queries the Neo4j program graph |
| **Cypher query patterns** | NL2GQL training (Lab 2) | Canonical queries become ground truth for NL2GQL |
| **Corpus metadata** | Clustering, evaluation | Labels enable supervised learning and validation |
| **Programmatic querying** | Similarity, triage scripts | Python + Neo4j is the pattern for all automation |
| **Schema understanding** | NL2GQL, agent workflows | Agents need schema knowledge to generate valid queries |

> 💡 **Key Insight:** Lab 1 highlights the cost of manual graph querying. Lab 2 introduces **NL2GQL** so humans and agents can ask those same questions in natural language, with the system generating and executing Cypher automatically.

---

## 📚 Lab Documents

See the following files in this folder:
- Lab 1.1 (lab_1_1_ingest_and_explore.md)
- Lab 1.2 (lab_1_2_graph_queries.md)
- Lab 1.3 (lab_1_3_malware_triage.md)
- Lab 1.4 (lab_1_4_vuln_analysis.md)
