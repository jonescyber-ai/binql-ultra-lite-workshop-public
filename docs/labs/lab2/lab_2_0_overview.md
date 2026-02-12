# 🧪 Lab 2 Overview — NL2GQL: Natural Language to Graph Query Language

Lab 2 introduces **NL2GQL** (Natural Language to Graph Query Language): a system that bridges natural language and Neo4j's Cypher query language using Large Language Models (LLMs). By the end of this lab, you will understand how to export graph schemas in LLM-friendly formats, build effective prompts with ontology context, and convert natural language questions into executable Cypher queries.

This lab builds directly on Lab 1's program graph foundations:

- **From manual Cypher → natural language queries.** In Lab 1, you wrote Cypher queries by hand. Now you'll build a system that generates them from plain English.
- **From schema knowledge → automated context.** Instead of memorizing node labels and relationships, you'll learn to extract and format schema information for LLMs.
- **From single queries → intelligent retry.** When queries fail, the system learns from errors and self-corrects.

The core insight: **LLMs are powerful but need context**. By providing the graph ontology (schema) as context, we transform a general-purpose LLM into a domain-specific Cypher expert.

---

## ⚡ TL;DR

> ✏️ **All 5 labs (2.1–2.5) require writing code.** You will implement Python functions in `student_labs/lab2/` and run tests to verify your implementation.

What you will do:
- Implement schema extraction using APOC procedures
- Implement schema enrichment with sample values for better LLM context
- Implement prompt building, response parsing, and error recovery
- Test your implementation by converting natural language questions to Cypher queries

---

> ⚠️ **SETUP REQUIRED:** Before starting any Lab 2 sub-labs, you must complete the **🔧 Lab Setup** section below to ingest the Lab 2 dataset into Neo4j.

---

### 📂 Student-Accessible Folders

| Folder | Purpose |
|--------|---------|
| `dataset/lab2/` | Lab 2 dataset (BCCs for NL2GQL testing) |
| `student_labs/` | Your implementation files (Labs 2.1–2.5) |
| `lab_common/` | Shared utilities including LLM client |
| `venv/` | Python virtual environment |
| `docs/` | Documentation and lab instructions |

---

### Prerequisites

- **Neo4j running**: The `binql` database instance should be started.
- **LLM API access**: Configured in `lab_common/llm/` (see **Lab 0.4** for details).
  > 💰 **Disclaimer:** You are responsible for all API costs incurred. By using the materials in this workshop, you agree to the terms described in the [LLM Token Usage Disclaimer](../../token_usage_disclaimer.md).

### Setup

```bash
source venv/bin/activate
```

---

## 🎯 Why NL2GQL?

Writing Cypher queries requires three types of knowledge:

1. **Schema knowledge**: What node labels, relationships, and properties exist?
2. **Cypher syntax**: How do you express patterns, filters, and aggregations?
3. **Domain semantics**: What does `classification = "benign"` actually mean?

This creates a barrier for:
- **Non-technical analysts** who need to query the graph but don't know Cypher.
- **Autonomous agents** that need to investigate binaries without human-written queries.
- **Rapid exploration** where writing queries slows down the investigation loop.

**NL2GQL solves this** by:

1. Extracting comprehensive schema metadata from Neo4j.
2. Enriching the schema with sample values and descriptions.
3. Providing this context to an LLM along with the user's question.
4. Parsing the LLM's response to extract executable Cypher.
5. Automatically retrying with error feedback when queries fail.

The result: ask questions in plain English, get accurate Cypher queries.

---

## 🔧 Lab Setup: Ingest Lab 2 Dataset

> ⚠️ **REQUIRED:** You must complete this setup before starting any Lab 2 sub-labs.

Lab 2 uses its own dataset with binaries for NL2GQL testing. You need to reset the database and ingest the Lab 2 binaries.

### Step 1: Reset the database and ingest Lab 2 data

#### Linux/macOS

```bash
source venv/bin/activate

# Reset database and ingest the Bison binary
python -m lab_common.binql.binql_ul \
  --reset \
  --bcc dataset/lab2/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc

# Ingest the benign corpus
python -m lab_common.binql.binql_ul \
  --bcc_dir dataset/lab2/benign_corpus
```

#### Windows (PowerShell)

```powershell
.\venv\Scripts\Activate.ps1

# Reset database and ingest the Bison binary
python -m lab_common.binql.binql_ul `
  --reset `
  --bcc dataset/lab2/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc

# Ingest the benign corpus
python -m lab_common.binql.binql_ul `
  --bcc_dir dataset/lab2/benign_corpus
```

### Step 2: Verify Neo4j connectivity

```bash
source venv/bin/activate
python -m lab_common.binql.binql_ul --check-db
```

### Step 3: Verify data was ingested

Open Neo4j Browser and run:

```cypher
MATCH (b:Binary) RETURN b.name, b.classification LIMIT 10;
```

You should see 6 binaries listed (1 bison_arm + 5 benign corpus).

---

## 🧱 Lab Breakdown

All 5 sub-labs are **implementation labs** where you write Python code. Each follows this pattern:

`Overview → 🎯 What You Need To Do → 📚 Implementation Guide → ✅ Success Criteria → Solution → 📚 Additional Reading`

### ✏️ Implementation Labs (2.1–2.5)

| Lab | Description | Your Task |
|-----|-------------|-----------|
| **Lab 2.1** | Schema Export | Implement `student_labs/lab2/schema_export.py` — Extract schema metadata using APOC |
| **Lab 2.2** | Schema Enrichment | Implement `student_labs/lab2/schema_enrichment.py` — Add sample values to schema |
| **Lab 2.3** | Prompt Builder | Implement `student_labs/lab2/prompt_builder.py` — Build LLM prompts with schema context |
| **Lab 2.4** | Response Parser | Implement `student_labs/lab2/response_parser.py` — Extract Cypher from LLM responses |
| **Lab 2.5** | Query Executor | Implement `student_labs/lab2/query_executor.py` — Execute queries with retry logic |

---

## Pipeline Summary (End-to-End)

```text
Inputs:
  - Natural language question (e.g., "Find all benign binaries")
  - Neo4j database with program graph (from Lab 1)
  - LLM API access

Steps:
  1) Export schema metadata using APOC procedures (Lab 2.1)
  2) Enrich schema with sample property values (Lab 2.2)
  3) Build system prompt with schema context (Lab 2.3)
  4) Send question to LLM, parse response to extract Cypher (Lab 2.4)
  5) Execute query with automatic retry on errors (Lab 2.5)

Outputs:
  - Generated Cypher query
  - Query execution results
  - Explanation of the query
```

---

## 🧂 Repository, Subfolders, and Key Files

**Student-accessible resources:**

| Resource | Location |
|----------|----------|
| Lab documentation | `docs/labs/lab2/` |
| Your implementations | `student_labs/lab2/` (Labs 2.1–2.5) |
| LLM client | `lab_common/llm/client.py` |
| Lab 2 dataset | `dataset/lab2/` (BCCs for testing) |

**How to run your NL2GQL implementation:**

```bash
source venv/bin/activate
python -m student_labs.lab2.nl2gql --query "Find all benign binaries"
```

---

## 🧠 Key Concepts

| Concept | Description |
|---------|-------------|
| **Schema/Ontology** | The structure of the graph: node labels, relationship types, properties, and constraints. |
| **APOC Procedures** | Neo4j's "Awesome Procedures On Cypher" library for metadata extraction and utilities. |
| **Prompt Engineering** | Crafting prompts with schema context, sample values, and constraints so LLMs generate accurate Cypher. |
| **Response Parsing** | Extracting structured data (Cypher queries) from LLM text responses. |
| **Error Recovery** | Feeding execution errors back to the LLM to generate corrected queries. |

---

## 🧭 Looking Ahead

Lab 2 establishes **NL2GQL** — the natural language interface that enables humans and agents to query the program graph without writing Cypher manually. This capability is foundational for later modules:

| Lab 2 Skill | Where It's Used | Why It Matters |
|-------------|-----------------|----------------|
| **Schema extraction** | Agent workflows | LLMs need schema context to generate valid queries |
| **Prompt engineering** | Summarization, triage, rule generation | Same pattern applies to all LLM tasks |
| **NL → Cypher translation** | Agent-driven analysis | Agents query the graph using natural language, not hand-written Cypher |
| **Error recovery** | Multi-agent workflows | Robust retry mechanisms are essential for autonomous systems |
| **Context enrichment** | RAG and summarization | The "context is everything" principle applies everywhere |

> 💡 **Key Insight:** Lab 2 reveals a fundamental pattern: **LLMs are powerful but need context**. The same model that struggles with raw Cypher generation becomes highly accurate when given proper schema context. This principle — enriching prompts with domain-specific structure — applies to every LLM task in the course.

### Advanced: Improving Translation Accuracy with Fine-Tuning

> 🔮 **Out of scope for this workshop**, but worth knowing about.

The NL2GQL pipeline in this lab uses a general-purpose LLM (e.g., `gpt-4o-mini`) with schema-grounded prompting. This works well, but translation accuracy can be significantly improved by **fine-tuning** the LLM on domain-specific question–Cypher pairs derived from the binql ontology.

Fine-tuning teaches the model the specific graph schema, naming conventions, and query patterns so it generates correct Cypher more reliably — especially for complex multi-hop queries, edge cases, and domain-specific terminology that prompt engineering alone may not cover.

The full **binql** system includes fine-tuning support with models trained on the binql ontology. For this workshop, schema-grounded prompting provides a strong baseline that demonstrates the core NL2GQL pattern.

---

## 📚 Lab Documents

See the following files in this folder:
- Lab 2.1 (lab_2_1_schema_export.md)
- Lab 2.2 (lab_2_2_schema_enrichment.md)
- Lab 2.3 (lab_2_3_prompt_builder.md)
- Lab 2.4 (lab_2_4_response_parser.md)
- Lab 2.5 (lab_2_5_query_executor.md)
