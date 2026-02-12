# 🧪 Lab 0 Overview — Environment Setup and Validation *(Pre-Work)*

By completing Lab 0, you’ll have a known-good environment for the rest of the workshop.

> ⚠️ **Complete Lab 0 before the workshop begins.** Lab 0 is pre-work — you should have a fully working environment (Python, Blackfyre, Neo4j) before the first session starts. This ensures we can jump straight into Lab 1 on day one.

---

## ⚡ TL;DR

> 🔧 **Labs 0.1–0.3**: Tool-running setup and validation — no code writing required.

What you will do:
- Set up Python 3.12+ and a virtual environment
- Install Blackfyre (editable)
- Create and configure a Neo4j Desktop database (`binql`) with APOC + GDS
- Validate that everything is working before starting Lab 1

---

### 📂 Student-Accessible Folders

| Folder | Purpose |
|---|---|
| `docs/` | Documentation and lab instructions |
| `docs/labs/` | Student-facing lab writeups |
| `docs/syllabus/` | Workshop syllabus |
| `venv/` | Python virtual environment (you create this) |

> ℹ️ Blackfyre is cloned into the repo root (`Blackfyre/` folder inside `binql-ultra-lite-workshop/`).

---

### Setup

```bash
source venv/bin/activate
```

---

## 🧱 Lab Breakdown

| Sub-Lab | Type | Description |
|---|---|---|
| Lab 0.1 | 🔧 Setup | Install/configure Python 3.12+, venv, and IDE interpreter |
| Lab 0.2 | 🔧 Setup | Install Blackfyre (editable) and validate imports |
| Lab 0.3 | 🔧 Setup | Set up Neo4j Desktop instance + APOC + GDS |
| Lab 0.4 | 🔧 Setup | Configure and test the LLM client (OpenAI / Anthropic) |

---

## 🧠 Key Concepts

| Concept | Description |
|---|---|
| **Known-good baseline** | Getting everyone to the same working environment before analysis starts |
| **Virtual environments** | Isolating Python dependencies so labs are reproducible |
| **Graph DB prerequisites** | Ensuring Neo4j + required plugins are working upfront |
| **Evidence-first validation** | Verifying every dependency with concrete commands/queries |

---

## 🧭 Looking Ahead

Lab 0 is pre-work — complete it before the workshop so you can move fast once the reverse engineering work starts.

In Lab 1 and beyond, you’ll load or build binary-derived structure into a Neo4j graph and start asking system-level reasoning questions (first in Cypher, then via natural language).

---

## 📚 Lab Documents

See the following files in this folder:
- Lab 0.1 (lab_0_1_setup_python.md)
- Lab 0.2 (lab_0_2_setup_blackfyre.md)
- Lab 0.3 (lab_0_3_setup_neo4j.md)
- Lab 0.4 (lab_0_4_setup_llm.md)

