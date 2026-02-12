# 🔹 Lab 1.2 — Graph Queries (Python)

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab1/graph_queries.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

In Lab 1.1 you explored the graph visually in Neo4j Browser. This lab shifts to **programmatic querying** using
Python and the Neo4j driver. You will write functions that validate the graph structure, check metadata, and run
analysis queries — the same pattern used in later labs and agent workflows.

This is also where you'll feel the **friction of manual Cypher authoring**. Each function below requires you to
know the schema, the relationship names, the property keys, and the Cypher syntax. That expertise requirement is
exactly what **NL2GQL** (Lab 2) will address.

---

## Overview

- **Goal:** Write Python functions that query the Neo4j program graph for validation and analysis.
- **Inputs:** Neo4j database populated by Lab 1.1.
- **Outputs:** A script that prints entity counts, relationship counts, metadata, dangerous import calls, and call graph edges.

---

## 🎯 What You Need To Do

> ℹ️ **Prerequisite:** Complete **Lab 1.1** before starting this lab. The database should contain 6 binaries.

### Step 1: Open the Template File

Open `student_labs/lab1/graph_queries.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement **6 functions** (the template already provides Neo4j connection, report printing, and CLI handling):

1. **`count_entity_types(driver, database)`** — Count all entity types in the graph
2. **`check_duplicates(driver, database)`** — Check for duplicate binaries
3. **`get_relationship_counts(driver, database)`** — Get relationship counts per binary
4. **`get_binary_metadata(driver, database)`** — Get classification and tags for all binaries
5. **`find_dangerous_import_calls(driver, database)`** — Find functions calling dangerous imports
6. **`get_call_graph(driver, database, limit)`** — Get call graph edges

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab1.test.test_lab_1_2
```

### Step 4: Run the Script

Run the full query report:

```bash
source venv/bin/activate
python -m student_labs.lab1.graph_queries
```

You should see entity counts, relationship counts, metadata, dangerous import results, and call graph edges printed to the console.

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j connection setup, the `DANGEROUS_IMPORTS` constant, report printing functions (`print_entity_counts`, `print_relationship_counts`, etc.), `run_all_queries`, and CLI handling. You do not need to implement these.

### Function 1 — `count_entity_types`

Count all entity types in the graph using a `UNION ALL` query.

```python
def count_entity_types(driver, database: str) -> List[Dict[str, Any]]:
    """Count all entity types in the graph."""
    query = """
    MATCH (b:Binary) RETURN 'Binary' AS label, count(b) AS count
    UNION ALL
    MATCH (f:Function) RETURN 'Function' AS label, count(f) AS count
    UNION ALL
    MATCH (bb:BasicBlock) RETURN 'BasicBlock' AS label, count(bb) AS count
    UNION ALL
    MATCH (s:StringLiteral) RETURN 'StringLiteral' AS label, count(s) AS count
    UNION ALL
    MATCH (i:ImportSymbol) RETURN 'ImportSymbol' AS label, count(i) AS count
    UNION ALL
    MATCH (e:ExportSymbol) RETURN 'ExportSymbol' AS label, count(e) AS count
    UNION ALL
    MATCH (l:Library) RETURN 'Library' AS label, count(l) AS count
    """
    with driver.session(database=database) as session:
        result = session.run(query)
        return [record.data() for record in result]
```

### Function 2 — `check_duplicates`

Check for duplicate binaries (same SHA256 appearing more than once). An empty list means no duplicates — which is expected after idempotent ingestion.

```python
def check_duplicates(driver, database: str) -> List[Dict[str, Any]]:
    """Check for duplicate binaries."""
    query = """
    MATCH (b:Binary)
    WITH b.sha256 AS sha256, count(*) AS count
    WHERE count > 1
    RETURN sha256, count
    """
    with driver.session(database=database) as session:
        result = session.run(query)
        return [record.data() for record in result]
```

### Function 3 — `get_relationship_counts`

Get relationship counts (functions, blocks, strings, imports) per binary. This uses `OPTIONAL MATCH` so binaries with no relationships still appear.

```python
def get_relationship_counts(driver, database: str) -> List[Dict[str, Any]]:
    """Get relationship counts per binary."""
    query = """
    MATCH (b:Binary)
    OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(f:Function)
    OPTIONAL MATCH (f)-[:ENTRY_BLOCK|ORPHAN_BLOCK]->(bb:BasicBlock)
    OPTIONAL MATCH (bb)-[:USES_STRING]->(s:StringLiteral)
    OPTIONAL MATCH (bb)-[:CALLS_TO]->(imp:ImportSymbol)
    RETURN b.name AS name,
           count(DISTINCT f) AS functions,
           count(DISTINCT bb) AS blocks,
           count(DISTINCT s) AS strings,
           count(DISTINCT imp) AS imports
    ORDER BY functions DESC
    """
    with driver.session(database=database) as session:
        result = session.run(query)
        return [record.data() for record in result]
```

### Function 4 — `get_binary_metadata`

Get classification and tags for all binaries.

```python
def get_binary_metadata(driver, database: str) -> List[Dict[str, Any]]:
    """Get classification and tags for all binaries."""
    query = """
    MATCH (b:Binary)
    RETURN b.name AS name,
           b.classification AS classification,
           b.tags AS tags
    ORDER BY b.name
    """
    with driver.session(database=database) as session:
        result = session.run(query)
        return [record.data() for record in result]
```

### Function 5 — `find_dangerous_import_calls`

Find functions that call dangerous imports (shell execution, unsafe string operations). Uses the `DANGEROUS_IMPORTS` constant provided in the template.

```python
DANGEROUS_IMPORTS = [
    "system", "execve", "popen", "strcpy", "gets", "sprintf",
]

def find_dangerous_import_calls(driver, database: str) -> List[Dict[str, Any]]:
    """Find functions that call dangerous imports."""
    query = """
    MATCH (f:Function)-[:ENTRY_BLOCK|ORPHAN_BLOCK]->(bb:BasicBlock)
          -[:CALLS_TO]->(imp:ImportSymbol)
    WHERE imp.name IN $dangerous_imports
    RETURN DISTINCT f.name AS function_name,
           collect(DISTINCT imp.name) AS dangerous_imports,
           f.binary_sha256 AS binary
    ORDER BY size(collect(DISTINCT imp.name)) DESC
    LIMIT 20
    """
    with driver.session(database=database) as session:
        result = session.run(query, dangerous_imports=DANGEROUS_IMPORTS)
        return [record.data() for record in result]
```

### Function 6 — `get_call_graph`

Get call graph edges (caller → callee function pairs).

```python
def get_call_graph(driver, database: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Get call graph edges."""
    query = """
    MATCH (caller:Function)-[:CALLS_FUNCTION]->(callee:Function)
    RETURN caller.name AS caller, callee.name AS callee
    LIMIT $limit
    """
    with driver.session(database=database) as session:
        result = session.run(query, limit=limit)
        return [record.data() for record in result]
```

---

## 🤔 Reflection: The Cost of Manual Cypher

Look back at the functions you just wrote. Each one required you to:

1. **Know the schema** — which node labels exist, which properties they have, which relationships connect them.
2. **Know Cypher syntax** — `MATCH`, `WHERE`, `RETURN`, `OPTIONAL MATCH`, `UNION ALL`, parameterized queries.
3. **Know the analysis question** — what you're looking for and how to express it as a graph pattern.

This is powerful — but it's also a bottleneck. Imagine an analyst who needs to ask "which binaries call `system` through a short call chain?" They need to translate that English question into the exact Cypher pattern above. That translation step is where time and expertise are spent.

**Lab 2 introduces NL2GQL** — natural language to graph query language — which removes that translation step. You'll be able to ask questions in plain English and get Cypher generated automatically. The queries you wrote here become the **ground truth** that NL2GQL learns from.

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] All 6 functions are implemented in `student_labs/lab1/graph_queries.py`
- [ ] All tests pass:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab1.test.test_lab_1_2
  ```
- [ ] The script runs and prints results:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab1.graph_queries
  ```
- [ ] Entity counts show non-zero values for Binary, Function, BasicBlock, StringLiteral, ImportSymbol
- [ ] No duplicate binaries found
- [ ] Metadata (classification, tags) is present for benign corpus binaries

---

## Summary

- You wrote Python functions that query the Neo4j program graph using the Neo4j driver.
- You validated graph structure (entity counts, duplicates, relationships, metadata).
- You ran analysis queries (dangerous imports, call graph).
- You experienced the friction of manual Cypher authoring — knowing the schema, syntax, and question are all required.
- **Lab 2 will introduce NL2GQL** to remove the Cypher authoring bottleneck.

---
