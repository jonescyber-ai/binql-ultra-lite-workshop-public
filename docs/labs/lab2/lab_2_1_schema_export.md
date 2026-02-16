# 🔹 Lab 2.1 — Schema Export

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab2/schema_export.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

This step has you implement functions that extract comprehensive schema metadata from Neo4j using APOC procedures — the foundation for providing LLMs with the context they need to generate accurate Cypher queries.

---

## Overview

- **Goal:** Implement functions that extract graph schema metadata using APOC procedures.
- **Inputs:** Neo4j driver and database name.
- **Outputs:** Structured metadata about node labels, relationships, properties, and constraints.

---

## 🎯 What You Need To Do

### Step 1: Open the Template File

Open `student_labs/lab2/schema_export.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement **3 functions** (the template already provides imports and Neo4j setup):

1. **`export_node_metadata(driver, database)`** — Export node labels and their properties using APOC
2. **`export_relationship_metadata(driver, database)`** — Export relationship types with source/target labels
3. **`export_schema_ddl(driver, database)`** — Export constraints and indexes as Cypher DDL

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab2.test.test_lab_2_1
```

### Step 4: Verify Output

Test your implementation by running:

```bash
source venv/bin/activate
python -m student_labs.lab2.schema_export --test
```

This should output the extracted schema metadata.

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j driver setup, imports, and logging. You do not need to implement these.

### Function 1 — `export_node_metadata`

Export node labels and their properties using APOC's `apoc.meta.nodeTypeProperties()` procedure.

```python
def export_node_metadata(driver, database: str) -> list:
    """
    Export node labels and their properties using APOC.

    Uses APOC's apoc.meta.nodeTypeProperties() to get comprehensive node metadata.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        List of dictionaries containing node metadata with keys:
        - nodeType: The node label (e.g., ":`Binary`")
        - nodeLabels: Array of labels
        - propertyName: Name of each property
        - propertyTypes: Data types (STRING, INTEGER, etc.)
        - mandatory: Whether the property is required
    """
    query = """
        CALL apoc.meta.nodeTypeProperties()
        YIELD nodeType, nodeLabels, propertyName, propertyTypes, mandatory
        RETURN nodeType, nodeLabels, propertyName, propertyTypes, mandatory
        ORDER BY nodeType, propertyName
    """

    with driver.session(database=database) as session:
        result = session.run(query)
        records = [dict(record) for record in result]

    return records
```

**What this does:**
- Calls APOC's metadata procedure to get all node labels and their properties
- Returns structured data about each property's type and whether it's required
- Orders results by node type and property name for consistent output

### Function 2 — `export_relationship_metadata`

Export relationship types with their source and target node labels.

```python
def export_relationship_metadata(driver, database: str) -> list:
    """
    Export relationship types with source/target labels and properties.

    Uses APOC's apoc.meta.relTypeProperties() to get comprehensive relationship metadata.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        List of dictionaries containing relationship metadata with keys:
        - relType: The relationship type (e.g., ":`HAS_FUNCTION`")
        - sourceNodeLabels: Array of source node labels
        - targetNodeLabels: Array of target node labels
        - propertyName: Name of relationship property (if any)
        - propertyTypes: Data types of properties
        - mandatory: Whether the property is required
    """
    query = """
        CALL apoc.meta.relTypeProperties()
        YIELD relType, sourceNodeLabels, targetNodeLabels, propertyName, propertyTypes, mandatory
        RETURN relType, sourceNodeLabels, targetNodeLabels, propertyName, propertyTypes, mandatory
        ORDER BY relType, sourceNodeLabels, targetNodeLabels, propertyName
    """

    with driver.session(database=database) as session:
        result = session.run(query)
        records = [dict(record) for record in result]

    return records
```

**What this does:**
- Calls APOC's relationship metadata procedure
- Returns the graph topology: which node types connect to which via what relationships
- This is crucial for LLMs to understand valid query patterns

### Function 3 — `export_schema_ddl`

Export constraints and indexes as Cypher DDL statements.

```python
def export_schema_ddl(driver, database: str) -> str:
    """
    Export constraints and indexes as Cypher DDL statements.

    Uses APOC's apoc.export.cypher.schema() to get schema as Cypher statements.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        String containing Cypher DDL statements for constraints and indexes.
    """
    query = """
        CALL apoc.export.cypher.schema()
        YIELD cypherStatements
        RETURN cypherStatements
    """

    with driver.session(database=database) as session:
        result = session.run(query)
        record = result.single()
        if record:
            return record["cypherStatements"]
        return ""
```

**What this does:**
- Exports the database schema as Cypher CREATE CONSTRAINT and CREATE INDEX statements
- Helps LLMs understand uniqueness constraints and required properties
- Useful for understanding the data model

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] All 3 stub functions are implemented
- [ ] `python -m student_labs.lab2.test.test_lab_2_1` passes all tests
- [ ] Running the script produces schema metadata output

**Expected test output:**

```text
===== Test Summary =====
Total Tests: 4
Passed:      4
Failed:      0
```

---

## What the Tests Validate

- ✅ All required functions are importable and callable
- ✅ `export_node_metadata()` returns a list of node property records
- ✅ `export_relationship_metadata()` returns a list of relationship records
- ✅ `export_schema_ddl()` returns a string with DDL statements

---

## Example Output

```text
=== NODE METADATA ===
Node Type: :`Binary`
  Properties:
    - sha256 (STRING, required)
    - name (STRING, required)
    - classification (STRING, optional)
    - tags (LIST, optional)

Node Type: :`Function`
  Properties:
    - binary_sha256 (STRING, required)
    - start_address (INTEGER, required)
    - name (STRING, required)
    - total_instructions (INTEGER, optional)

=== RELATIONSHIP METADATA ===
Relationship: :`HAS_FUNCTION`
  Pattern: (Binary) -> (Function)

Relationship: :`CALLS_TO`
  Pattern: (BasicBlock) -> (ImportSymbol)
  Pattern: (BasicBlock) -> (Function)

=== SCHEMA DDL ===
CREATE CONSTRAINT binary_sha256 IF NOT EXISTS FOR (b:Binary) REQUIRE b.sha256 IS UNIQUE;
CREATE CONSTRAINT function_identity IF NOT EXISTS FOR (f:Function) REQUIRE (f.binary_sha256, f.start_address) IS UNIQUE;
...
```

---

## Solution

When complete, you will have:
- Functions that extract comprehensive schema metadata from Neo4j
- Understanding of APOC metadata procedures
- The foundation for schema enrichment in Lab 2.2

---

## 📚 Additional Reading

This section contains background information about APOC and schema metadata. You do not need to read this to complete the lab.

### What is APOC?

APOC (Awesome Procedures On Cypher) is Neo4j's standard library of procedures and functions. It provides:

- **Metadata procedures**: Extract schema information programmatically
- **Data import/export**: Load data from various formats
- **Graph algorithms**: Pathfinding, centrality, community detection
- **Utility functions**: String manipulation, date handling, etc.

### Why Schema Metadata Matters for LLMs

When an LLM generates Cypher queries, it needs to know:

1. **What node labels exist?** (Binary, Function, BasicBlock, etc.)
2. **What properties do they have?** (sha256, name, start_address, etc.)
3. **What are the property types?** (STRING, INTEGER, LIST, etc.)
4. **What relationships connect them?** (HAS_FUNCTION, CALLS_TO, etc.)
5. **What direction do relationships go?** ((Binary)-[:HAS_FUNCTION]->(Function))

Without this context, the LLM might:
- Use non-existent labels or properties
- Use wrong property types in comparisons
- Create invalid relationship patterns

### APOC Metadata Procedures

| Procedure | Purpose |
|-----------|---------|
| `apoc.meta.nodeTypeProperties()` | Get all node labels and their properties |
| `apoc.meta.relTypeProperties()` | Get all relationship types and their properties |
| `apoc.meta.schema()` | Get a map representation of the schema |
| `apoc.export.cypher.schema()` | Export schema as Cypher DDL |

### Verifying APOC is Installed

You can verify APOC is available by running:

```cypher
RETURN apoc.version() AS apoc_version;
```

If this returns a version string (e.g., `"5.x.x"`), APOC is installed and ready to use.

### Manual Schema Exploration

You can also explore the schema manually in Neo4j Browser:

```cypher
-- Visualize the schema
CALL db.schema.visualization();

-- List all constraints
SHOW CONSTRAINTS;

-- List all indexes
SHOW INDEXES;

-- Count nodes by label
MATCH (n)
RETURN labels(n) AS labels, count(*) AS count
ORDER BY count DESC;
```

---
