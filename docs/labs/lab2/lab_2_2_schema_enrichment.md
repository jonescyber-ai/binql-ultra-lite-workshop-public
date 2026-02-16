# 🔹 Lab 2.2 — Schema Enrichment

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab2/schema_enrichment.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

This step has you implement functions that enrich schema metadata with sample property values — dramatically improving LLM query generation accuracy by showing what values are actually valid.

---

## Overview

- **Goal:** Implement functions that add sample property values to schema metadata.
- **Inputs:** Neo4j driver, database name, and node metadata from Lab 2.1.
- **Outputs:** Enriched schema with sample values for each property.

---

## 🎯 What You Need To Do

### Step 1: Open the Template File

Open `student_labs/lab2/schema_enrichment.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement **2 functions** (the template already provides imports and helpers):

1. **`get_sample_values(driver, database, label, property_name, max_samples)`** — Query sample values for a specific property
2. **`enrich_node_properties(driver, database, nodes, max_samples)`** — Add sample values to all node properties

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab2.test.test_lab_2_2
```

### Step 4: Compare Enriched vs Raw Schema

Test your implementation by running:

```bash
source venv/bin/activate
python -m student_labs.lab2.schema_enrichment --compare
```

This shows the difference between raw and enriched schema output.

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j driver setup, imports, and the `export_node_metadata()` function from Lab 2.1. You do not need to implement these.

### Function 1 — `get_sample_values`

Query sample values for a specific property on a specific node label.

```python
def get_sample_values(driver, database: str, label: str, property_name: str, 
                      max_samples: int = 5) -> list:
    """
    Query sample values for a specific property.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        label: Node label (e.g., "Binary").
        property_name: Property name (e.g., "classification").
        max_samples: Maximum number of sample values to return.

    Returns:
        List of sample values (strings, integers, etc.).
    """
    # Clean the label - remove backticks and colons if present
    clean_label = label.replace(":`", "").replace("`", "").replace(":", "")
    
    query = f"""
        MATCH (n:{clean_label})
        WHERE n.{property_name} IS NOT NULL
        RETURN DISTINCT n.{property_name} AS value
        LIMIT $max_samples
    """

    with driver.session(database=database) as session:
        result = session.run(query, max_samples=max_samples)
        values = [record["value"] for record in result]

    return values
```

**What this does:**
- Queries the database for distinct values of a specific property
- Limits results to avoid returning too many samples
- Handles label formatting from APOC output (removes backticks/colons)

**Important:** The label from APOC comes in format `":\`Binary\`"` but Cypher queries need just `Binary`.

### Function 2 — `enrich_node_properties`

Add sample values to all properties in the node metadata.

```python
def enrich_node_properties(driver, database: str, nodes: list, 
                           max_samples: int = 5) -> list:
    """
    Add sample values to node property metadata.

    Takes the output from export_node_metadata() and enriches each property
    with sample values from the database.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        nodes: List of node metadata records from export_node_metadata().
        max_samples: Maximum number of sample values per property.

    Returns:
        Enriched list with 'sampleValues' added to each record.
    """
    enriched = []
    
    for node in nodes:
        # Create a copy to avoid modifying the original
        enriched_node = dict(node)
        
        # Get the label and property name
        label = node.get("nodeType", "")
        property_name = node.get("propertyName", "")
        
        if label and property_name:
            # Get sample values for this property
            samples = get_sample_values(
                driver, database, label, property_name, max_samples
            )
            enriched_node["sampleValues"] = samples
        else:
            enriched_node["sampleValues"] = []
        
        enriched.append(enriched_node)
    
    return enriched
```

**What this does:**
- Iterates through all node property records from Lab 2.1
- For each property, queries the database for sample values
- Adds a `sampleValues` key to each record
- Returns the enriched metadata

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] Both stub functions are implemented
- [ ] `python -m student_labs.lab2.test.test_lab_2_2` passes all tests
- [ ] Running the comparison shows enriched output with sample values

**Expected test output:**

```text
===== Test Summary =====
Total Tests: 3
Passed:      3
Failed:      0
```

---

## What the Tests Validate

- ✅ All required functions are importable and callable
- ✅ `get_sample_values()` returns a list of values for known properties
- ✅ `enrich_node_properties()` adds `sampleValues` to each record

---

## Example Output

**Before enrichment (raw schema):**

```text
Property: classification
  Type: String
  Required: false
```

**After enrichment:**

```text
Property: classification
  Type: String
  Required: false
  Sample Values: ["benign", "suspicious", "unknown"]
```

**Full comparison output:**

```text
=== RAW SCHEMA (without enrichment) ===
Node: Binary
  - sha256 (STRING, required)
  - name (STRING, required)
  - classification (STRING, optional)

=== ENRICHED SCHEMA (with sample values) ===
Node: Binary
  - sha256 (STRING, required)
    Samples: ["9409117ee68a2d75...", "06b1035b09478319..."]
  - name (STRING, required)
    Samples: ["bison_arm", "benign_sample", "benign_sample"]
  - classification (STRING, optional)
    Samples: ["benign", "unknown"]
```

---

## Solution

When complete, you will have:
- Functions that enrich schema metadata with real sample values
- Understanding of why sample values improve LLM accuracy
- The foundation for building effective prompts in Lab 2.3

---

## 📚 Additional Reading

This section contains background information about schema enrichment. You do not need to read this to complete the lab.

### Why Enrichment Matters

Consider this property without enrichment:

```text
Property: classification
  Type: String
  Required: false
```

The LLM knows `classification` is a String, but doesn't know what values are valid. It might generate:

```cypher
WHERE b.classification = "bad"  -- Wrong! "bad" isn't a valid value
```

With enrichment:

```text
Property: classification
  Type: String
  Required: false
  Sample Values: ["benign", "suspicious", "unknown"]
```

Now the LLM can generate:

```cypher
WHERE b.classification = "benign"  -- Correct!
```

### Impact on Query Accuracy

In testing, schema enrichment improves LLM query accuracy by 30-50% for queries involving:

- **Enum-like properties**: classification, tags, exit_type
- **Pattern matching**: SHA256 hashes, function names
- **Relationship traversal**: Understanding what connects to what

### Performance Considerations

Enrichment adds database queries for each property. For large schemas:

- **Default `max_samples=5`**: Good balance of context vs. query time
- **Increase for enum properties**: Properties with few distinct values benefit from more samples
- **Decrease for high-cardinality properties**: SHA256 hashes don't need many samples

### Caching Enriched Schemas

In production, you might cache the enriched schema:

```python
# Pseudo-code for caching
def get_enriched_schema(driver, database, cache_ttl=3600):
    cache_key = f"schema:{database}"
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    nodes = export_node_metadata(driver, database)
    enriched = enrich_node_properties(driver, database, nodes)
    cache.set(cache_key, enriched, ttl=cache_ttl)
    return enriched
```

### Sample Value Selection

The current implementation uses `DISTINCT ... LIMIT` which returns arbitrary samples. For better results, you could:

1. **Prioritize common values**: Use `ORDER BY count(*) DESC`
2. **Include edge cases**: Sample both typical and unusual values
3. **Respect privacy**: Avoid sampling sensitive data

---
