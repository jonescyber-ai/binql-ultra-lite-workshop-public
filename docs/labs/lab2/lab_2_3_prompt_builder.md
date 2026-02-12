# 🔹 Lab 2.3 — Prompt Builder

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab2/prompt_builder.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

This step has you implement the prompt building functions that combine schema metadata with instructions to create effective LLM prompts for Cypher generation.

---

## Overview

- **Goal:** Implement functions that format schema metadata and build system prompts for LLM-based Cypher generation.
- **Inputs:** Schema metadata (nodes, relationships, sample values) from Labs 2.1-2.2.
- **Outputs:** Formatted schema text and complete system prompts ready for LLM consumption.

---

## 🎯 What You Need To Do

### Step 1: Open the Template File

Open `student_labs/lab2/prompt_builder.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement **3 functions** (the template already provides imports and constants):

1. **`format_relationships_for_llm(relationships)`** — Format relationship metadata into readable text
2. **`format_nodes_for_llm(nodes)`** — Format node metadata with properties and sample values
3. **`build_cypher_generation_prompt(schema_text)`** — Build the complete system prompt

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab2.test.test_lab_2_3
```

### Step 4: Verify Output Format

Test your implementation by running:

```bash
source venv/bin/activate
python -m student_labs.lab2.prompt_builder --test
```

This should output a formatted schema and system prompt.

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Imports, type hints, and helper constants. You do not need to implement these.

### Function 1 — `format_relationships_for_llm`

Format relationship metadata into LLM-friendly text showing the graph topology.

```python
def format_relationships_for_llm(relationships: list) -> str:
    """
    Format relationship metadata into LLM-friendly text.

    Args:
        relationships: List of relationship records from APOC.

    Returns:
        Formatted string describing relationship patterns.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("RELATIONSHIP TYPES (Graph Topology)")
    lines.append("=" * 60)
    lines.append("")
    
    # Group by relationship type
    rel_groups = {}
    for rel in relationships:
        rel_type = rel.get("relType", "UNKNOWN")
        if rel_type not in rel_groups:
            rel_groups[rel_type] = []
        rel_groups[rel_type].append(rel)
    
    for rel_type, rels in sorted(rel_groups.items()):
        # Clean the relationship type name
        clean_type = rel_type.replace(":`", "").replace("`", "").replace(":", "")
        lines.append(f"Relationship: {clean_type}")
        
        # Show source -> target patterns
        patterns = set()
        for rel in rels:
            sources = rel.get("sourceNodeLabels", [])
            targets = rel.get("targetNodeLabels", [])
            for src in sources:
                for tgt in targets:
                    patterns.add(f"  ({src})-[:{clean_type}]->({tgt})")
        
        for pattern in sorted(patterns):
            lines.append(pattern)
        lines.append("")
    
    return "\n".join(lines)
```

**What this does:**
- Groups relationships by type
- Shows the valid patterns: which node types can connect via which relationships
- Cleans up APOC formatting for readability

### Function 2 — `format_nodes_for_llm`

Format node metadata with properties and sample values.

```python
def format_nodes_for_llm(nodes: list) -> str:
    """
    Format node metadata into LLM-friendly text.

    Args:
        nodes: List of node records from APOC (optionally enriched with sample values).

    Returns:
        Formatted string describing node labels and their properties.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("NODE LABELS AND PROPERTIES")
    lines.append("=" * 60)
    lines.append("")
    
    # Group by node type
    node_groups = {}
    for node in nodes:
        node_type = node.get("nodeType", "UNKNOWN")
        if node_type not in node_groups:
            node_groups[node_type] = []
        node_groups[node_type].append(node)
    
    for node_type, props in sorted(node_groups.items()):
        # Clean the node type name
        clean_type = node_type.replace(":`", "").replace("`", "").replace(":", "")
        lines.append(f"Node: {clean_type}")
        
        for prop in props:
            prop_name = prop.get("propertyName", "unknown")
            prop_types = prop.get("propertyTypes", [])
            mandatory = prop.get("mandatory", False)
            samples = prop.get("sampleValues", [])
            
            type_str = ", ".join(prop_types) if prop_types else "UNKNOWN"
            req_str = "required" if mandatory else "optional"
            
            lines.append(f"  - {prop_name} ({type_str}, {req_str})")
            
            # Add sample values if available
            if samples:
                # Truncate long values for display
                display_samples = []
                for s in samples[:3]:
                    s_str = str(s)
                    if len(s_str) > 30:
                        s_str = s_str[:27] + "..."
                    display_samples.append(f'"{s_str}"')
                lines.append(f"    Samples: [{', '.join(display_samples)}]")
        
        lines.append("")
    
    return "\n".join(lines)
```

**What this does:**
- Groups properties by node type
- Shows property name, type, and whether it's required
- Includes sample values (truncated for readability)

### Function 3 — `build_cypher_generation_prompt`

Build the complete system prompt for Cypher generation.

```python
def build_cypher_generation_prompt(schema_text: str) -> str:
    """
    Build a system prompt for Cypher query generation.

    Args:
        schema_text: Formatted schema text from format_nodes_for_llm and format_relationships_for_llm.

    Returns:
        Complete system prompt for LLM.
    """
    prompt = f"""You are an expert Neo4j Cypher query generator. Given a natural language question, generate an accurate Cypher query.

DATABASE SCHEMA:
{schema_text}

INSTRUCTIONS:
1. Generate ONLY valid Cypher syntax
2. Use exact node labels and relationship types from the schema
3. Use only properties that exist in the schema
4. Respect property types (STRING, INTEGER, etc.)
5. Follow relationship direction: (Source)-[:TYPE]->(Target)
6. Use MATCH for queries, not CREATE/MERGE unless explicitly asked
7. Return your Cypher query inside ```cypher and ``` code blocks
8. Add a brief explanation after the query
9. Include LIMIT 25 unless the user specifies a different limit

EXAMPLE:
User: "Find all binaries with more than 100 functions"
Assistant:
```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
WITH b, count(f) AS func_count
WHERE func_count > 100
RETURN b.name, b.sha256, func_count
ORDER BY func_count DESC
LIMIT 25
```

This query finds binaries with more than 100 functions and returns their name, SHA256 hash, and function count.
"""
    return prompt
```

**What this does:**
- Embeds the schema as context for the LLM
- Provides clear instructions for query generation
- Includes an example to demonstrate expected format
- Specifies the code block format for easy parsing

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] All 3 stub functions are implemented
- [ ] `python -m student_labs.lab2.test.test_lab_2_3` passes all tests
- [ ] Running the script produces formatted schema and prompt output

**Expected test output:**

```text
===== Test Summary =====
Total Tests: 4
Passed:      4
Failed:      0
```

---

## What the Tests Validate

- ✅ `format_relationships_for_llm()` produces readable relationship patterns
- ✅ `format_nodes_for_llm()` includes property names, types, and sample values
- ✅ `build_cypher_generation_prompt()` includes schema and instructions
- ✅ Generated prompt contains required elements (INSTRUCTIONS, EXAMPLE, code block markers)

---

## Example Output

**Formatted relationships:**

```text
============================================================
RELATIONSHIP TYPES (Graph Topology)
============================================================

Relationship: HAS_FUNCTION
  (Binary)-[:HAS_FUNCTION]->(Function)

Relationship: CALLS_TO
  (BasicBlock)-[:CALLS_TO]->(Function)
  (BasicBlock)-[:CALLS_TO]->(ImportSymbol)

Relationship: IMPORTS_SYMBOL
  (Binary)-[:IMPORTS_SYMBOL]->(ImportSymbol)
```

**Formatted nodes:**

```text
============================================================
NODE LABELS AND PROPERTIES
============================================================

Node: Binary
  - sha256 (STRING, required)
    Samples: ["9409117ee68a2d75...", "06b1035b09478319..."]
  - name (STRING, required)
    Samples: ["bison_arm", "benign_sample"]
  - classification (STRING, optional)
    Samples: ["benign", "unknown"]
```

---

## Solution

When complete, you will have:
- Functions that format schema metadata for LLM consumption
- A system prompt that provides comprehensive context for Cypher generation
- Understanding of effective prompt structure for code generation tasks

---

## 📚 Additional Reading

This section contains background information about prompt engineering for code generation. You do not need to read this to complete the lab.

### Anatomy of an Effective Prompt

An effective NL2GQL prompt has four parts:

```
┌─────────────────────────────────────┐
│ 1. SYSTEM PROMPT                    │
│    - Role definition                │
│    - Schema context                 │
│    - Instructions                   │
├─────────────────────────────────────┤
│ 2. SCHEMA CONTEXT                   │
│    - Node labels & properties       │
│    - Relationship types             │
│    - Sample values                  │
├─────────────────────────────────────┤
│ 3. FEW-SHOT EXAMPLES (optional)     │
│    - Question → Cypher pairs        │
│    - Demonstrate expected format    │
├─────────────────────────────────────┤
│ 4. USER QUESTION                    │
│    - Natural language query         │
└─────────────────────────────────────┘
```

### Why Structure Matters

LLMs perform better when prompts:

1. **Define the role clearly**: "You are an expert Neo4j Cypher query generator"
2. **Provide complete context**: The schema tells the LLM what's possible
3. **Give explicit instructions**: Numbered rules reduce ambiguity
4. **Show examples**: Few-shot learning improves accuracy
5. **Specify output format**: Code blocks make parsing reliable

### Common Prompt Mistakes

| Mistake | Problem | Solution |
|---------|---------|----------|
| No schema context | LLM invents labels/properties | Include full schema |
| Vague instructions | Inconsistent output format | Use numbered rules |
| No examples | LLM guesses format | Add 1-2 examples |
| No output format | Hard to parse response | Specify code blocks |

### Prompt Length Considerations

- **Too short**: Missing context leads to errors
- **Too long**: May exceed token limits, slower responses
- **Optimal**: Include essential schema, trim redundant info

For large schemas, consider:
- Only including relevant node types for the query domain
- Summarizing rarely-used properties
- Caching and reusing schema text

### Testing Prompts

When developing prompts, test with:

1. **Simple queries**: "Find all binaries"
2. **Filter queries**: "Find benign binaries"
3. **Relationship queries**: "Find functions that call system"
4. **Aggregation queries**: "Count binaries by classification"
5. **Complex queries**: "Find binaries with suspicious strings that call network functions"

Track accuracy across these categories to identify prompt weaknesses.

---
