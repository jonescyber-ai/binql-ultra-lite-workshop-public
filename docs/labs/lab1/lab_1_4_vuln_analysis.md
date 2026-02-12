# 🔹 Lab 1.4 — Vulnerability Analysis Script

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab1/vuln_analysis.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

This step builds on Lab 1.3 by focusing on **code-level vulnerability indicators** rather than malware behavior.

---

## Overview

- **Goal:** Write a Python script that takes a binary SHA256, queries the Neo4j graph, and outputs a vulnerability assessment.
- **Inputs:** Binary SHA256, Neo4j credentials (from `binql_config.yaml` or environment variables).
- **Outputs:** A text/JSON report containing:
  - Buffer-overflow-prone functions (`strcpy`, `sprintf`, `gets`, `strcat`)
  - Format-string sinks (`printf`, `fprintf`, `syslog` with user input)
  - Memory management issues (`malloc`/`free` patterns)
  - Call depth to risky functions (how many hops from entry to sink)
  - Vulnerability severity rating

---

## 🎯 What You Need To Do

### Step 1: Open the Template File

Open `student_labs/lab1/vuln_analysis.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement these functions:

1. **`get_binary_info(driver, database, sha256)`** — Query basic binary information
2. **`get_buffer_overflow_imports(driver, database, sha256)`** — Query buffer-overflow-prone imports
3. **`get_format_string_imports(driver, database, sha256)`** — Query format string sinks
4. **`get_memory_imports(driver, database, sha256)`** — Query memory management imports with call counts
5. **`get_call_depth_to_sinks(driver, database, sha256)`** — Find call paths to dangerous functions
6. **`compute_vuln_severity(buffer_imports, format_imports, call_paths)`** — Compute severity level

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab1.test.test_lab_1_4
```

### Step 4: Run the Script

Test your implementation against the Bison binary:

```bash
source venv/bin/activate
python -m student_labs.lab1.vuln_analysis \
  --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd
```

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j connection setup, the constants `BUFFER_OVERFLOW_IMPORTS`, `FORMAT_STRING_IMPORTS`, `MEMORY_IMPORTS`, and `HIGH_RISK_FUNCTIONS`, report generation functions (`generate_report`, `generate_json_report`), and CLI handling. You do not need to implement these.

### Function 1 — `get_binary_info`

Run a Cypher query to get binary name, architecture, function count.

```python
def get_binary_info(driver, database: str, sha256: str) -> dict:
    """Query basic binary information."""
    query = """
    MATCH (b:Binary {sha256: $sha256})
    OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(f:Function)
    RETURN b.name AS name,
           b.architecture AS architecture,
           count(DISTINCT f) AS function_count
    """
    with driver.session(database=database) as session:
        result = session.run(query, sha256=sha256)
        record = result.single()
        if record is None or record["name"] is None:
            return None
        return record.data()
```

### Function 2 — `get_buffer_overflow_imports`

Look for classic unsafe C functions. The `BUFFER_OVERFLOW_IMPORTS` constant is already defined at module level in the template.

```python
def get_buffer_overflow_imports(driver, database: str, sha256: str) -> list:
    """Query imports that may cause buffer overflows."""
    query = """
    MATCH (b:Binary {sha256: $sha256})-[:HAS_FUNCTION]->(:Function)
          -[:ENTRY_BLOCK|ORPHAN_BLOCK]->(:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE imp.name IN $vuln_imports
    RETURN DISTINCT imp.name AS import_name
    ORDER BY imp.name
    """
    with driver.session(database=database) as session:
        result = session.run(query, sha256=sha256, vuln_imports=BUFFER_OVERFLOW_IMPORTS)
        return [r["import_name"] for r in result]
```

### Function 3 — `get_format_string_imports`

Look for printf-family functions that could be exploited. The `FORMAT_STRING_IMPORTS` constant is already defined at module level in the template.

```python
def get_format_string_imports(driver, database: str, sha256: str) -> list:
    """Query imports that may be format string sinks."""
    query = """
    MATCH (b:Binary {sha256: $sha256})-[:HAS_FUNCTION]->(:Function)
          -[:ENTRY_BLOCK|ORPHAN_BLOCK]->(:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE imp.name IN $format_imports
    RETURN DISTINCT imp.name AS import_name
    ORDER BY imp.name
    """
    with driver.session(database=database) as session:
        result = session.run(query, sha256=sha256, format_imports=FORMAT_STRING_IMPORTS)
        return [r["import_name"] for r in result]
```

### Function 4 — `get_memory_imports`

Track malloc/free/realloc usage for potential use-after-free or double-free. The `MEMORY_IMPORTS` constant is already defined at module level in the template.

```python
def get_memory_imports(driver, database: str, sha256: str) -> list:
    """Query memory management imports."""
    query = """
    MATCH (b:Binary {sha256: $sha256})-[:HAS_FUNCTION]->(:Function)
          -[:ENTRY_BLOCK|ORPHAN_BLOCK]->(:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE imp.name IN $memory_imports
    RETURN imp.name AS import_name, count(*) AS call_count
    ORDER BY call_count DESC
    """
    with driver.session(database=database) as session:
        result = session.run(query, sha256=sha256, memory_imports=MEMORY_IMPORTS)
        return [{"name": r["import_name"], "count": r["call_count"]} for r in result]
```

### Function 5 — `get_call_depth_to_sinks`

Find shortest paths from entry points to vulnerable sinks.

```python
def get_call_depth_to_sinks(driver, database: str, sha256: str, max_depth: int = 5) -> list:
    """Find call paths from entry functions to dangerous imports."""
    # Note: Neo4j doesn't support parameterized variable-length paths,
    # so we use a fixed depth of 1..5 and filter in post-processing if needed.
    query = """
    MATCH (b:Binary {sha256: $sha256})-[:HAS_FUNCTION]->(f:Function)
    WHERE f.name IN ['main', '_start', 'entry']
    MATCH path = (f)-[:CALLS_FUNCTION*1..5]->(sink:Function)
          -[:ENTRY_BLOCK|ORPHAN_BLOCK]->(:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE imp.name IN ['strcpy', 'gets', 'sprintf', 'system']
    RETURN f.name AS entry_func, 
           [n IN nodes(path) | n.name] AS call_path,
           imp.name AS sink_import,
           length(path) AS depth
    ORDER BY depth ASC
    LIMIT 10
    """
    with driver.session(database=database) as session:
        result = session.run(query, sha256=sha256)
        paths = [dict(r) for r in result]
        if max_depth != 5:
            paths = [p for p in paths if p.get('depth', 0) <= max_depth]
        return paths
```

### Function 6 — `compute_vuln_severity`

Combine findings into a severity rating. The `HIGH_RISK_FUNCTIONS` constant (used for scoring) is already defined at module level in the template.

```python
def compute_vuln_severity(buffer_imports: list, format_imports: list, 
                          call_paths: list) -> str:
    """Compute vulnerability severity based on findings."""
    score = 0
    
    # High-risk buffer overflow functions
    high_risk = {'gets', 'strcpy', 'strcat', 'sprintf'}
    score += len([i for i in buffer_imports if i in high_risk]) * 3
    
    # Medium-risk functions
    score += len(buffer_imports) + len(format_imports)
    
    # Short call paths are more exploitable
    short_paths = [p for p in call_paths if p.get('depth', 99) <= 3]
    score += len(short_paths) * 2
    
    if score >= 12:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"
```

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] All stub functions are implemented
- [ ] `python -m student_labs.lab1.test.test_lab_1_4` passes all tests
- [ ] Running the script produces a vulnerability analysis report

**Expected test output:**

```text
===== Test Summary =====
Total Tests: 8
Passed:      8
Failed:      0
```

---

## What the Tests Validate

- ✅ Script can connect to Neo4j using `get_neo4j_credentials()`
- ✅ `get_binary_info()` returns expected fields (name, architecture, function_count)
- ✅ `get_buffer_overflow_imports()` returns a list of import names
- ✅ `get_format_string_imports()` returns a list of import names
- ✅ `get_memory_imports()` returns import names with call counts
- ✅ `get_call_depth_to_sinks()` returns call path information
- ✅ `compute_vuln_severity()` returns valid severity levels
- ✅ CLI runs without error and produces output

---

## Example Output

```text
=== VULNERABILITY ANALYSIS REPORT ===
SHA256: 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd
Name: bison_arm
Architecture: ARM

--- Summary ---
Functions:       958
Vulnerable Imports: 5
Call Paths to Sinks: 12

--- Buffer Overflow Risk ---
  • strcpy (no bounds checking)
  • strcat (no bounds checking)
  • sprintf (no bounds checking)
  • gets (deprecated, always vulnerable)

--- Format String Risk ---
  • printf (potential format string vulnerability)
  • fprintf (potential format string vulnerability)

--- Memory Management ---
  • malloc (12 calls)
  • free (8 calls)
  • realloc (2 calls)

--- Call Depth Analysis ---
  • main -> parse_input -> strcpy: 2 hops
  • main -> process_data -> sprintf: 2 hops
  • handle_request -> gets: 1 hop

--- Vulnerability Severity ---
Severity: HIGH
  - 4 buffer overflow risks
  - 2 format string risks
  - Short call paths to dangerous functions

--- Recommendations ---
  • Replace strcpy/strcat with strncpy/strncat
  • Replace sprintf with snprintf
  • Remove gets() entirely (use fgets)
  • Audit printf/fprintf for user-controlled format strings
```

---

## Solution

When complete, you will have:
- A working vulnerability analysis script that programmatically queries the Neo4j graph.
- The script focuses on **code-level vulnerability indicators** (buffer overflows, format strings, memory issues).
- You understand how to use graph traversal to find call paths to dangerous sinks.
- Combined with Lab 1.3, you now have two complementary analysis tools: one for malware triage, one for vulnerability assessment.

---

