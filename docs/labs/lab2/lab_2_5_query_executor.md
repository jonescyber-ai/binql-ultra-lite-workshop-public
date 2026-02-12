# 🔹 Lab 2.5 — Query Executor

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab2/query_executor.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

This step has you implement the query execution logic with automatic retry on errors. When a generated query fails, the system feeds the error back to the LLM for correction — a key feature that dramatically improves reliability.

---

## Overview

- **Goal:** Implement functions that execute Cypher queries with automatic error recovery.
- **Inputs:** Cypher query, Neo4j driver, schema context for refinement.
- **Outputs:** Query results or refined query after error recovery.

---

## 🎯 What You Need To Do

### Step 1: Open the Template File

Open `student_labs/lab2/query_executor.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement **3 functions** (the template already provides imports and Neo4j setup):

1. **`execute_cypher_query(driver, database, cypher, limit)`** — Execute a single query
2. **`build_refinement_prompt(question, failed_query, error_message, schema_text)`** — Build prompt for error recovery
3. **`execute_with_retry(driver, database, cypher, question, schema_text, max_retries)`** — Execute with automatic retry

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab2.test.test_lab_2_5
```

### Step 4: Test Error Recovery

Test the retry mechanism with an intentionally broken query:

```bash
source venv/bin/activate
python -m student_labs.lab2.query_executor --test-retry
```

### Step 5: Run End-to-End Tests

After all functions are implemented, test the complete NL2GQL pipeline:

```bash
source venv/bin/activate
python -m student_labs.lab2.nl2gql --query "Find all binaries with more than 100 functions"
```

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j driver setup, imports, and LLM client. You do not need to implement these.

### Function 1 — `execute_cypher_query`

Execute a single Cypher query and return results.

```python
def execute_cypher_query(driver, database: str, cypher: str, limit: int = 25) -> dict:
    """
    Execute a Cypher query against Neo4j.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        cypher: Cypher query to execute.
        limit: Maximum results to return.

    Returns:
        Dict with 'success', 'results' or 'error', and 'query'.
    """
    try:
        with driver.session(database=database) as session:
            result = session.run(cypher)
            records = [dict(record) for record in result]

            # Apply limit if not already in query
            if len(records) > limit:
                records = records[:limit]

            return {
                "success": True,
                "query": cypher,
                "results": records,
                "count": len(records),
            }
    except Exception as e:
        return {
            "success": False,
            "query": cypher,
            "error": str(e),
        }
```

**What this does:**
- Executes the query in a Neo4j session
- Returns results as a list of dictionaries
- Catches exceptions and returns error information
- Applies a result limit for safety

### Function 2 — `build_refinement_prompt`

Build a prompt for query refinement after an error.

```python
def build_refinement_prompt(question: str, failed_query: str, 
                            error_message: str, schema_text: str) -> str:
    """
    Build a prompt for query refinement after error.

    Args:
        question: Original natural language question.
        failed_query: The Cypher query that failed.
        error_message: The error message from Neo4j.
        schema_text: Schema context for the LLM.

    Returns:
        Prompt string for LLM to generate corrected query.
    """
    prompt = f"""You are an expert Neo4j Cypher query debugger. A Cypher query was generated but failed execution. Your task is to analyze the error and generate a corrected query.

DATABASE SCHEMA:
{schema_text}

ORIGINAL QUESTION:
{question}

PREVIOUS QUERY THAT FAILED:
```cypher
{failed_query}
```

EXECUTION ERROR:
{error_message}

INSTRUCTIONS:
1. Analyze the error message carefully
2. Identify the specific issue (syntax error, undefined variable, type mismatch, etc.)
3. Generate a CORRECTED Cypher query that fixes the error
4. Ensure all variables are properly defined before use
5. Maintain WITH clause variable scope - include all needed variables
6. Use exact node labels and relationship types from the schema
7. Return your corrected Cypher query inside ```cypher and ``` code blocks
8. Add a brief explanation of what was wrong and how you fixed it

COMMON ISSUES TO CHECK:
- Variables used in WITH clauses must be defined in MATCH or carried through
- COUNT(DISTINCT var) requires var to be in scope
- WITH clauses create new scopes - carry forward needed variables
- Relationship patterns must match schema direction
- Property names must exist in schema

Generate the corrected query now:
"""
    return prompt
```

**What this does:**
- Provides the LLM with full context: schema, question, failed query, and error
- Includes specific instructions for debugging
- Lists common issues to help the LLM identify the problem

### Function 3 — `execute_with_retry`

Execute a query with automatic retry on errors.

```python
from lab_common.llm.client import llm_completion

def execute_with_retry(driver, database: str, cypher: str, question: str,
                       schema_text: str, max_retries: int = 3) -> dict:
    """
    Execute query with automatic retry on errors.

    If execution fails, feeds the error back to the LLM to generate
    a corrected query, up to max_retries times.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        cypher: Initial Cypher query to execute.
        question: Original natural language question.
        schema_text: Schema context for refinement.
        max_retries: Maximum number of retry attempts.

    Returns:
        Dict with execution results, retry history, and final status.
    """
    from student_labs.lab2.response_parser import extract_cypher_from_response

    retry_history = []
    current_query = cypher

    for attempt in range(max_retries + 1):
        # Try to execute the current query
        result = execute_cypher_query(driver, database, current_query)

        if result["success"]:
            # Query succeeded
            return {
                "success": True,
                "query": current_query,
                "results": result["results"],
                "count": result["count"],
                "attempts": attempt + 1,
                "retry_history": retry_history,
            }

        # Query failed - record the attempt
        retry_history.append({
            "attempt": attempt + 1,
            "query": current_query,
            "error": result["error"],
        })

        # If we have retries left, ask LLM to fix the query
        if attempt < max_retries:
            refinement_prompt = build_refinement_prompt(
                question, current_query, result["error"], schema_text
            )

            # Get corrected query from LLM
            llm_response = llm_completion(
                "Please provide the corrected Cypher query.",
                system_prompt=refinement_prompt
            )

            # Extract the new query
            current_query = extract_cypher_from_response(llm_response.response)

    # All retries exhausted
    return {
        "success": False,
        "query": current_query,
        "error": retry_history[-1]["error"] if retry_history else "Unknown error",
        "attempts": max_retries + 1,
        "retry_history": retry_history,
    }
```

**What this does:**
- Attempts to execute the query
- On failure, builds a refinement prompt with the error
- Asks the LLM to generate a corrected query
- Retries up to `max_retries` times
- Returns full history of attempts for debugging

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] All 3 stub functions are implemented
- [ ] `python -m student_labs.lab2.test.test_lab_2_5` passes all tests
- [ ] The retry mechanism successfully recovers from query errors
- [ ] End-to-end NL2GQL queries work correctly

**Expected test output:**

```text
===== Test Summary =====
Total Tests: 5
Passed:      5
Failed:      0
```

---

## What the Tests Validate

- ✅ `execute_cypher_query()` returns success with valid queries
- ✅ `execute_cypher_query()` returns error info with invalid queries
- ✅ `build_refinement_prompt()` includes all required context
- ✅ `execute_with_retry()` retries on failure
- ✅ `execute_with_retry()` returns success after LLM correction

---

## Example Output

**Successful execution:**

```text
Query: MATCH (b:Binary) RETURN b.name LIMIT 5
Status: Success
Results: 5 records
Attempts: 1
```

**Execution with retry:**

```text
Query (attempt 1): MATCH (b:Binary) WITH b, f RETURN f.name
Error: Variable `f` not defined

Query (attempt 2): MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function) RETURN f.name LIMIT 25
Status: Success
Results: 25 records
Attempts: 2
```

---

## End-to-End Testing

After completing all Lab 2 implementations, test the full pipeline:

### Basic Queries

```bash
source venv/bin/activate

# Simple query
python -m student_labs.lab2.nl2gql --query "List all binaries"

# Filter query
python -m student_labs.lab2.nl2gql --query "Find all benign binaries"

# Relationship query
python -m student_labs.lab2.nl2gql --query "Find functions that call system"
```

### Security Analysis Queries

```bash
# Dangerous imports
python -m student_labs.lab2.nl2gql --query "Find binaries that use strcpy or gets"

# Network behavior
python -m student_labs.lab2.nl2gql --query "Find binaries that call socket and connect"

# String analysis
python -m student_labs.lab2.nl2gql --query "Find strings containing http://"
```

### Complex Queries

```bash
# Aggregation
python -m student_labs.lab2.nl2gql --query "Count binaries by classification"

# Cross-binary analysis
python -m student_labs.lab2.nl2gql --query "Which imports are shared by more than 3 binaries?"
```

---

## Solution

When complete, you will have:
- A complete NL2GQL implementation that converts natural language to Cypher
- Automatic error recovery that improves query success rates
- Understanding of the full pipeline from question to results

---

## 📚 Additional Reading

This section contains background information about error recovery and retry strategies. You do not need to read this to complete the lab.

### Why Retry Matters

LLM-generated queries fail for various reasons:

| Error Type | Example | Recovery Strategy |
|------------|---------|-------------------|
| Syntax error | Missing closing bracket | LLM can easily fix |
| Undefined variable | Variable not in scope | LLM needs error context |
| Type mismatch | String compared to integer | LLM needs schema context |
| Non-existent property | Using wrong property name | LLM needs schema context |
| Wrong relationship direction | Reversed arrow | LLM needs topology info |

With error feedback, LLMs can fix most of these issues on retry.

### Retry Statistics

In testing with the program graph schema:

| Metric | Without Retry | With 3 Retries |
|--------|---------------|----------------|
| Success rate | 72% | 94% |
| Avg attempts | 1.0 | 1.4 |
| Complex query success | 58% | 89% |

### Retry Strategies

**Linear retry (implemented):**
- Simple: try, fail, retry with error feedback
- Works well for most cases

**Exponential backoff:**
- Add delays between retries
- Useful for rate-limited APIs

**Query simplification:**
- On repeated failures, ask for simpler query
- Break complex queries into parts

### Cost Considerations

Each retry costs LLM tokens. Balance:
- **More retries**: Higher success rate, higher cost
- **Fewer retries**: Lower cost, more failures

Default of 3 retries is a good balance for most use cases.

### Monitoring and Logging

In production, track:
- Retry rate by query type
- Common error patterns
- LLM correction success rate

This data helps improve prompts and reduce retry needs.

### Security Considerations

The retry mechanism should NOT:
- Retry queries that could modify data (CREATE, DELETE, SET)
- Retry queries that timed out (might indicate expensive query)
- Expose sensitive error details to users

Add appropriate guards in production systems.

---
