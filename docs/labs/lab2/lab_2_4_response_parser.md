# 🔹 Lab 2.4 — Response Parser

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab2/response_parser.py` to complete this lab.
>
> ⚠️ **This lab requires writing code and running tests.** Follow the "🎯 What You Need To Do" section, then use the "📚 Implementation Guide" for detailed guidance on each function.

This step has you implement functions that extract Cypher queries from LLM responses. LLMs return free-form text, so robust parsing is essential for reliable query execution.

---

## Overview

- **Goal:** Implement functions that extract Cypher queries from LLM text responses.
- **Inputs:** Raw LLM response text containing Cypher in code blocks.
- **Outputs:** Clean, executable Cypher query strings.

---

## 🎯 What You Need To Do

### Step 1: Open the Template File

Open `student_labs/lab2/response_parser.py` and find the stub markers:

```text
### YOUR CODE HERE ###
...
### END YOUR CODE HERE ###
```

### Step 2: Implement the Required Functions

You need to implement **3 functions** (the template already provides imports):

1. **`extract_cypher_from_response(response_text)`** — Extract Cypher from code blocks
2. **`validate_cypher_basic(cypher)`** — Basic syntax validation
3. **`clean_cypher_query(cypher)`** — Clean and normalize the query

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab2.test.test_lab_2_4
```

### Step 4: Test with Sample Responses

Test your parser with various LLM response formats:

```bash
source venv/bin/activate
python -m student_labs.lab2.response_parser --test
```

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Imports and regex patterns. You do not need to implement these.

### Function 1 — `extract_cypher_from_response`

Extract Cypher query from LLM response text. Handle multiple code block formats.

```python
import re

def extract_cypher_from_response(response_text: str) -> str:
    """
    Extract Cypher query from LLM response.

    Looks for Cypher code blocks marked with ```cypher or ```

    Args:
        response_text: Raw LLM response text.

    Returns:
        Extracted Cypher query string, or empty string if not found.
    """
    # Try to find code blocks with cypher language marker
    cypher_pattern = r"```cypher\s*(.*?)\s*```"
    match = re.search(cypher_pattern, response_text, re.DOTALL | re.IGNORECASE)

    if match:
        return match.group(1).strip()

    # Try to find any code block
    code_pattern = r"```\s*(.*?)\s*```"
    match = re.search(code_pattern, response_text, re.DOTALL)

    if match:
        return match.group(1).strip()

    # If no code block found, return the entire response (might be just the query)
    return response_text.strip()
```

**What this does:**
- First tries to find code blocks specifically marked as `cypher`
- Falls back to any code block if no cypher-specific block found
- Returns the full response if no code blocks exist (some LLMs return raw queries)

### Function 2 — `validate_cypher_basic`

Perform basic validation of Cypher query syntax.

```python
def validate_cypher_basic(cypher: str) -> bool:
    """
    Basic validation of Cypher query syntax.

    Checks for common Cypher keywords and basic structure.
    This is NOT a full syntax validator - just catches obvious issues.

    Args:
        cypher: Cypher query string.

    Returns:
        True if query appears valid, False otherwise.
    """
    if not cypher or not cypher.strip():
        return False

    cypher_upper = cypher.upper()

    # Must contain at least one Cypher keyword
    keywords = ["MATCH", "RETURN", "CREATE", "MERGE", "DELETE", "SET", "WITH", "CALL"]
    has_keyword = any(kw in cypher_upper for kw in keywords)

    if not has_keyword:
        return False

    # Basic bracket matching
    if cypher.count("(") != cypher.count(")"):
        return False
    if cypher.count("[") != cypher.count("]"):
        return False
    if cypher.count("{") != cypher.count("}"):
        return False

    return True
```

**What this does:**
- Checks for presence of Cypher keywords
- Validates bracket matching (parentheses, square brackets, curly braces)
- Returns False for obviously invalid queries

### Function 3 — `clean_cypher_query`

Clean and normalize the Cypher query.

```python
def clean_cypher_query(cypher: str) -> str:
    """
    Clean and normalize a Cypher query.

    Removes comments, extra whitespace, and normalizes formatting.

    Args:
        cypher: Raw Cypher query string.

    Returns:
        Cleaned Cypher query.
    """
    if not cypher:
        return ""

    # Remove single-line comments (// ...)
    lines = cypher.split("\n")
    cleaned_lines = []
    for line in lines:
        # Remove inline comments
        if "//" in line:
            line = line.split("//")[0]
        cleaned_lines.append(line.strip())

    # Join and normalize whitespace
    result = " ".join(line for line in cleaned_lines if line)

    # Normalize multiple spaces to single space
    result = re.sub(r"\s+", " ", result)

    return result.strip()
```

**What this does:**
- Removes single-line comments (`// ...`)
- Strips extra whitespace
- Normalizes the query to a single line (optional, but helps with logging)

---

## ✅ Success Criteria

You have completed this lab when:
- [ ] All 3 stub functions are implemented
- [ ] `python -m student_labs.lab2.test.test_lab_2_4` passes all tests
- [ ] Running the test script correctly parses various response formats

**Expected test output:**

```text
===== Test Summary =====
Total Tests: 5
Passed:      5
Failed:      0
```

---

## What the Tests Validate

- ✅ `extract_cypher_from_response()` extracts from ` ```cypher ` blocks
- ✅ `extract_cypher_from_response()` extracts from generic ` ``` ` blocks
- ✅ `extract_cypher_from_response()` handles responses without code blocks
- ✅ `validate_cypher_basic()` accepts valid queries and rejects invalid ones
- ✅ `clean_cypher_query()` removes comments and normalizes whitespace

---

## Example Output

**Input (LLM response):**

```text
Here's a Cypher query to find all binaries with their function counts:

```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
// Return binary info and function count
RETURN b.name, b.sha256, count(f) AS func_count
ORDER BY func_count DESC
LIMIT 25
```

This query counts functions per binary and returns them sorted by function count.
```

**Output (extracted and cleaned):**

```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function) RETURN b.name, b.sha256, count(f) AS func_count ORDER BY func_count DESC LIMIT 25
```

---

## Solution

When complete, you will have:
- Functions that reliably extract Cypher from various LLM response formats
- Basic validation to catch obviously malformed queries
- Query cleaning for consistent formatting

---

## 📚 Additional Reading

This section contains background information about parsing LLM responses. You do not need to read this to complete the lab.

### Why Parsing is Challenging

LLMs don't always follow instructions perfectly. You might receive:

1. **Well-formatted response:**
   ````
   ```cypher
   MATCH (b:Binary) RETURN b
   ```
   ````

2. **Generic code block:**
   ````
   ```
   MATCH (b:Binary) RETURN b
   ```
   ````

3. **No code block:**
   ```
   MATCH (b:Binary) RETURN b
   ```

4. **Multiple code blocks:**
   ````
   Here's one approach:
   ```cypher
   MATCH (b:Binary) RETURN b
   ```
   Or alternatively:
   ```cypher
   MATCH (b:Binary) RETURN b.name
   ```
   ````

5. **Explanation mixed in:**
   ````
   ```cypher
   // Find all binaries
   MATCH (b:Binary)
   RETURN b  // Return the full node
   ```
   ````

Your parser needs to handle all these cases gracefully.

### Regex Patterns Explained

The pattern `r"```cypher\s*(.*?)\s*```"` breaks down as:

| Part | Meaning |
|------|---------|
| ` ``` ` | Literal backticks |
| `cypher` | Language marker |
| `\s*` | Optional whitespace |
| `(.*?)` | Capture group (non-greedy) |
| `re.DOTALL` | `.` matches newlines |

### Validation Strategies

The basic validation in this lab catches obvious errors. Production systems might add:

1. **AST parsing**: Use a Cypher parser library
2. **EXPLAIN validation**: Run `EXPLAIN <query>` in Neo4j
3. **Schema validation**: Check that labels/properties exist
4. **Security checks**: Block dangerous operations (DELETE, DROP)

### Handling Multiple Queries

If the LLM returns multiple queries, you have options:

1. **Take the first**: Simple, usually correct
2. **Take the last**: Sometimes LLMs refine as they go
3. **Ask for clarification**: Return all options to the user
4. **Validate all**: Run validation and pick the first valid one

### Error Recovery

When parsing fails, consider:

1. **Retry with clarification**: Ask the LLM to format correctly
2. **Fuzzy extraction**: Look for MATCH/RETURN patterns anywhere
3. **User intervention**: Show the raw response and ask for help

---
