# 🔹 Lab 3.2 — Source-to-Sink Path Analysis: Tracing Exploitable Code Flows

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab3/source_to_sink_analysis.py` to complete this lab.
>
> 📁 **Student File:** `student_labs/lab3/source_to_sink_analysis.py`

**Finding input sources (Lab 3.1) is only half the story.** A buffer overflow vulnerability requires two things: (1) attacker-controlled input, and (2) that input reaching a dangerous sink like `strcpy` or `sprintf`. This lab connects the dots by tracing CFG paths from Lab 3.1's input sources to dangerous sinks.

---

## Overview

- **Goal:** Implement functions that find CFG paths from user-controlled input sources to dangerous sinks
- **Inputs:** Binaries ingested in Neo4j from the Lab 3 Setup
- **Outputs:** Functions that return `SourceToSinkPath` objects identifying exploitable code flows

### The Big Picture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOURCE-TO-SINK ANALYSIS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Lab 3.1 SOURCES                    Lab 3.2 SINKS              │
│   (Where input enters)               (Where danger lives)        │
│                                                                  │
│   ┌─────────┐                        ┌─────────────────┐        │
│   │ Network │──┐                 ┌──▶│ Buffer Overflow │        │
│   │  recv() │  │                 │   │ strcpy, sprintf │        │
│   └─────────┘  │   ┌─────────┐   │   └─────────────────┘        │
│   ┌─────────┐  ├──▶│  CFG    │───┤                              │
│   │  File   │  │   │  PATH   │   │   ┌─────────────────┐        │
│   │ fread() │──┤   └─────────┘   ├──▶│ Format String   │        │
│   └─────────┘  │                 │   │ printf, syslog  │        │
│   ┌─────────┐  │                 │   └─────────────────┘        │
│   │  Stdin  │──┘                 │                              │
│   │ scanf() │                    │   ┌─────────────────┐        │
│   └─────────┘                    └──▶│ Command Inject  │        │
│                                      │ system, popen   │        │
│   THIS LAB ◀─────────────────────────└─────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Matters

Functions that have **both** an input source AND a path to a dangerous sink are the highest-priority targets for vulnerability analysis. This is the core of taint analysis—tracking how untrusted data flows through the program.

---

## 🎯 What You Need To Do

### Step 1: Open the Student Module

Open the source-to-sink analysis module in your editor:

```bash
# View the module
cat student_labs/lab3/source_to_sink_analysis.py
```

The module provides:
- `run_query()` - Helper function to execute Cypher queries (already implemented)
- `SourceToSinkPath` - Dataclass for structured results (already implemented)
- `_convert_to_source_to_sink_paths()` - Converts query results to SourceToSinkPath objects (already implemented)
- Sink API lists (`BUFFER_OVERFLOW_SINKS`, `FORMAT_STRING_SINKS`, etc.) - Pre-defined at module level
- 7 functions with `### YOUR CODE HERE ###` placeholders for you to fill in

### Step 2: Implement the Required Functions

You need to implement these functions:

**Source-to-Sink Path Detection:**
1. **`_find_source_to_sink_paths_base()`** — Core CFG path query from sources to sinks (implement once, used by all detection functions)
2. **`find_buffer_overflow_paths()`** — Find paths to buffer overflow sinks (strcpy, sprintf, memcpy)
3. **`find_format_string_paths()`** — Find paths to format string sinks (printf, syslog)
4. **`find_command_injection_paths()`** — Find paths to command injection sinks (system, popen, exec*)
5. **`find_path_traversal_paths()`** — Find paths to path traversal sinks (fopen, open, CreateFile)

**LLM-Based Sink Classification (discover sinks not in hardcoded lists):**
6. **`classify_sink_api_with_llm()`** — LLM-based classification for a single API as a dangerous sink
7. **`classify_sink_apis_batch_with_llm()`** — Batch classification of multiple APIs for efficiency

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the module to test your implementations:

```bash
source venv/bin/activate

# Run all source-to-sink queries (across all binaries in database)
python -m student_labs.lab3.source_to_sink_analysis --all

# Run specific vulnerability queries
python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow
python -m student_labs.lab3.source_to_sink_analysis --format-string
python -m student_labs.lab3.source_to_sink_analysis --command-injection
python -m student_labs.lab3.source_to_sink_analysis --path-traversal

# Find high-risk functions (multiple vulnerability types)
python -m student_labs.lab3.source_to_sink_analysis --high-risk

# Enable inter-procedural analysis (traces paths across function calls)
python -m student_labs.lab3.source_to_sink_analysis --all --interprocedural
python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow --interprocedural --call-depth 2
```

> 💡 **Inter-Procedural Analysis:** The `--interprocedural` flag extends analysis across function call boundaries, finding vulnerabilities where input is received in one function but the dangerous operation happens in a called function. See the "📚 Additional Reading" section for implementation details.

### Step 4: Generate a Vulnerability Report for a Specific Binary

Use `--sha256` to analyze a specific binary and generate an LLM-powered markdown report:

```bash
source venv/bin/activate

# Generate vulnerability report (default output: output/lab3/source_sink_report_<sha256>.md)
# Using bison binary which has interesting source-to-sink paths
python -m student_labs.lab3.source_to_sink_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd

# Generate report with custom output file
python -m student_labs.lab3.source_to_sink_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd --output my_vuln_report.md
```

The report includes:
- Binary metadata and function count
- Risk assessment with LLM-generated justification
- Executive summary of the vulnerability landscape
- Vulnerability paths grouped by category (buffer overflow, format string, command injection, path traversal)
- Exploitation scenarios and recommendations

> 💡 **Note:** The bison binary has actual source-to-sink paths (e.g., `getenv` → `memcpy` in `locale_charset`), making it a good example for this lab. Well-designed libraries like libpng may show 0 vulnerable paths because they separate input handling from dangerous operations into different functions.

### Step 5: Run the Tests

Validate your implementation with the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab3.test.test_lab_3_2 -v
```

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j connection setup, `run_query()` function, `SourceToSinkPath` dataclass, `_convert_to_source_to_sink_paths()` helper, sink API lists (`BUFFER_OVERFLOW_SINKS`, `FORMAT_STRING_SINKS`, etc.), CLI handling, and result formatting. You do not need to implement these.

### Function 1 — `_find_source_to_sink_paths_base()`

This is the **core function** that all 4 detection functions will call. It contains the CFG path query that finds functions where:
1. A user-controlled input API is reachable from the entry point
2. A dangerous sink API is reachable FROM the source API (data can flow from input to sink)

**What to implement:** Paste the Cypher query that traces paths from input sources to dangerous sinks.

```python
def _find_source_to_sink_paths_base(
    driver: Driver,
    database: str,
    source_apis: List[str],
    sink_apis: List[str],
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """Base function for finding source-to-sink paths using CFG reachability."""
    # Build the API list strings for the query
    source_api_str = ", ".join(f"'{api}'" for api in source_apis)
    sink_api_str = ", ".join(f"'{api}'" for api in sink_apis)

    ### YOUR CODE HERE ###
    query = f"""
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)-[:ENTRY_BLOCK]->(entry:BasicBlock)
MATCH (entry)-[:BRANCHES_TO*0..20]->(src_bb:BasicBlock)-[:CALLS_TO]->(src:ImportSymbol)
WHERE src.name IN [{source_api_str}]
MATCH (src_bb)-[:BRANCHES_TO*0..15]->(sink_bb:BasicBlock)-[:CALLS_TO]->(sink:ImportSymbol)
WHERE sink.name IN [{sink_api_str}]
RETURN DISTINCT
    b.name AS binary,
    f.name AS function,
    f.start_address AS address,
    collect(DISTINCT src.name) AS source_apis,
    collect(DISTINCT sink.name) AS sink_apis,
    count(DISTINCT src) AS source_count,
    count(DISTINCT sink) AS sink_count
ORDER BY sink_count DESC, source_count DESC, binary, function
    """
    ### END YOUR CODE HERE ###

    # Execute query and convert results (this part is done for you)
    rows = run_query(driver, database, query, limit)
    return _convert_to_source_to_sink_paths(rows)
```

**Key elements:**
- First MATCH finds the input source (reachable from entry)
- Second MATCH finds a path FROM the source TO the sink
- This ensures data can actually flow from input to dangerous operation

### Function 2 — `find_buffer_overflow_paths()`

Finds paths from user input to buffer overflow sinks. These are critical vulnerabilities that can lead to memory corruption and code execution.

**What to implement:** Define the source and sink API lists, then call the base function.

```python
def find_buffer_overflow_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """Find paths from user input to buffer overflow sinks."""
    ### YOUR CODE HERE ###
    # Input sources (from Lab 3.1)
    source_apis = [
        "recv", "recvfrom", "read", "fread", "fgets", "scanf", "gets",
        "getenv", "ReadFile", "InternetReadFile", "fread_unlocked",
    ]
    # Dangerous sinks - buffer overflow
    sink_apis = [
        "strcpy", "strncpy", "strcat", "strncat",           # String copy/concat
        "sprintf", "vsprintf",                               # Formatted output to buffer
        "gets",                                              # Unbounded input
        "memcpy", "memmove", "bcopy",                        # Memory copy
        "wcscpy", "wcsncpy", "wcscat", "wcsncat",           # Wide string operations
    ]
    results = _find_source_to_sink_paths_base(driver, database, source_apis, sink_apis, limit)
    for r in results:
        r.vulnerability_type = "buffer_overflow"
    return results
    ### END YOUR CODE HERE ###
```

**Vulnerability:** Buffer overflow when user input is copied to fixed-size buffers without bounds checking (CWE-120, CWE-121).

### Function 3 — `find_format_string_paths()`

Finds paths from user input to format string sinks. These vulnerabilities allow attackers to read/write arbitrary memory.

```python
def find_format_string_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """Find paths from user input to format string sinks."""
    ### YOUR CODE HERE ###
    # Input sources
    source_apis = [
        "recv", "recvfrom", "read", "fread", "fgets", "scanf", "gets",
        "getenv", "ReadFile", "InternetReadFile", "fread_unlocked",
    ]
    # Dangerous sinks - format string
    sink_apis = [
        "printf", "fprintf", "sprintf", "snprintf",          # Printf family
        "vprintf", "vfprintf", "vsprintf", "vsnprintf",      # Variadic printf
        "syslog", "vsyslog",                                 # System logging
        "err", "errx", "warn", "warnx",                      # BSD error functions
        "wprintf", "fwprintf", "swprintf",                   # Wide printf
    ]
    results = _find_source_to_sink_paths_base(driver, database, source_apis, sink_apis, limit)
    for r in results:
        r.vulnerability_type = "format_string"
    return results
    ### END YOUR CODE HERE ###
```

**Vulnerability:** Format string attacks when user input is passed as the format argument (CWE-134).

### Function 4 — `find_command_injection_paths()`

Finds paths from user input to command execution sinks. These are critical vulnerabilities that allow arbitrary command execution.

```python
def find_command_injection_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """Find paths from user input to command injection sinks."""
    ### YOUR CODE HERE ###
    # Input sources
    source_apis = [
        "recv", "recvfrom", "read", "fread", "fgets", "scanf", "gets",
        "getenv", "ReadFile", "InternetReadFile", "fread_unlocked",
    ]
    # Dangerous sinks - command execution
    sink_apis = [
        "system", "popen", "pclose",                         # Shell execution
        "execl", "execle", "execlp", "execv", "execve", "execvp",  # Exec family
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", # Windows shell
        "CreateProcessA", "CreateProcessW",                  # Windows process
        "WinExec",                                           # Legacy Windows
        "wordexp",                                           # Word expansion
    ]
    results = _find_source_to_sink_paths_base(driver, database, source_apis, sink_apis, limit)
    for r in results:
        r.vulnerability_type = "command_injection"
    return results
    ### END YOUR CODE HERE ###
```

**Vulnerability:** OS command injection when user input is passed to shell commands (CWE-78).

### Function 5 — `find_path_traversal_paths()`

Finds paths from user input to file operation sinks. These vulnerabilities allow attackers to access arbitrary files.

```python
def find_path_traversal_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """Find paths from user input to path traversal sinks."""
    ### YOUR CODE HERE ###
    # Input sources
    source_apis = [
        "recv", "recvfrom", "read", "fread", "fgets", "scanf", "gets",
        "getenv", "ReadFile", "InternetReadFile", "fread_unlocked",
    ]
    # Dangerous sinks - file operations with user-controlled paths
    sink_apis = [
        "fopen", "freopen", "open", "open64",                # File open
        "creat", "creat64",                                  # File create
        "opendir", "fdopendir",                              # Directory open
        "mkdir", "rmdir", "remove", "unlink",                # File/dir operations
        "rename", "link", "symlink",                         # File linking
        "chmod", "chown", "chgrp",                           # Permission changes
        "CreateFileA", "CreateFileW",                        # Windows file
        "DeleteFileA", "DeleteFileW",                        # Windows delete
    ]
    results = _find_source_to_sink_paths_base(driver, database, source_apis, sink_apis, limit)
    for r in results:
        r.vulnerability_type = "path_traversal"
    return results
    ### END YOUR CODE HERE ###
```

**Vulnerability:** Path traversal when user input controls file paths, e.g., `../../../etc/passwd` (CWE-22).

### Function 6 — `classify_sink_api_with_llm()`

Uses LLM to classify an unknown API and determine if it's a dangerous sink. This helps discover sinks not in the hardcoded lists, similar to how Lab 3.1 uses LLM to discover input sources.

**What to implement:**
1. Define a system prompt that instructs the LLM to return JSON classification
2. Create a prompt asking to classify the API as a dangerous sink
3. Call `llm_completion()` and parse the JSON response
4. Handle errors gracefully

```python
def classify_sink_api_with_llm(api_name: str) -> Dict[str, Any]:
    """Use LLM to classify an API and determine if it's a dangerous sink."""
    from lab_common.llm.client import llm_completion
    import json

    ### YOUR CODE HERE ###
    system_prompt = """You are an expert security analyst specializing in binary vulnerability analysis and API classification.
Your task is to analyze API names and determine if they are dangerous sinks that could lead to vulnerabilities when processing untrusted input.

IMPORTANT: A "dangerous sink" (is_dangerous_sink=true) is an API that can cause security vulnerabilities when it receives attacker-controlled data. This includes:
- Buffer overflow sinks: APIs that copy/write data without bounds checking (strcpy, sprintf, memcpy, gets)
- Format string sinks: APIs that interpret format specifiers from user data (printf, syslog)
- Command injection sinks: APIs that execute shell commands or processes (system, popen, exec*)
- Path traversal sinks: APIs that access files using user-controlled paths (fopen, open, CreateFile)

RESPONSE FORMAT: Return ONLY valid JSON (no markdown, no explanation outside JSON).
Schema:
{
  "api": "<api name>",
  "is_dangerous_sink": <true/false>,
  "sink_category": "<buffer_overflow|format_string|command_injection|path_traversal|other|none>",
  "confidence": "<high|medium|low>",
  "description": "<brief description of what this API does>",
  "vulnerability_notes": "<security considerations, how this API can be exploited>"
}

Classification guidelines (set is_dangerous_sink=true for these categories):
- buffer_overflow: APIs that copy/concatenate strings or memory without bounds checking (strcpy, strcat, sprintf, vsprintf, gets, memcpy, memmove, wcscpy, etc.) -> is_dangerous_sink=TRUE
- format_string: APIs that interpret format strings which could contain attacker-controlled specifiers (printf, fprintf, sprintf, snprintf, syslog, err, warn, etc.) -> is_dangerous_sink=TRUE
- command_injection: APIs that execute shell commands or spawn processes (system, popen, exec*, ShellExecute*, CreateProcess*, WinExec, wordexp, etc.) -> is_dangerous_sink=TRUE
- path_traversal: APIs that open/create/delete files using paths that could be attacker-controlled (fopen, open, creat, mkdir, unlink, rename, CreateFile*, DeleteFile*, etc.) -> is_dangerous_sink=TRUE
- other: Other dangerous operations (SQL queries, LDAP queries, XML parsing, etc.) -> is_dangerous_sink=TRUE
- none: Safe APIs that don't process untrusted data dangerously (malloc, free, strlen, fclose, etc.) -> is_dangerous_sink=FALSE

Consider both POSIX/Linux and Windows API variants."""

    prompt = f"Classify this API as a potential dangerous sink: {api_name}"

    try:
        context = llm_completion(prompt, system_prompt=system_prompt)
        response = context.response.strip()
        data = json.loads(response)
        return data
    except json.JSONDecodeError as e:
        return {
            "api": api_name,
            "is_dangerous_sink": False,
            "sink_category": "unknown",
            "confidence": "low",
            "description": "Unable to parse LLM response",
            "vulnerability_notes": "Manual analysis required",
        }
    ### END YOUR CODE HERE ###
```

### Function 7 — `classify_sink_apis_batch_with_llm()`

Classifies multiple APIs as dangerous sinks in batches to reduce LLM calls. This is more efficient than calling `classify_sink_api_with_llm()` for each API individually.

**What to implement:**
1. Process APIs in batches of `batch_size`
2. Define a system prompt requesting a JSON array
3. Parse the JSON array response
4. On error, fall back to individual classification

```python
def classify_sink_apis_batch_with_llm(
    api_names: List[str],
    batch_size: int = 20,
) -> List[Dict[str, Any]]:
    """Classify multiple APIs as dangerous sinks in batches."""
    from lab_common.llm.client import llm_completion
    import json

    if not api_names:
        return []

    all_results = []

    ### YOUR CODE HERE ###
    for i in range(0, len(api_names), batch_size):
        batch = api_names[i:i + batch_size]

        system_prompt = """You are an expert security analyst. Classify each API as a dangerous sink.
RESPONSE FORMAT: Return ONLY a valid JSON array. Each element:
{
  "api": "<api name>",
  "is_dangerous_sink": <true/false>,
  "sink_category": "<buffer_overflow|format_string|command_injection|path_traversal|other|none>",
  "confidence": "<high|medium|low>",
  "description": "<brief description>",
  "vulnerability_notes": "<security considerations>"
}"""

        prompt = f"Classify these APIs as dangerous sinks: {', '.join(batch)}"

        try:
            context = llm_completion(prompt, system_prompt=system_prompt)
            data = json.loads(context.response.strip())
            if isinstance(data, list):
                all_results.extend(data)
            else:
                all_results.append(data)
        except (json.JSONDecodeError, Exception):
            # Fallback: classify individually
            for api in batch:
                all_results.append(classify_sink_api_with_llm(api))

    return all_results
    ### END YOUR CODE HERE ###
```

---

## ✅ Success Criteria

Your implementation is complete when:

- [ ] All 7 functions are implemented in `student_labs/lab3/source_to_sink_analysis.py`
- [ ] The CLI runs without errors:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.source_to_sink_analysis --all
  ```
- [ ] High-risk function detection works:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.source_to_sink_analysis --high-risk
  ```
- [ ] Binary-specific report generation works:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.source_to_sink_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd
  ```
- [ ] All tests pass:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.test.test_lab_3_2
  ```

**Optional (Advanced):**
- [ ] Enable **inter-procedural analysis** with `--interprocedural`:
  ```bash
  python -m student_labs.lab3.source_to_sink_analysis --all --interprocedural
  ```
  
  > **Why it matters:** Catches cross-function vulnerabilities like `main()` → `helper()` → `strcpy()` that intra-procedural analysis misses. See "Additional Reading" for details.

---

## Summary

In this lab, you implemented:

| Component | What It Does |
|-----------|--------------|
| **Base Path Query Function** | CFG path query from input sources to dangerous sinks |
| **4 Sink Detection Functions** | Specialized detectors for buffer overflow, format string, command injection, and path traversal |
| **LLM Sink Classification** | Classify unknown APIs as dangerous sinks using LLM (single and batch) |
| **High-Risk Function Detection** | Find functions with multiple vulnerability types |

**Key Insight:** The same CFG reachability pattern from Labs 4 and 5.1 now traces *paths* from input sources to dangerous sinks. Lab 3.2 builds on Lab 3.1 by using `get_user_input_sources_for_binary()` for binary-specific analysis, and adds LLM-based sink classification to discover dangerous APIs not in the hardcoded lists.

---

## 📚 Additional Reading

### Vulnerability Categories and Risk Levels

| Category | CWE | Attack Vector | Risk Level |
|----------|-----|---------------|------------|
| **Buffer Overflow** | CWE-120, CWE-121 | Memory corruption, code execution | Critical |
| **Format String** | CWE-134 | Memory read/write, code execution | Critical |
| **Command Injection** | CWE-78 | Arbitrary command execution | Critical |
| **Path Traversal** | CWE-22 | Arbitrary file access | High |

### Why Source-to-Sink Analysis Matters

Static analysis often produces overwhelming results. Source-to-sink analysis prioritizes findings by:

1. **Verifying exploitability**: Only flag vulnerabilities where attacker input can reach the sink
2. **Reducing false positives**: Filter out dangerous APIs that don't process user input
3. **Prioritizing review**: Functions with multiple vulnerability types deserve immediate attention

### The Taint Analysis Connection

This lab implements a simplified form of **taint analysis**:
- **Sources**: Where untrusted data enters (Lab 3.1)
- **Sinks**: Where dangerous operations occur (Lab 3.2)
- **Propagation**: CFG paths from source to sink

Full taint analysis also tracks data transformations, but CFG reachability provides a practical approximation for vulnerability triage.

### Intra-Procedural vs Inter-Procedural Analysis

**This lab performs intra-procedural analysis**—it only traces paths within a single function's CFG. This is an important limitation to understand:

| Analysis Type | What It Finds | What It Misses |
|---------------|---------------|----------------|
| **Intra-procedural** (this lab) | `recv()` → `strcpy()` in the same function | Data passed between functions |
| **Inter-procedural** | Paths across function calls | (More complete but computationally expensive) |

**Example:** A well-designed library like libpng may show **0 vulnerable paths** because:
1. Input handling (`fread` in `png_default_read_data`) is isolated in a dedicated callback
2. Dangerous operations (`memcpy`) happen in separate functions after validation
3. No direct CFG path exists from source to sink within the same function

This is actually **good security design**—separating input handling from dangerous operations. The bison binary, by contrast, has `getenv` → `memcpy` within the same function (`locale_charset`), which our analysis correctly flags.

**Improving with Inter-Procedural Analysis:**

To extend this analysis across function boundaries, you would need:
1. **Call graph construction**: Build a graph of which functions call which
2. **Context-sensitive analysis**: Track data flow through function parameters and return values
3. **Points-to analysis**: Determine which pointers can alias the same memory

These techniques are implemented in BinQL's inter-procedural analysis capabilities, which you can explore using the `--interprocedural` flag.

### High-Level Implementation of Inter-Procedural Analysis

Inter-procedural analysis extends path tracing across function call boundaries:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    INTER-PROCEDURAL DATA FLOW                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   main()              helper()              vulnerable_func()           │
│  ┌─────────┐         ┌─────────┐           ┌─────────────────┐         │
│  │ getenv()│────────▶│ process │──────────▶│    strcpy()     │         │
│  │ (SOURCE)│  call   │  data   │   call    │     (SINK)      │         │
│  └─────────┘         └─────────┘           └─────────────────┘         │
│                                                                         │
│  Intra-procedural: ✗ Misses this (different functions)                 │
│  Inter-procedural: ✓ Traces across call boundaries                     │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Components:**

| Component | Purpose |
|-----------|---------|
| **Call Graph** | Maps which functions call which |
| **Taint Propagation** | Tracks tainted data through parameters and return values |
| **Bounded Depth** | Limits call chain depth (default: 2) for performance |

**Example Query Pattern:**
```cypher
// Follow: source_func [SOURCE] -> mid_func -> sink_func [SINK]
MATCH (src_func)-[:CALLS]->(mid_func)-[:CALLS]->(sink_func)
WHERE src_func has SOURCE_API AND sink_func has SINK_API
```

**Trade-offs:**

| | Intra-Procedural | Inter-Procedural |
|--|------------------|------------------|
| **Speed** | Fast | Slower (more paths) |
| **Coverage** | Single function | Cross-function flows |
| **Use** | Quick triage | Deep analysis |

### CLI Reference

The source-to-sink analysis module provides a comprehensive CLI for vulnerability detection:

```bash
source venv/bin/activate

# Run all vulnerability detection queries
python -m student_labs.lab3.source_to_sink_analysis --all

# Run specific vulnerability category queries
python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow
python -m student_labs.lab3.source_to_sink_analysis --format-string
python -m student_labs.lab3.source_to_sink_analysis --command-injection
python -m student_labs.lab3.source_to_sink_analysis --path-traversal

# Find high-risk functions (multiple vulnerability types)
python -m student_labs.lab3.source_to_sink_analysis --high-risk

# Enable inter-procedural analysis (traces paths across function calls)
python -m student_labs.lab3.source_to_sink_analysis --all --interprocedural
python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow --interprocedural --call-depth 2

# Generate vulnerability report for a specific binary
python -m student_labs.lab3.source_to_sink_analysis --sha256 <binary_sha256>

# Generate report with custom output path
python -m student_labs.lab3.source_to_sink_analysis --sha256 <binary_sha256> --output custom_report.md
```

| Flag | Description |
|------|-------------|
| `--all` | Run all vulnerability detection queries |
| `--buffer-overflow` | Find buffer overflow paths (strcpy, sprintf, memcpy) |
| `--format-string` | Find format string paths (printf, syslog) |
| `--command-injection` | Find command injection paths (system, popen, exec*) |
| `--path-traversal` | Find path traversal paths (fopen, open, CreateFile) |
| `--high-risk` | Find functions with multiple vulnerability types |
| `--interprocedural` | Enable inter-procedural analysis (trace paths across function calls) |
| `--call-depth <n>` | Maximum call depth for inter-procedural analysis (default: 2) |
| `--sha256 <hash>` | Analyze a specific binary and generate LLM-powered report |
| `--output <path>` | Custom output path for the vulnerability report |
