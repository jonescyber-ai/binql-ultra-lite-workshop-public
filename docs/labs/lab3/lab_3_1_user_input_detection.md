# 🔹 Lab 3.1 — User-Controlled Input Detection: Finding Attack Entry Points

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab3/user_input_detection.py` to complete this lab.
>
> 📁 **Student File:** `student_labs/lab3/user_input_detection.py`

**Every exploitable vulnerability starts with attacker-controlled input.** A buffer overflow in code that only processes hardcoded data is not exploitable. But the same overflow in code that processes network packets, file contents, or command-line arguments becomes a critical security issue.

This lab teaches you to answer the fundamental question: **"Where can an attacker inject data into this program?"**

---

## Overview

- **Goal:** Implement functions that detect user-controlled input sources using CFG reachability queries
- **Inputs:** Binaries ingested in Neo4j from the Lab 3 Setup
- **Outputs:** Functions that return `InputSourceResult` objects identifying attack entry points

### Why Input Source Detection Matters

```
┌─────────────────────────────────────────────────────────────────┐
│                    VULNERABILITY TRIAGE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Lab 3.1: Find INPUT SOURCES          Lab 3.2: Trace to SINKS  │
│   (Where does attacker data enter?)    (Where does it go?)      │
│                                                                  │
│   ┌─────────┐                          ┌─────────┐              │
│   │ Network │──┐                   ┌──▶│ strcpy  │              │
│   │  recv() │  │                   │   │ sprintf │              │
│   └─────────┘  │   ┌───────────┐   │   └─────────┘              │
│   ┌─────────┐  ├──▶│ Function  │───┤                            │
│   │  File   │  │   │   Code    │   │   ┌─────────┐              │
│   │ fread() │──┤   └───────────┘   └──▶│ system  │              │
│   └─────────┘  │                       │  exec   │              │
│   ┌─────────┐  │                       └─────────┘              │
│   │  Stdin  │──┘                                                │
│   │ scanf() │                                                   │
│   └─────────┘                                                   │
│                                                                  │
│   THIS LAB ◀────────────────────────────────────────────────────│
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 What You Need To Do

### Step 1: Open the Student Module

Open the user input detection module in your editor:

```bash
# View the module
cat student_labs/lab3/user_input_detection.py
```

The module provides:
- `run_query()` - Helper function to execute Cypher queries (already implemented)
- `InputSourceResult` - Dataclass for structured results (already implemented)
- `_convert_to_input_source_results()` - Converts query results to InputSourceResult objects (already implemented)
- 9 functions with `### YOUR CODE HERE ###` placeholders for you to fill in

### Step 2: Implement the Required Functions

You need to implement these functions:

1. **`_detect_input_source_base()`** — Core CFG reachability query (implement once, used by all detection functions)
2. **`detect_network_input()`** — Find network input sources (sockets, HTTP, SSL)
3. **`detect_file_input()`** — Find file input sources (fread, ReadFile, mmap)
4. **`detect_stdin_input()`** — Find stdin input sources (scanf, gets, console)
5. **`detect_environment_input()`** — Find environment variable input (getenv)
6. **`detect_ipc_input()`** — Find IPC input sources (pipes, shared memory, RPC)
7. **`detect_cmdline_input()`** — Find command-line argument input (getopt, argv)
8. **`classify_api_with_llm()`** — LLM-based API classification for unknown APIs
9. **`generate_scan_report()`** — Generate a markdown report of user-input sources for a binary (used by `--scan-apis`)

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the module to test your implementations:

```bash
source venv/bin/activate

# Run all input source detection queries
python -m student_labs.lab3.user_input_detection --all

# Run specific input source query
python -m student_labs.lab3.user_input_detection --network
python -m student_labs.lab3.user_input_detection --file

# Test LLM classification
python -m student_labs.lab3.user_input_detection --classify-api recv

# Generate a security report for a specific binary
python -m student_labs.lab3.user_input_detection --scan-apis --sha256 5901ede53ed33d4feafbc9763ebb86209d542c456b3990bb887177982fb1ceb6
```

### Step 4: Run the Tests

Validate your implementation with the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab3.test.test_lab_3_1 -v
```

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j connection setup, `run_query()` function, `InputSourceResult` dataclass, `_convert_to_input_source_results()` helper, CLI handling, and result formatting. You do not need to implement these.

### Function 1 — `_detect_input_source_base()`

This is the **core function** that all 6 detection functions will call. It contains the CFG reachability query that finds functions with reachable input-related imports.

**What to implement:** Paste the Cypher query that:
- Starts from function entry points
- Follows CFG edges to find reachable basic blocks
- Identifies which input APIs are actually called
- Filters out dead code and unused imports

```python
def _detect_input_source_base(
    driver: Driver,
    database: str,
    api_list: List[str],
    limit: int = 100,
) -> List[InputSourceResult]:
    """Base function for detecting input sources using CFG reachability."""
    # Build the API list string for the query
    api_list_str = ", ".join(f"'{api}'" for api in api_list)

    ### YOUR CODE HERE ###
    query = f"""
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)-[:ENTRY_BLOCK]->(entry:BasicBlock)
MATCH (entry)-[:BRANCHES_TO*0..20]->(bb:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
WHERE imp.name IN [{api_list_str}]
RETURN DISTINCT
    b.name AS binary,
    f.name AS function,
    f.start_address AS address,
    collect(DISTINCT imp.name) AS input_apis,
    count(DISTINCT imp) AS api_count
ORDER BY api_count DESC, binary, function
    """
    ### END YOUR CODE HERE ###

    # Execute query and convert results (this part is done for you)
    rows = run_query(driver, database, query, limit)
    return _convert_to_input_source_results(rows, api_field="input_apis")
```

### Function 2 — `detect_network_input()`

Detects network input sources (sockets, HTTP, SSL/TLS). These are entry points for remote attacker-controlled data.

**What to implement:** Define the API list and call the base function.

```python
def detect_network_input(driver: Driver, database: str, limit: int = 100) -> List[InputSourceResult]:
    """Detect network input sources in binaries."""
    ### YOUR CODE HERE ###
    api_list = [
        # BSD sockets
        "recv", "recvfrom", "recvmsg", "read", "readv",
        # Windows sockets
        "WSARecv", "WSARecvFrom", "WSARecvMsg",
        # Windows HTTP (WinINet)
        "InternetReadFile", "InternetReadFileEx",
        # Windows HTTP Server
        "HttpReceiveHttpRequest", "HttpReceiveRequestEntityBody",
        # Windows HTTP (WinHTTP)
        "WinHttpReadData", "WinHttpReceiveResponse",
        # SSL/TLS libraries
        "PR_Read", "PR_Recv", "SSL_read", "BIO_read",
    ]
    return _detect_input_source_base(driver, database, api_list, limit)
    ### END YOUR CODE HERE ###
```

### Function 3 — `detect_file_input()`

Detects file input sources. File input is a major attack vector for document parsers, configuration handlers, and archive processors.

```python
def detect_file_input(driver: Driver, database: str, limit: int = 100) -> List[InputSourceResult]:
    """Detect file input sources in binaries."""
    ### YOUR CODE HERE ###
    api_list = [
        # C standard library
        "fread", "fgets", "fgetc", "fgetws", "fgetwc",
        # POSIX I/O
        "read", "pread", "pread64", "readv", "preadv",
        # Windows file I/O
        "ReadFile", "ReadFileEx", "ReadFileScatter",
        # NT native
        "NtReadFile", "ZwReadFile",
        # Memory mapping
        "mmap", "MapViewOfFile", "MapViewOfFileEx",
    ]
    return _detect_input_source_base(driver, database, api_list, limit)
    ### END YOUR CODE HERE ###
```

### Function 4 — `detect_stdin_input()`

Detects standard input sources. These are entry points for user-controlled data in interactive applications and piped input.

```python
def detect_stdin_input(driver: Driver, database: str, limit: int = 100) -> List[InputSourceResult]:
    """Detect standard input sources in binaries."""
    ### YOUR CODE HERE ###
    api_list = [
        # Formatted input
        "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
        # Line input
        "gets", "fgets", "getchar", "getc", "ungetc",
        # Wide character input
        "getwchar", "fgetws", "fgetwc",
        # Windows console
        "ReadConsoleA", "ReadConsoleW", "ReadConsoleInputA", "ReadConsoleInputW",
        "GetStdHandle", "_getch", "_getche", "_getwch", "_getwche",
    ]
    return _detect_input_source_base(driver, database, api_list, limit)
    ### END YOUR CODE HERE ###
```

### Function 5 — `detect_environment_input()`

Detects environment variable input. Environment input is attacker-controlled in many contexts (web servers, SUID binaries, containers).

```python
def detect_environment_input(driver: Driver, database: str, limit: int = 100) -> List[InputSourceResult]:
    """Detect environment variable input sources in binaries."""
    ### YOUR CODE HERE ###
    api_list = [
        # POSIX
        "getenv", "getenv_s", "_wgetenv", "_wgetenv_s",
        "secure_getenv", "__secure_getenv",
        # Windows
        "GetEnvironmentVariableA", "GetEnvironmentVariableW",
        "GetEnvironmentStringsA", "GetEnvironmentStringsW",
        "ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW",
    ]
    return _detect_input_source_base(driver, database, api_list, limit)
    ### END YOUR CODE HERE ###
```

### Function 6 — `detect_ipc_input()`

Detects IPC (Inter-Process Communication) input sources. IPC input can be attacker-controlled in multi-process applications and service architectures.

```python
def detect_ipc_input(driver: Driver, database: str, limit: int = 100) -> List[InputSourceResult]:
    """Detect IPC input sources in binaries."""
    ### YOUR CODE HERE ###
    api_list = [
        # POSIX message queues
        "msgrcv", "mq_receive", "mq_timedreceive",
        # Shared memory
        "shmat", "shmget", "shmctl",
        # Named pipes (Windows)
        "ReadFile", "PeekNamedPipe", "TransactNamedPipe",
        # File mapping
        "CreateFileMappingA", "CreateFileMappingW", "OpenFileMappingA", "OpenFileMappingW",
        "MapViewOfFile", "MapViewOfFileEx",
        # RPC
        "RpcServerListen", "RpcBindingFromStringBindingA", "NdrServerCall2",
        # DDE
        "DdeConnect", "DdeClientTransaction",
        # COM
        "CoCreateInstance", "CoGetClassObject",
    ]
    return _detect_input_source_base(driver, database, api_list, limit)
    ### END YOUR CODE HERE ###
```

### Function 7 — `detect_cmdline_input()`

Detects command-line argument input. Command-line input is fully attacker-controlled in SUID binaries and subprocess invocations.

```python
def detect_cmdline_input(driver: Driver, database: str, limit: int = 100) -> List[InputSourceResult]:
    """Detect command-line argument input sources in binaries."""
    ### YOUR CODE HERE ###
    api_list = [
        # POSIX option parsing
        "getopt", "getopt_long", "getopt_long_only",
        # GNU argp
        "argp_parse",
        # popt library
        "poptGetContext", "poptGetNextOpt",
        # Windows
        "CommandLineToArgvW", "GetCommandLineA", "GetCommandLineW",
        # CRT initialization
        "__getmainargs", "__wgetmainargs",
        # Path utilities
        "PathGetArgsA", "PathGetArgsW",
    ]
    return _detect_input_source_base(driver, database, api_list, limit)
    ### END YOUR CODE HERE ###
```

### Function 8 — `classify_api_with_llm()`

Uses LLM to classify an unknown API and determine if it's a user-controlled input source. This helps discover input sources not in the hardcoded lists.

**What to implement:**
1. Define a system prompt that instructs the LLM to return JSON classification
2. Create a prompt asking to classify the API
3. Call `llm_completion()` and parse the JSON response
4. Handle errors gracefully

```python
def classify_api_with_llm(api_name: str) -> Dict[str, Any]:
    """Use LLM to classify an API and determine if it's a user-controlled input source."""
    from lab_common.llm.client import llm_completion
    import json

    ### YOUR CODE HERE ###
    system_prompt = """You are an expert security analyst specializing in binary analysis and API classification.
Your task is to analyze API names and determine if they accept user-controlled input.

IMPORTANT: An API is a "user input source" (is_user_input=true) if it READS or RECEIVES external data that
could be attacker-controlled. This includes:
- File reading APIs (fread, fgets, ReadFile, etc.) - files can contain malicious data
- Network APIs (recv, read on sockets, etc.) - network data is attacker-controlled
- Stdin APIs (scanf, gets, etc.) - user input is attacker-controlled
- Environment APIs (getenv, etc.) - environment can be attacker-controlled

RESPONSE FORMAT: Return ONLY valid JSON (no markdown, no explanation outside JSON).
Schema:
{
  "api": "<api name>",
  "is_user_input": <true/false>,
  "input_category": "<network|file|stdin|environment|ipc|cmdline|other|none>",
  "confidence": "<high|medium|low>",
  "description": "<brief description of what this API does>",
  "security_notes": "<security considerations, potential vulnerabilities>"
}

Classification guidelines (set is_user_input=true for these categories):
- network: APIs that receive data from network sockets, HTTP, SSL/TLS (recv, WSARecv, InternetReadFile, etc.) -> is_user_input=TRUE
- file: APIs that READ from files or memory-mapped regions (fread, fgets, ReadFile, mmap, etc.) -> is_user_input=TRUE
- stdin: APIs that read from standard input or console (scanf, gets, ReadConsole, etc.) -> is_user_input=TRUE
- environment: APIs that read environment variables (getenv, GetEnvironmentVariable, etc.) -> is_user_input=TRUE
- ipc: APIs for inter-process communication that RECEIVE data (msgrcv, shmat, pipes, RPC, COM, etc.) -> is_user_input=TRUE
- cmdline: APIs that process command-line arguments (getopt, GetCommandLine, etc.) -> is_user_input=TRUE
- other: User input from other sources (GUI input, clipboard, etc.) -> is_user_input=TRUE
- none: APIs that do NOT read external data (malloc, free, memcpy, strlen, fwrite, fclose, etc.) -> is_user_input=FALSE

Consider both POSIX/Linux and Windows API variants."""

    prompt = f"Classify this API: {api_name}"

    try:
        context = llm_completion(prompt, system_prompt=system_prompt)
        response = context.response.strip()
        # Strip markdown code fences if present
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        data = json.loads(response)
        return data
    except json.JSONDecodeError as e:
        return {
            "api": api_name,
            "is_user_input": False,
            "input_category": "unknown",
            "confidence": "low",
            "description": "Unable to parse LLM response",
            "security_notes": "Manual analysis required",
        }
    ### END YOUR CODE HERE ###
```

### Function 9 — `generate_scan_report()`

Generates a comprehensive markdown report of user-input sources for a specific binary. This function is invoked by the `--scan-apis --sha256` CLI flag.

**What to implement:**
1. Get binary info using `get_binary_info()`
2. Call `get_user_input_sources_for_binary()` to get all user-input sources
3. Group sources by category
4. Use `llm_completion()` to generate an executive summary and security analysis
5. Build a markdown report with all sections
6. Write to file if `output_path` is specified
7. Return the report string

> 💡 **Hint:** See the function's docstring in the student file for the full signature and return type. The report should include binary metadata, user-input sources grouped by category with call-site details, an LLM-generated executive summary, and recommendations.

---

## 🔹 Optional: LLM-Based API List Extraction

> **Advanced / Optional** — This section demonstrates an alternative to hardcoding API lists. You do not need to implement this to pass the lab, but it showcases a powerful LLM pattern.

In your `detect_*()` implementations above, each function defines a hardcoded `api_list`. The module provides an alternative: `extract_api_list_with_llm()`, which uses an LLM to dynamically generate the API list from the function's docstring.

**Universal one-liner pattern:**
```python
def detect_network_input(driver, database, limit=100):
    """Find functions that receive data from network connections (sockets, HTTP)..."""
    api_list = extract_api_list_with_llm(detect_network_input.__doc__)
    return _detect_input_source_base(driver, database, api_list, limit)
```

This works identically for all 6 categories — the LLM reads the docstring description and returns the appropriate API names. Benefits:
- **No duplication** — API lists are derived from the docstring, not maintained in two places
- **Discoverable** — the LLM may find APIs you didn't know about
- **Maintainable** — update the docstring description, and the API list updates automatically

**Trade-offs:** LLM extraction adds ~1-2s per call (results are cached in memory), costs tokens, and may vary between runs. The hardcoded approach is deterministic and free. Use whichever fits your use case.

```bash
# Test LLM extraction
source venv/bin/activate
python -m student_labs.lab3.test.test_lab_3_1 -v
# Look for: test_extract_api_list_with_llm_returns_apis
```

---

## ✅ Success Criteria

Your implementation is complete when:

- [ ] All 9 functions are implemented in `student_labs/lab3/user_input_detection.py`
- [ ] The CLI runs without errors:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.user_input_detection --all
  ```
- [ ] LLM classification works:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.user_input_detection --classify-api recv
  ```
- [ ] Report generation works:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.user_input_detection --scan-apis --sha256 5901ede53ed33d4feafbc9763ebb86209d542c456b3990bb887177982fb1ceb6
  ```
- [ ] All tests pass:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.test.test_lab_3_1
  ```

---

## Summary

In this lab, you implemented:

| Component | What It Does |
|-----------|--------------|
| **Base Query Function** | CFG reachability query to find functions calling specific APIs |
| **6 Detection Functions** | Specialized detectors for network, file, stdin, environment, IPC, and command-line input |
| **LLM API Classifier** | Classify unknown APIs to discover new input sources |
| **Scan Report Generator** | Generate a markdown report of user-input sources for a binary |

**Key Insight:** The same CFG reachability pattern from Lab 1 (capability detection) now finds *input sources* instead of *capabilities*. The `--scan-apis` command uses `get_user_input_sources_for_binary()` which Lab 3.2 will leverage for source-to-sink analysis.

---

## 📚 Additional Reading

### Input Source Risk Levels

| Category | Attack Vector | Risk Level |
|----------|---------------|------------|
| **Network** | Remote exploitation | Critical |
| **File** | Malicious documents | High |
| **Stdin** | Interactive/piped input | Medium-High |
| **Environment** | CGI, SUID, containers | Medium-High |
| **IPC** | Service communication | Medium |
| **Command-line** | SUID, subprocess | Medium |

### Why CFG Reachability Matters

Static analysis often produces false positives from:
- Dead code that's never executed
- Decoy imports added to confuse analysts
- Library code that's linked but never called

By requiring reachability from function entry points, we filter these out and focus on input sources that can actually receive attacker data.

### Handling LLM Classification False Positives

LLM-based API classification (Function 8) may produce incorrect results. The module provides tools to review and correct classifications:

**Review cached classifications:**
```bash
# List all cached user-input classifications
python -m student_labs.lab3.user_input_detection --review-classifications

# Filter by category
python -m student_labs.lab3.user_input_detection --review-classifications --filter-category network

# Export all classifications to a review file
python -m student_labs.lab3.user_input_detection --export-classifications
```

**Override incorrect classifications:**

Create or edit `cache/llm_api_classification/overrides.json` to correct false positives or negatives. Overrides take precedence over LLM results on the next run.

```json
{
  "my_safe_api": {
    "api": "my_safe_api",
    "is_user_input": false,
    "input_category": "none",
    "confidence": "high",
    "description": "Internal helper, not user input",
    "security_notes": "False positive corrected — does not read external data"
  }
}
```

This override mechanism is useful when integrating the classification pipeline into CI/CD workflows, where consistent and auditable results are important.
