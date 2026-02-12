# 🔹 Lab 3.3 — Path Risk Analysis: Ranking Vulnerability Paths by Complexity and Traversal Likelihood

> ✏️ **This is an implementation lab.** You will write Python code in `student_labs/lab3/complexity_analysis.py` to complete this lab.
>
> 📁 **Student File:** `student_labs/lab3/complexity_analysis.py`

**Lab 3.2 found the paths. Lab 3.3 ranks them.** Not all source-to-sink paths are equally dangerous. This lab takes the vulnerability paths identified in Lab 3.2 and quantifies each path's risk by analyzing complexity metrics and traversal likelihood—enabling effective triage when facing many findings.

---

## Overview

- **Goal:** Analyze Lab 3.2's source-to-sink paths to produce quantified risk scores for prioritized vulnerability triage
- **Inputs:** `SourceToSinkPath` results from Lab 3.2 (via API calls)
- **Outputs:** `PathRiskAnalysis` objects that rank each path by complexity, traversal likelihood, and combined risk score

### The Big Picture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LAB 5.3: PATH RISK QUANTIFICATION                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   LAB 5.2 OUTPUT                    LAB 5.3 ANALYSIS                        │
│   (Source-to-Sink Paths)            (Quantify Each Path)                    │
│                                                                              │
│   ┌─────────────────────┐           ┌─────────────────────────────────┐     │
│   │ SourceToSinkPath #1 │           │  PATH COMPLEXITY ANALYSIS       │     │
│   │ recv() → strcpy()   │──────────▶│  • Cyclomatic complexity: 15    │     │
│   │ in function: parse  │           │  • Branch count: 8              │     │
│   └─────────────────────┘           │  • Nesting depth: 4             │     │
│                                     └─────────────────────────────────┘     │
│   ┌─────────────────────┐                        │                          │
│   │ SourceToSinkPath #2 │                        ▼                          │
│   │ fread() → sprintf() │           ┌─────────────────────────────────┐     │
│   │ in function: load   │──────────▶│  TRAVERSAL LIKELIHOOD           │     │
│   └─────────────────────┘           │  • Entry point connectivity: 3  │     │
│                                     │  • Caller count: 5              │     │
│   ┌─────────────────────┐           │  • Dark code ratio: 0.1         │     │
│   │ SourceToSinkPath #3 │           └─────────────────────────────────┘     │
│   │ getenv() → memcpy() │                        │                          │
│   │ in function: init   │──────────▶             ▼                          │
│   └─────────────────────┘           ┌─────────────────────────────────┐     │
│                                     │  QUANTIFIED RISK SCORE          │     │
│                                     │  Path #1: 87/100 (Critical)     │     │
│                                     │  Path #2: 62/100 (High)         │     │
│                                     │  Path #3: 34/100 (Medium)       │     │
│                                     └─────────────────────────────────┘     │
│                                                                              │
│   KEY INSIGHT: Not all Lab 3.2 paths are equally dangerous.                 │
│   Lab 3.3 quantifies WHICH paths deserve immediate attention.               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Matters: The Lab 3.2 → 5.3 Narrative

Lab 3.2 identifies **potential** vulnerabilities—functions where user input can reach dangerous sinks. But not all paths are equally exploitable:

| Lab 3.2 Finding | Lab 3.3 Question | Why It Matters |
|-----------------|------------------|----------------|
| `recv() → strcpy()` in `parse_request` | How complex is the path? | Complex paths have more edge cases attackers can exploit |
| `fread() → sprintf()` in `load_config` | How likely is this path to execute? | Rarely-traversed paths may be untested |
| `getenv() → memcpy()` in `init_locale` | Is this path reachable from main entry points? | Unreachable paths are lower priority |

**Lab 3.3 transforms Lab 3.2's binary "vulnerable/not vulnerable" into a quantified risk score** that enables effective triage.

---

## 🎯 What You Need To Do

### Step 1: Open the Student Module

Open the complexity analysis module in your editor:

```bash
# View the module
cat student_labs/lab3/complexity_analysis.py
```

The module provides:
- `run_query()` - Helper function to execute Cypher queries (already implemented)
- `PathComplexityMetrics` - Dataclass for complexity metrics (already implemented)
- `PathTraversalMetrics` - Dataclass for traversal likelihood (already implemented)
- `PathRiskAnalysis` - Dataclass for complete risk analysis (already implemented)
- Integration with Lab 3.2's `SourceToSinkPath` via imports
- 5 functions with `### YOUR CODE HERE ###` placeholders for you to fill in

### Step 2: Implement the Required Functions

You need to implement these functions:

**Core Path Analysis Functions:**
1. **`analyze_path_complexity()`** — Calculate complexity metrics for a Lab 3.2 path (cyclomatic complexity, branch count, basic block count)
2. **`analyze_path_traversal_likelihood()`** — Measure how likely the path is to be executed (entry point connectivity, caller count, dark code ratio)
3. **`calculate_path_risk_score()`** — Combine complexity + traversal + vulnerability severity into a quantified risk score (0-100)

**Batch Analysis Functions:**
4. **`get_paths_for_binary()`** — Retrieve all Lab 3.2 source-to-sink paths for a specific binary using Lab 3.2's API
5. **`analyze_all_paths_for_binary()`** — Analyze all Lab 3.2 paths for a binary and return ranked `PathRiskAnalysis` objects

> 💡 **Note:** LLM-powered report generation is covered in **Lab 3.4**, which synthesizes findings from Labs 3.1-5.3 into comprehensive vulnerability triage reports.

> 📖 **See the "📚 Implementation Guide" section below for detailed guidance on implementing each function.**

### Step 3: Test Your Implementation

Run the module to test your implementations:

```bash
source venv/bin/activate

# Analyze all Lab 3.2 paths for a specific binary
python -m student_labs.lab3.complexity_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd

# Show only critical/high risk paths
python -m student_labs.lab3.complexity_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd --min-risk high

# Analyze all binaries in database
python -m student_labs.lab3.complexity_analysis --all

# Show detailed metrics for each path
python -m student_labs.lab3.complexity_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd --verbose
```

### Step 4: Run the Tests

Validate your implementation with the test suite:

```bash
source venv/bin/activate
python -m student_labs.lab3.test.test_lab_3_3 -v
```

---

## 📚 Implementation Guide

This section contains detailed guidance for implementing each function. **You only need to implement the code inside the `### YOUR CODE HERE ###` markers.**

> ℹ️ **Already provided in the template:** Neo4j connection setup, `run_query()` function, dataclasses (`PathComplexityMetrics`, `PathTraversalMetrics`, `PathRiskAnalysis`), Lab 3.2 imports, CLI handling, and result formatting. You do not need to implement these.

### Function 1 — `analyze_path_complexity()`

This function calculates complexity metrics for a function containing a Lab 3.2 source-to-sink path. It queries Neo4j to get cyclomatic complexity, branch count, and basic block count.

**What to implement:** Write a Cypher query that calculates complexity metrics for the function.

```python
def analyze_path_complexity(
    driver: Driver,
    database: str,
    path: SourceToSinkPath,
) -> PathComplexityMetrics:
    """
    Calculate complexity metrics for a Lab 3.2 source-to-sink path.
    
    Uses the function containing the path to calculate:
    - Cyclomatic complexity (edges - nodes + 2)
    - Branch count (number of conditional branches)
    - Basic block count
    """
    ### YOUR CODE HERE ###
    query = """
    MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function {name: $function_name})
    WHERE b.name CONTAINS $binary_name OR b.sha256 CONTAINS $binary_name
    MATCH (f)-[:ENTRY_BLOCK]->(entry:BasicBlock)
    MATCH (f)-[:HAS_BASIC_BLOCK]->(bb:BasicBlock)
    WITH b, f, entry, count(DISTINCT bb) AS node_count
    OPTIONAL MATCH (f)-[:HAS_BASIC_BLOCK]->(bb1:BasicBlock)-[:BRANCHES_TO]->(bb2:BasicBlock)
    WITH b, f, entry, node_count, count(*) AS edge_count
    RETURN 
        f.name AS function,
        f.start_address AS address,
        node_count AS basic_block_count,
        edge_count,
        CASE WHEN node_count > 0 THEN (edge_count - node_count + 2) ELSE 1 END AS cyclomatic_complexity
    LIMIT 1
    """
    
    rows = run_query(driver, database, query, params={
        "function_name": path.function,
        "binary_name": path.binary,
    })
    
    if rows:
        row = rows[0]
        return PathComplexityMetrics(
            cyclomatic_complexity=row.get("cyclomatic_complexity", 1),
            branch_count=row.get("edge_count", 0),
            basic_block_count=row.get("basic_block_count", 1),
            nesting_depth=0,  # Would require additional analysis
            path_length=0,    # Would require path-specific query
        )
    
    # Default metrics if function not found
    return PathComplexityMetrics(
        cyclomatic_complexity=1,
        branch_count=0,
        basic_block_count=1,
        nesting_depth=0,
        path_length=0,
    )
    ### END YOUR CODE HERE ###
```

**Key elements:**
- Query calculates cyclomatic complexity using McCabe's formula: `E - N + 2`
- Uses the function name and binary from the Lab 3.2 `SourceToSinkPath`
- Returns a `PathComplexityMetrics` dataclass

### Function 2 — `analyze_path_traversal_likelihood()`

This function measures how likely a path is to be executed by analyzing entry point connectivity, caller count, and dark code ratio.

**What to implement:** Write Cypher queries to calculate traversal likelihood metrics.

```python
def analyze_path_traversal_likelihood(
    driver: Driver,
    database: str,
    path: SourceToSinkPath,
) -> PathTraversalMetrics:
    """
    Measure how likely a Lab 3.2 path is to be executed.
    
    Calculates:
    - Entry point connectivity (how many entry points can reach this function)
    - Caller count (number of functions that call this function)
    - Dark code ratio (percentage of low-connectivity blocks)
    - Is error handler (heuristic based on nearby error APIs)
    """
    ### YOUR CODE HERE ###
    # Query 1: Get caller count
    caller_query = """
    MATCH (b:Binary)-[:HAS_FUNCTION]->(target:Function {name: $function_name})
    WHERE b.name CONTAINS $binary_name OR b.sha256 CONTAINS $binary_name
    OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(caller:Function)-[:HAS_BASIC_BLOCK]->(bb:BasicBlock)-[:CALLS_TO]->(target)
    RETURN count(DISTINCT caller) AS caller_count
    """
    
    caller_rows = run_query(driver, database, caller_query, params={
        "function_name": path.function,
        "binary_name": path.binary,
    })
    caller_count = caller_rows[0].get("caller_count", 0) if caller_rows else 0
    
    # Query 2: Check entry point connectivity
    entry_query = """
    MATCH (b:Binary)-[:HAS_FUNCTION]->(target:Function {name: $function_name})
    WHERE b.name CONTAINS $binary_name OR b.sha256 CONTAINS $binary_name
    OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(entry:Function)
    WHERE entry.name IN ['main', '_start', 'WinMain', 'DllMain', '_main']
    RETURN count(DISTINCT entry) AS entry_point_connectivity
    """
    
    entry_rows = run_query(driver, database, entry_query, params={
        "function_name": path.function,
        "binary_name": path.binary,
    })
    entry_connectivity = entry_rows[0].get("entry_point_connectivity", 0) if entry_rows else 0
    
    # Query 3: Calculate dark code ratio
    dark_query = """
    MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function {name: $function_name})
    WHERE b.name CONTAINS $binary_name OR b.sha256 CONTAINS $binary_name
    MATCH (f)-[:HAS_BASIC_BLOCK]->(bb:BasicBlock)
    OPTIONAL MATCH (pred:BasicBlock)-[:BRANCHES_TO]->(bb)
    WITH f, bb, count(pred) AS in_degree
    WITH f, 
         count(bb) AS total_blocks,
         sum(CASE WHEN in_degree <= 1 THEN 1 ELSE 0 END) AS dark_blocks
    RETURN 
        total_blocks,
        dark_blocks,
        toFloat(dark_blocks) / total_blocks AS dark_code_ratio
    """
    
    dark_rows = run_query(driver, database, dark_query, params={
        "function_name": path.function,
        "binary_name": path.binary,
    })
    dark_code_ratio = dark_rows[0].get("dark_code_ratio", 0.0) if dark_rows else 0.0
    
    # Heuristic: check if sink APIs suggest error handling
    error_apis = ['perror', 'strerror', 'exit', 'abort', 'err', 'errx']
    is_error_handler = any(api in path.sink_apis for api in error_apis)
    
    return PathTraversalMetrics(
        entry_point_connectivity=entry_connectivity,
        path_in_degree=0,  # Would require path-specific analysis
        dark_code_ratio=dark_code_ratio,
        is_error_handler=is_error_handler,
        caller_count=caller_count,
    )
    ### END YOUR CODE HERE ###
```

**Key elements:**
- Multiple queries to gather different traversal metrics
- Dark code ratio identifies rarely-visited code regions
- Error handler detection uses heuristics based on API names

### Function 3 — `calculate_path_risk_score()`

This function combines complexity metrics, traversal likelihood, and vulnerability severity into a single risk score (0-100).

**What to implement:** Implement the risk scoring formula.

```python
def calculate_path_risk_score(
    complexity: PathComplexityMetrics,
    traversal: PathTraversalMetrics,
    vulnerability_type: str,
) -> Tuple[float, str]:
    """
    Calculate combined risk score (0-100) for a Lab 3.2 path.
    
    Scoring Philosophy:
    - High complexity + high traversal likelihood = CRITICAL
    - High complexity + low traversal likelihood = HIGH
    - Low complexity + high traversal likelihood = MEDIUM
    - Low complexity + low traversal likelihood = LOW
    
    Weights:
    - Complexity: 40% (complex paths have more exploitable edge cases)
    - Traversal likelihood: 35% (reachable paths are more exploitable)
    - Vulnerability severity: 25% (command injection > buffer overflow > format string > path traversal)
    
    Returns:
        Tuple of (score, risk_level) where risk_level is "critical", "high", "medium", or "low"
    """
    ### YOUR CODE HERE ###
    # Normalize complexity (0-1)
    complexity_score = min(complexity.cyclomatic_complexity / 30, 1.0)
    complexity_score += min(complexity.nesting_depth / 5, 0.3)  # Bonus for deep nesting
    complexity_score = min(complexity_score, 1.0)
    
    # Normalize traversal likelihood (0-1)
    # Higher connectivity = more likely to be traversed = higher score
    traversal_score = min(traversal.entry_point_connectivity / 3, 0.4)
    traversal_score += min(traversal.caller_count / 5, 0.3)
    traversal_score += (1.0 - traversal.dark_code_ratio) * 0.3  # Less dark code = higher score
    if traversal.is_error_handler:
        traversal_score *= 0.7  # Error handlers are less likely to be reached
    traversal_score = min(traversal_score, 1.0)
    
    # Vulnerability severity multiplier
    severity_multipliers = {
        "command_injection": 1.0,   # Arbitrary code execution
        "buffer_overflow": 0.9,     # Memory corruption, potential RCE
        "format_string": 0.85,      # Memory read/write
        "path_traversal": 0.7,      # File access
    }
    severity_score = severity_multipliers.get(vulnerability_type, 0.5)
    
    # Combined score (0-100)
    combined = (
        complexity_score * 40 +
        traversal_score * 35 +
        severity_score * 25
    )
    
    # Determine risk level
    if combined >= 70:
        risk_level = "critical"
    elif combined >= 50:
        risk_level = "high"
    elif combined >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return combined, risk_level
    ### END YOUR CODE HERE ###
```

**Risk Levels:**

| Score Range | Risk Level | Interpretation | Action |
|-------------|------------|----------------|--------|
| 70-100 | 🔴 Critical | Complex, reachable, severe vulnerability | Immediate review and fix |
| 50-69 | 🟠 High | Significant risk, likely exploitable | Review within sprint |
| 30-49 | 🟡 Medium | Moderate risk, may require specific conditions | Schedule for review |
| 0-29 | 🟢 Low | Low complexity or unlikely to be reached | Document, deprioritize |

### Function 4 — `get_paths_for_binary()`

This function retrieves all Lab 3.2 source-to-sink paths for a specific binary by calling Lab 3.2's API functions.

**What to implement:** Call Lab 3.2's detection functions and filter by binary.

```python
def get_paths_for_binary(
    driver: Driver,
    database: str,
    sha256: str,
) -> List[SourceToSinkPath]:
    """
    Retrieve all Lab 3.2 source-to-sink paths for a specific binary.
    
    Calls Lab 3.2's API functions:
    - find_buffer_overflow_paths()
    - find_format_string_paths()
    - find_command_injection_paths()
    - find_path_traversal_paths()
    
    Then filters results to the specified binary.
    """
    from student_labs.lab3.source_to_sink_analysis import (
        find_buffer_overflow_paths,
        find_format_string_paths,
        find_command_injection_paths,
        find_path_traversal_paths,
    )
    
    ### YOUR CODE HERE ###
    all_paths: List[SourceToSinkPath] = []
    
    # Call Lab 3.2 API functions
    all_paths.extend(find_buffer_overflow_paths(driver, database))
    all_paths.extend(find_format_string_paths(driver, database))
    all_paths.extend(find_command_injection_paths(driver, database))
    all_paths.extend(find_path_traversal_paths(driver, database))
    
    # Filter to specific binary (match by sha256 in binary name or exact match)
    binary_paths = [
        p for p in all_paths 
        if sha256 in p.binary or p.binary == sha256
    ]
    
    return binary_paths
    ### END YOUR CODE HERE ###
```

**Key elements:**
- Imports Lab 3.2's detection functions
- Calls all four vulnerability detection functions
- Filters results to the specified binary

### Function 5 — `analyze_all_paths_for_binary()`

This function analyzes all Lab 3.2 paths for a binary and returns ranked `PathRiskAnalysis` objects.

**What to implement:** Orchestrate the full analysis pipeline.

```python
def analyze_all_paths_for_binary(
    driver: Driver,
    database: str,
    sha256: str,
) -> List[PathRiskAnalysis]:
    """
    Complete Lab 3.2 → Lab 3.3 pipeline for a binary.
    
    1. Get all source-to-sink paths from Lab 3.2
    2. Analyze each path's complexity and traversal likelihood
    3. Calculate risk scores
    4. Return ranked list of PathRiskAnalysis objects
    """
    ### YOUR CODE HERE ###
    # Step 1: Get Lab 3.2 paths
    paths = get_paths_for_binary(driver, database, sha256)
    
    if not paths:
        return []
    
    # Step 2-3: Analyze each path
    risk_analyses: List[PathRiskAnalysis] = []
    
    for path in paths:
        # Get complexity metrics
        complexity = analyze_path_complexity(driver, database, path)
        
        # Get traversal likelihood
        traversal = analyze_path_traversal_likelihood(driver, database, path)
        
        # Calculate risk score
        risk_score, risk_level = calculate_path_risk_score(
            complexity, traversal, path.vulnerability_type
        )
        
        # Normalize individual scores for the dataclass
        complexity_score = min(complexity.cyclomatic_complexity / 30, 1.0)
        traversal_score = min(traversal.caller_count / 5, 0.5) + (1.0 - traversal.dark_code_ratio) * 0.5
        
        # Create PathRiskAnalysis
        analysis = PathRiskAnalysis(
            binary=path.binary,
            function=path.function,
            address=path.address,
            source_apis=path.source_apis,
            sink_apis=path.sink_apis,
            vulnerability_type=path.vulnerability_type,
            complexity_metrics=complexity,
            traversal_metrics=traversal,
            complexity_score=complexity_score,
            traversal_score=traversal_score,
            combined_risk_score=risk_score,
            risk_level=risk_level,
            priority_rank=0,  # Set after sorting
            recommendations=[],  # Generated by LLM in report
        )
        risk_analyses.append(analysis)
    
    # Step 4: Rank by risk score (highest first)
    risk_analyses.sort(key=lambda x: x.combined_risk_score, reverse=True)
    for i, analysis in enumerate(risk_analyses):
        analysis.priority_rank = i + 1
    
    return risk_analyses
    ### END YOUR CODE HERE ###
```

**Key elements:**
- Calls `get_paths_for_binary()` to get Lab 3.2 results
- Analyzes each path with complexity and traversal functions
- Calculates risk scores and ranks results

---

## ✅ Success Criteria

Your implementation is complete when:

- [ ] All 5 functions are implemented in `student_labs/lab3/complexity_analysis.py`
- [ ] The CLI runs without errors:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.complexity_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd
  ```
- [ ] Risk scoring produces meaningful differentiation between paths
- [ ] All tests pass:
  ```bash
  source venv/bin/activate
  python -m student_labs.lab3.test.test_lab_3_3
  ```

> 💡 **Next Step:** After completing Lab 3.3, proceed to **Lab 3.4** to generate comprehensive LLM-powered vulnerability triage reports that synthesize findings from Labs 3.1-5.3.

---

## Summary

In this lab, you implemented:

| Component | What It Does |
|-----------|--------------|
| **Path Complexity Analysis** | Calculate cyclomatic complexity, branch count, and basic block count for Lab 3.2 paths |
| **Traversal Likelihood Analysis** | Measure entry point connectivity, caller count, and dark code ratio |
| **Risk Scoring** | Combine complexity + traversal + severity into a 0-100 risk score |
| **Lab 3.2 Integration** | Call Lab 3.2's API to retrieve source-to-sink paths |
| **Batch Analysis** | Analyze all paths for a binary and rank by risk |

**Key Insight:** Lab 3.3 doesn't find new vulnerabilities—it **quantifies** the ones Lab 3.2 found. By analyzing complexity and traversal likelihood, Lab 3.3 transforms a list of potential vulnerabilities into a prioritized triage queue.

**Next:** Lab 3.4 uses LLM to synthesize Lab 3.3's ranked results into comprehensive vulnerability triage reports with executive summaries and actionable recommendations.

---

## 📚 Additional Reading

### The Lab 3.1 → 5.2 → 5.3 Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE VULNERABILITY ANALYSIS PIPELINE                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   LAB 5.1                    LAB 5.2                    LAB 5.3             │
│   Input Sources              Source-to-Sink            Path Risk            │
│                              Paths                     Analysis             │
│                                                                              │
│   ┌─────────────┐           ┌─────────────┐           ┌─────────────┐       │
│   │ recv()      │           │ recv() →    │           │ Score: 87   │       │
│   │ fread()     │──────────▶│ strcpy()    │──────────▶│ CRITICAL    │       │
│   │ getenv()    │           │             │           │             │       │
│   └─────────────┘           └─────────────┘           └─────────────┘       │
│                                                                              │
│   "Where does              "Can input                "Which paths          │
│    input enter?"            reach sinks?"             are highest risk?"   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Complexity Metrics Explained

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| **Cyclomatic Complexity** | E - N + 2 | Number of independent paths through the code |
| **Branch Count** | Count of edges | Number of conditional branches |
| **Basic Block Count** | Count of nodes | Size of the function |
| **Nesting Depth** | Max depth | How deeply nested the code is |

### Traversal Likelihood Metrics Explained

| Metric | What It Measures | Why It Matters |
|--------|------------------|----------------|
| **Entry Point Connectivity** | How many entry points can reach this function | Functions reachable from `main` are more likely to execute |
| **Caller Count** | Number of functions that call this function | More callers = more likely to be executed |
| **Dark Code Ratio** | Percentage of low-connectivity blocks | High ratio suggests rarely-tested code |
| **Is Error Handler** | Whether the path is in error handling code | Error handlers are less frequently executed |

### CLI Reference

```bash
source venv/bin/activate

# Analyze all Lab 3.2 paths for a specific binary
python -m student_labs.lab3.complexity_analysis --sha256 <binary_sha256>

# Show only critical/high risk paths
python -m student_labs.lab3.complexity_analysis --sha256 <hash> --min-risk high

# Analyze all binaries in database
python -m student_labs.lab3.complexity_analysis --all

# Show detailed metrics for each path
python -m student_labs.lab3.complexity_analysis --sha256 <hash> --verbose
```

| Flag | Description |
|------|-------------|
| `--sha256 <hash>` | Analyze paths for a specific binary |
| `--all` | Analyze all binaries in database |
| `--min-risk <level>` | Filter to paths at or above risk level (critical, high, medium, low) |
| `--verbose` | Show detailed metrics for each path |

### Connection to Lab 3.4

**Lab 3.4 (Vulnerability Triage Report):** Takes Lab 3.3's ranked `PathRiskAnalysis` results along with Lab 3.1 and 5.2 findings and uses LLM to generate comprehensive vulnerability triage reports with executive summaries and actionable recommendations. See Lab 3.4 for LLM-powered report generation.
