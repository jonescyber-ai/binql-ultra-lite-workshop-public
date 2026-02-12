# 🧪 Lab 3 Overview — Graph-Based Vulnerability Analysis: From Unsafe APIs to Exploit Paths

Lab 3 introduces **graph-based vulnerability analysis** using Cypher queries against the program graph in Neo4j. Building on the malware analysis techniques from Lab 1, this lab shifts focus from malicious capabilities to *vulnerable code patterns*—unsafe API usage, exploitable paths, and code regions that warrant security scrutiny.

The core insight is that vulnerability analysis shares the same foundational primitive as malware analysis: **CFG reachability**. The same query patterns that find behavioral APIs in Lab 1 can find *vulnerable* APIs in Lab 3. By anchoring vulnerability signals to execution paths from function entry points, we answer the critical question: *"Can this vulnerable code actually be reached?"*

This lab builds on the program graph from Lab 1, the graph query skills from Lab 2, and the CFG reachability patterns from Lab 1. You will execute Cypher queries that detect unsafe API usage, trace exploit paths to risky sinks, identify reused vulnerable code across binaries, and highlight complex or rarely-exercised code regions that may hide subtle vulnerabilities.

**Why Graph-Based Vulnerability Analysis?** Traditional vulnerability scanning often produces overwhelming results—thousands of potential issues with no prioritization. By combining CFG reachability with cyclomatic complexity, code coverage patterns, and cross-binary analysis, the graph enables *risk-prioritized* vulnerability triage that focuses analyst effort on the most exploitable and impactful findings.

---

## ⚡ TL;DR

- **Lab 3.1**: Detect user-controlled input sources (network, file, stdin, environment, IPC, command-line)
- **Lab 3.2**: Use Lab 3.1's input sources to find paths to dangerous sinks (buffer overflows, format strings, command injection)
- **Lab 3.3**: Analyze complex and "dark" code regions for hidden vulnerabilities
- **Lab 3.4**: Generate LLM-powered vulnerability triage reports combining all Lab 3 analysis

What you will do:
- **Detect** user-controlled input sources where attackers can inject data
- **Trace** CFG-bounded paths from Lab 3.1's input sources to dangerous sinks
- **Highlight** cyclomatically complex regions that also use dangerous APIs
- **Find** rarely-visited or unreachable "dark" code that may hide subtle vulnerabilities
- **Generate** comprehensive triage reports using LLM to synthesize vulnerability findings

---

> ⚠️ **SETUP REQUIRED:** Before starting any Lab 3 sub-labs, you must complete the **🔧 Lab Setup** section below to ingest the vulnerability analysis samples into Neo4j.

---

### 📂 Student-Accessible Folders

| Folder | Purpose |
|--------|---------|
| `dataset/lab3/` | Lab datasets (binaries with known vulnerabilities for analysis) |
| `bccs/` | Pre-generated BCC files |
| `lab_common/` | Shared utilities including binql_ul |
| `venv/` | Python virtual environment |
| `docs/` | Documentation and lab instructions |

---

### Prerequisites

- Neo4j running and reachable
- Course Python environment available
- Familiarity with Cypher queries (Lab 2)
- Understanding of program graphs (Lab 1)
- Completion of Lab 1 (graph query patterns)

### Setup

```bash
source venv/bin/activate
```

---

## 🎯 Why Graph-Based Vulnerability Analysis?

Traditional vulnerability analysis approaches have significant limitations:

- **Alert fatigue**: Static analyzers produce thousands of warnings with no prioritization
- **Missing context**: Knowing an unsafe API exists doesn't tell you if it's reachable or exploitable
- **Single-binary focus**: Vulnerabilities in shared libraries affect multiple binaries
- **Complexity blindness**: Simple metrics miss the interaction between complexity and dangerous APIs

**Graph-based vulnerability analysis** addresses these limitations by:

1. **Verifying reachability**: Only flag vulnerabilities in code paths that can actually execute
2. **Tracing exploit paths**: Find paths from user-controlled input to dangerous sinks
3. **Cross-binary analysis**: Identify reused vulnerable code across firmware or software ecosystems
4. **Risk prioritization**: Combine multiple signals (complexity, reachability, API danger) for triage

The key insight is that **the same CFG reachability primitive from Lab 1 powers vulnerability analysis**. The query pattern `(entry)-[:BRANCHES_TO*]->(bb)-[:CALLS_TO]->(imp)` that finds malicious APIs also finds vulnerable APIs—the difference is in *which* APIs you search for and *how* you interpret the results.

### From Malware Analysis to Vulnerability Analysis

| Lab 1 (Triage) | Lab 3 (Vulnerability) | Shared Primitive |
|-----------------|----------------------|------------------|
| Find network C2 APIs | Find unsafe string APIs | CFG reachability to imports |
| Detect anti-analysis | Detect missing bounds checks | Structural pattern queries |
| Cluster by behavior | Find reused vulnerable code | Cross-binary graph queries |
| Triage by capability | Triage by exploitability | Multi-signal prioritization |

> 💡 **Key Principle:** Vulnerability analysis is capability detection with a different lens. Instead of asking "What malicious things can this code do?", we ask "What dangerous things can happen to this code?"

---

## 🔧 Lab Setup: Ingest the Vulnerability Analysis Samples

> ⚠️ **REQUIRED:** You must complete this setup before starting any Lab 3 sub-labs. The queries in Labs 3.1–3.4 require binaries to be ingested in Neo4j.

This lab uses binaries from the `dataset/lab3/` folder containing known vulnerability patterns for analysis.

### Step 1: Reset the Database

Start with a clean database to ensure consistent results:

```bash
source venv/bin/activate
python -m lab_common.binql.binql_ul --reset
```

### Step 2: Ingest Lab 3 Binaries

Ingest the binaries from the `dataset/lab3/` folder:

```bash
source venv/bin/activate
python -m lab_common.binql.binql_ul --bcc_dir dataset/lab3/
```

### Step 3: Verify Ingestion

Verify all binaries are in the database:

```bash
source venv/bin/activate
python -m lab_common.binql.binql_ul --list-binaries
```

You should see the Lab 3 dataset binaries listed:

| Name | SHA256 | Funcs | BCC | Decomp | Class |
|------|--------|-------|-----|--------|-------|
| *(binaries from dataset/lab3/)* | ... | ... | ✓ | ✓ | unknown |

---

## 🧱 Lab Breakdown

| Sub-Lab | Type | Description |
|---------|------|-------------|
| **Lab 3.1** | 📝 Query Implementation | User-Controlled Input Detection — implement a base query function and 6 specialized detection functions to identify attack entry points (network, file, stdin, environment, IPC, command-line input sources) |
| **Lab 3.2** | ✏️ Implementation | Source-to-Sink Path Analysis — implement functions that use Lab 3.1's detected input sources to find CFG paths that reach dangerous sinks (buffer overflows, format strings, command injection), plus LLM-based classification to discover dangerous sinks not in hardcoded lists |
| **Lab 3.3** | ✏️ Implementation | Complexity and Dark Code Analysis — highlight cyclomatically complex regions with dangerous APIs and find rarely-visited or unreachable code that may hide subtle vulnerabilities |
| **Lab 3.4** | ✏️ Implementation | Vulnerability Triage Report — use LLM to synthesize findings from Labs 3.1–3.3 into comprehensive, prioritized vulnerability triage reports with actionable recommendations |

### 📂 Student Files

| Sub-Lab | Student File |
|---------|--------------|
| **Lab 3.1** | `student_labs/lab3/user_input_detection.py` |
| **Lab 3.2** | `student_labs/lab3/source_to_sink_analysis.py` |
| **Lab 3.3** | `student_labs/lab3/complexity_analysis.py` |
| **Lab 3.4** | `student_labs/lab3/vulnerability_triage_report.py` |

---

## Query Categories

### User-Controlled Input Detection Queries (Lab 3.1)

These queries answer: **"Where can an attacker inject data into this program?"**

| Query | Input Source | Key APIs |
|-------|--------------|----------|
| **1. Network Input** | Sockets, HTTP, SSL/TLS | `recv`, `recvfrom`, `WSARecv`, `InternetReadFile`, `SSL_read` |
| **2. File Input** | Files, memory-mapped regions | `fread`, `fgets`, `ReadFile`, `mmap`, `MapViewOfFile` |
| **3. Standard Input** | stdin, console | `scanf`, `gets`, `fgets`, `getchar`, `ReadConsoleA` |
| **4. Environment Variables** | Environment configuration | `getenv`, `GetEnvironmentVariableA`, `ExpandEnvironmentStringsA` |
| **5. IPC Input** | Message queues, shared memory, pipes, RPC | `msgrcv`, `shmat`, `PeekNamedPipe`, `RpcServerListen`, `CoCreateInstance` |
| **6. Command-Line Arguments** | argv processing | `getopt`, `getopt_long`, `CommandLineToArgvW`, `GetCommandLineA` |

### Source-to-Sink Path Analysis Queries (Lab 3.2)

These queries answer: **"Can user input from Lab 3.1's sources reach dangerous sinks?"**

Lab 3.2 builds directly on Lab 3.1 by taking the detected input sources (network, file, stdin, etc.) and tracing CFG paths to dangerous sinks:

| Query | Pattern | Dangerous Sinks | What It Reveals |
|-------|---------|-----------------|-----------------|
| **7. Buffer Overflow Paths** | Source → ... → `strcpy`, `sprintf`, `gets` | Unsafe string APIs | Exploitable buffer overflows |
| **8. Format String Paths** | Source → ... → `printf`, `syslog` | Format functions with user data | Format string vulnerabilities |
| **9. Command Injection Paths** | Source → ... → `system`, `popen`, `exec*` | Command execution APIs | OS command injection |
| **10. Path Traversal Paths** | Source → ... → `fopen`, `open` | File access APIs | Directory traversal attacks |

---

## 🧠 Key Concepts

| Concept | Description |
|---------|-------------|
| **User-Controlled Input Detection** | Identifying where external data enters the program (network, file, stdin, environment, IPC, command-line). These are the attack entry points where adversaries inject malicious data. |
| **Exploit Path Tracing** | Following CFG paths from user-controlled input sources to dangerous sinks, identifying code flows that could be exploited. Combines data flow intuition with control flow reachability. |
| **Cyclomatic Complexity + Risk** | Combining code complexity metrics with dangerous API usage to prioritize review. Complex code with unsafe APIs is higher risk than simple code with the same APIs. |
| **Dark Code Analysis** | Finding rarely-executed or unreachable code regions that may hide subtle vulnerabilities. Attackers often target code paths that developers and testers overlook. |
| **LLM-Powered Triage Reports** | Using LLM to synthesize vulnerability findings from multiple analysis passes into comprehensive, prioritized reports with executive summaries, risk assessments, and actionable recommendations. |

---

## 📋 Vulnerability Triage Prioritization

Understanding how to prioritize vulnerability findings is essential for effective security analysis:

| Priority | Criteria | Action |
|----------|----------|--------|
| **🔴 Critical** | Reachable unsafe API + user input path + high complexity | Immediate review and fix |
| **🟠 High** | Reachable unsafe API + user input path | Review within sprint |
| **🟡 Medium** | Reachable unsafe API (no clear input path) | Schedule for review |
| **🟢 Low** | Unsafe API in unreachable/dead code | Document, deprioritize |

### Combining Signals for Triage

**No single query provides complete vulnerability assessment.** Effective triage combines multiple signals:

| Signal | Source | Weight |
|--------|--------|--------|
| **Input Source Detection** | Lab 3.1 queries | Where can attackers inject data (network, file, stdin, etc.) |
| **Exploit Path Reachability** | Lab 3.2 queries | Can user input reach dangerous sinks |
| **Code Complexity** | Lab 3.3 queries | How complex is the surrounding code |
| **Dark Code Regions** | Lab 3.3 queries | Rarely-executed code that may hide vulnerabilities |
| **LLM Synthesis** | Lab 3.4 report | Comprehensive triage with prioritized recommendations |

> 💡 **Key Principle:** Vulnerability triage is about prioritization, not exhaustive analysis. Lab 3.4 uses LLM to synthesize all signals into actionable reports.

---

## 🧭 Workshop Wrap-Up

Lab 3 is the **final lab** in this workshop. Together, Labs 1–3 demonstrate the full arc of graph-grounded binary analysis:

| Lab | What You Learned |
|-----|-----------------|
| **Lab 1** | Load binaries into a graph and explore program structure with Cypher |
| **Lab 2** | Build NL2GQL — ask questions in English, get graph-backed answers |
| **Lab 3** | Use the graph for vulnerability analysis — from input detection to LLM-powered triage reports |

The techniques you've practiced — CFG reachability, cross-binary queries, LLM synthesis — are building blocks that extend naturally to malware analysis, CVE triage, firmware ecosystems, and agentic workflows. The richer **binql-lite** (used in our 4-day courses) and the upcoming **full open-source binql** build on exactly these foundations.

> 💡 **Key Principle:** The graph is the interface between analyst intent and automated reasoning — *structure first, then automate*.

---

## 📚 Additional Reading

For deeper understanding of the vulnerability analysis techniques:

- **CWE (Common Weakness Enumeration)** — Standardized taxonomy of software weaknesses
- **NVD (National Vulnerability Database)** — CVE details and severity scores
- **OWASP Top 10** — Common web application vulnerabilities
- Neo4j Cypher documentation for advanced query patterns
