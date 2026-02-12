"""
Lab 3.2: Source-to-Sink Path Analysis Module.

This module provides functions to find CFG paths from user-controlled input
sources (Lab 3.1) to dangerous sinks (buffer overflow, format string, command
injection, path traversal). This is the core of taint analysis—tracking how
untrusted data flows to security-sensitive operations.

The module uses a **base query pattern** to avoid repetition:
1. `_find_source_to_sink_paths_base()` - Contains the CFG path query (students implement once)
2. `find_*_paths()` functions - Call the base function with their specific API lists

Students implement the base query once, then implement each specialized function
by defining source and sink API lists and calling the base function.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.source_to_sink_analysis --help

    # Run all source-to-sink queries
    python -m student_labs.lab3.source_to_sink_analysis --all

    # Run specific vulnerability query
    python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow
    python -m student_labs.lab3.source_to_sink_analysis --format-string

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab3.source_to_sink_analysis --all

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should fill in
      the query placeholders marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab3/lab_3_2_source_to_sink_analysis.md
"""

import argparse
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import Driver, GraphDatabase

from lab_common.binql import get_neo4j_credentials

# Import Lab 3.1 API for binary-specific user input source detection
from student_labs.lab3.user_input_detection import (
    get_user_input_sources_for_binary,
    UserInputSourceDetail,
)

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab3 import source_to_sink_analysis_reference as _ref
    logger.info("Using reference implementation for source_to_sink_analysis")


@dataclass
class SourceToSinkPath:
    """Result from a source-to-sink path query."""

    binary: str
    function: str
    address: Optional[str] = None
    source_apis: List[str] = field(default_factory=list)
    sink_apis: List[str] = field(default_factory=list)
    source_count: int = 0
    sink_count: int = 0
    vulnerability_type: str = ""


def run_query(driver: Driver, database: str, query: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Execute a Cypher query and return results as a list of dictionaries.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        query: Cypher query string to execute.
        limit: Maximum number of results (0 = no limit).

    Returns:
        List of dictionaries, where each dictionary represents a row with
        column names as keys.
    """
    if _USE_REFERENCE:
        return _ref.run_query(driver, database, query, limit)

    # Add LIMIT clause if not already present and limit > 0
    query_upper = query.upper().strip()
    if limit > 0 and "LIMIT" not in query_upper:
        query = f"{query.rstrip().rstrip(';')} LIMIT {limit}"

    with driver.session(database=database) as session:
        result = session.run(query)
        records = list(result)
        keys = result.keys() if records else []

        # Convert Neo4j records to plain dictionaries
        output = []
        for record in records:
            row = {}
            for key in keys:
                value = record.get(key)
                # Convert Neo4j types to Python types
                if hasattr(value, "__iter__") and not isinstance(value, (str, dict)):
                    value = list(value)
                row[key] = value
            output.append(row)

        return output


# =============================================================================
# Helper Function for Converting Query Results to SourceToSinkPath
# =============================================================================

def _convert_to_source_to_sink_paths(
    rows: List[Dict[str, Any]],
    vulnerability_type: str = "",
) -> List[SourceToSinkPath]:
    """
    Convert query result rows to SourceToSinkPath objects.

    Args:
        rows: List of dictionaries from run_query().
        vulnerability_type: Type of vulnerability (e.g., "buffer_overflow").

    Returns:
        List of SourceToSinkPath objects.
    """
    results = []
    for row in rows:
        results.append(SourceToSinkPath(
            binary=row.get("binary", ""),
            function=row.get("function", ""),
            address=hex(row["address"]) if row.get("address") else None,
            source_apis=row.get("source_apis", []),
            sink_apis=row.get("sink_apis", []),
            source_count=row.get("source_count", 0),
            sink_count=row.get("sink_count", 0),
            vulnerability_type=vulnerability_type,
        ))
    return results


# =============================================================================
# Base Query Function - Students Implement the Query Here (ONCE)
# =============================================================================


def _find_source_to_sink_paths_base(
    driver: Driver,
    database: str,
    source_apis: List[str],
    sink_apis: List[str],
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """
    Base function for finding source-to-sink paths using CFG reachability.

    This function contains the core Cypher query that finds functions where:
    1. A user-controlled input API is reachable from the entry point
    2. A dangerous sink API is reachable FROM the source API

    All specialized detection functions (find_buffer_overflow_paths, etc.)
    call this base function with their specific source and sink API lists.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        source_apis: List of input source API names (from Lab 3.1).
        sink_apis: List of dangerous sink API names.
        limit: Maximum number of results.

    Returns:
        List of SourceToSinkPath objects containing:
        - binary: Binary name/hash
        - function: Function name
        - address: Function start address (hex)
        - source_apis: List of input source APIs found
        - sink_apis: List of dangerous sink APIs found
        - source_count: Number of distinct source APIs
        - sink_count: Number of distinct sink APIs

    Example:
        >>> results = _find_source_to_sink_paths_base(
        ...     driver, "neo4j",
        ...     source_apis=["recv", "fread"],
        ...     sink_apis=["strcpy", "sprintf"]
        ... )
        >>> for r in results:
        ...     print(f"{r.function}: {r.source_apis} -> {r.sink_apis}")
    """
    if _USE_REFERENCE:
        return _ref._find_source_to_sink_paths_base(driver, database, source_apis, sink_apis, limit)

    # Build the API list strings for the query
    source_api_str = ", ".join(f"'{api}'" for api in source_apis)
    sink_api_str = ", ".join(f"'{api}'" for api in sink_apis)

    # =========================================================================
    # STUDENTS: Paste your Cypher query below (between the triple quotes)
    # This query finds functions where:
    # 1. An input source API is reachable from the entry point
    # 2. A dangerous sink API is reachable FROM the source
    #
    # Use {source_api_str} for the source APIs and {sink_api_str} for sink APIs.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Write a Cypher query that finds paths from source APIs to sink APIs.
    # Use {source_api_str} and {sink_api_str} in your query.
    query = ""
    ### END YOUR CODE HERE ###

    # Execute query and convert results
    rows = run_query(driver, database, query, limit)
    return _convert_to_source_to_sink_paths(rows)


# =============================================================================
# Specialized Detection Functions - Students Call Base Function Here
# =============================================================================


def find_buffer_overflow_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """
    Find paths from user input to buffer overflow sinks.

    Detects functions where user-controlled input can reach dangerous
    string/memory copy operations that may cause buffer overflows.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of SourceToSinkPath objects with buffer overflow paths.
    """
    if _USE_REFERENCE:
        return _ref.find_buffer_overflow_paths(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the source and sink API lists, then call the base function.
    # Copy this entire block including the api_list definitions.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define source_apis and sink_apis lists, then call _find_source_to_sink_paths_base.
    # Set vulnerability_type = "buffer_overflow" on each result.
    pass
    ### END YOUR CODE HERE ###


def find_format_string_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """
    Find paths from user input to format string sinks.

    Detects functions where user-controlled input can reach printf-family
    functions as the format argument, enabling format string attacks.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of SourceToSinkPath objects with format string paths.
    """
    if _USE_REFERENCE:
        return _ref.find_format_string_paths(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the source and sink API lists, then call the base function.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define source_apis and sink_apis lists, then call _find_source_to_sink_paths_base.
    # Set vulnerability_type = "format_string" on each result.
    pass
    ### END YOUR CODE HERE ###


def find_command_injection_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """
    Find paths from user input to command execution sinks.

    Detects functions where user-controlled input can reach shell execution
    or process creation APIs, enabling OS command injection.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of SourceToSinkPath objects with command injection paths.
    """
    if _USE_REFERENCE:
        return _ref.find_command_injection_paths(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the source and sink API lists, then call the base function.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define source_apis and sink_apis lists, then call _find_source_to_sink_paths_base.
    # Set vulnerability_type = "command_injection" on each result.
    pass
    ### END YOUR CODE HERE ###


def find_path_traversal_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[SourceToSinkPath]:
    """
    Find paths from user input to file operation sinks.

    Detects functions where user-controlled input can reach file open/create
    operations, enabling path traversal attacks (e.g., ../../../etc/passwd).

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of SourceToSinkPath objects with path traversal paths.
    """
    if _USE_REFERENCE:
        return _ref.find_path_traversal_paths(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the source and sink API lists, then call the base function.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define source_apis and sink_apis lists, then call _find_source_to_sink_paths_base.
    # Set vulnerability_type = "path_traversal" on each result.
    pass
    ### END YOUR CODE HERE ###


# =============================================================================
# Aggregation Functions
# =============================================================================


def get_all_vulnerability_paths(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> Dict[str, List[SourceToSinkPath]]:
    """
    Run all source-to-sink path queries and return combined results.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum results per category.

    Returns:
        Dictionary mapping vulnerability type to lists of SourceToSinkPath objects.
    """
    return {
        "buffer_overflow": find_buffer_overflow_paths(driver, database, limit),
        "format_string": find_format_string_paths(driver, database, limit),
        "command_injection": find_command_injection_paths(driver, database, limit),
        "path_traversal": find_path_traversal_paths(driver, database, limit),
    }


def get_high_risk_functions(
    driver: Driver,
    database: str,
    min_vuln_types: int = 2,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Find functions with multiple vulnerability types.

    Functions that have paths to multiple types of dangerous sinks are
    higher-risk targets because they have more potential attack vectors.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        min_vuln_types: Minimum number of vulnerability types to be considered high-risk.
        limit: Maximum number of results.

    Returns:
        List of dictionaries with function info and their vulnerability types.
    """
    all_results = get_all_vulnerability_paths(driver, database, limit=0)

    # Build a map of (binary, function) -> set of vulnerability types
    function_vulns: Dict[tuple, Dict[str, Any]] = {}

    for vuln_type, results in all_results.items():
        for result in results:
            key = (result.binary, result.function)
            if key not in function_vulns:
                function_vulns[key] = {
                    "binary": result.binary,
                    "function": result.function,
                    "address": result.address,
                    "vuln_types": set(),
                    "all_source_apis": [],
                    "all_sink_apis": [],
                }
            function_vulns[key]["vuln_types"].add(vuln_type)
            function_vulns[key]["all_source_apis"].extend(result.source_apis)
            function_vulns[key]["all_sink_apis"].extend(result.sink_apis)

    # Filter to functions with multiple vulnerability types
    high_risk = []
    for func_info in function_vulns.values():
        if len(func_info["vuln_types"]) >= min_vuln_types:
            high_risk.append({
                "binary": func_info["binary"],
                "function": func_info["function"],
                "address": func_info["address"],
                "vuln_types": sorted(func_info["vuln_types"]),
                "vuln_count": len(func_info["vuln_types"]),
                "source_apis": list(set(func_info["all_source_apis"])),
                "sink_apis": list(set(func_info["all_sink_apis"])),
            })

    # Sort by vulnerability count descending
    high_risk.sort(key=lambda x: (-x["vuln_count"], x["binary"], x["function"]))

    return high_risk[:limit] if limit > 0 else high_risk


# =============================================================================
# Binary-Specific Source-to-Sink Analysis (Using Lab 3.1 API)
# =============================================================================


@dataclass
class DetailedSourceToSinkPath:
    """
    Detailed source-to-sink path with basic block addresses.

    This dataclass extends SourceToSinkPath with granular call-site information
    from Lab 3.1's get_user_input_sources_for_binary() API.
    """

    binary: str
    sha256: str
    function: str
    function_address: str
    source_api: str
    source_basic_block: str
    source_category: str  # network, file, stdin, environment, ipc, cmdline
    sink_api: str
    sink_basic_block: str
    vulnerability_type: str  # buffer_overflow, format_string, command_injection, path_traversal


# Dangerous sink APIs by vulnerability type
BUFFER_OVERFLOW_SINKS = [
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf",
    "gets",
    "memcpy", "memmove", "bcopy",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",
]

FORMAT_STRING_SINKS = [
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "syslog", "vsyslog",
    "wprintf", "fwprintf", "swprintf",
]

COMMAND_INJECTION_SINKS = [
    "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW",
    "WinExec",
]

PATH_TRAVERSAL_SINKS = [
    "fopen", "freopen", "open", "openat",
    "CreateFileA", "CreateFileW",
    "DeleteFileA", "DeleteFileW",
    "RemoveDirectoryA", "RemoveDirectoryW",
    "rename", "remove", "unlink",
]


def find_source_to_sink_paths_for_binary(
    driver: Driver,
    database: str,
    sha256: str,
    include_llm_classification: bool = True,
    limit: int = 500,
) -> List[DetailedSourceToSinkPath]:
    """
    Find source-to-sink paths for a specific binary using Lab 3.1's API.

    This function leverages get_user_input_sources_for_binary() from Lab 3.1
    to get detailed user-input source information (including basic block addresses),
    then traces paths from those sources to dangerous sinks.

    NOTE: This function is PROVIDED - students do not need to implement it.
    It demonstrates how Lab 3.2 leverages Lab 3.1's API.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to analyze.
        include_llm_classification: If True, use LLM to discover additional input sources.
        limit: Maximum number of results.

    Returns:
        List of DetailedSourceToSinkPath objects with granular call-site information.

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.

    Example:
        >>> paths = find_source_to_sink_paths_for_binary(driver, "neo4j", "abc123...")
        >>> for p in paths:
        ...     print(f"{p.source_api} @ {p.source_basic_block} -> {p.sink_api} @ {p.sink_basic_block}")
    """
    if _USE_REFERENCE:
        return _ref.find_source_to_sink_paths_for_binary(driver, database, sha256, include_llm_classification, limit)

    # Step 1: Get user input sources from Lab 3.1 API
    input_sources = get_user_input_sources_for_binary(
        driver, database, sha256,
        include_llm_classification=include_llm_classification,
    )

    if not input_sources:
        logger.info(f"No user input sources found for binary {sha256[:16]}...")
        return []

    logger.info(f"Found {len(input_sources)} user input sources from Lab 3.1 API")

    # Step 2: Build sink API lists by vulnerability type
    sink_categories = {
        "buffer_overflow": BUFFER_OVERFLOW_SINKS,
        "format_string": FORMAT_STRING_SINKS,
        "command_injection": COMMAND_INJECTION_SINKS,
        "path_traversal": PATH_TRAVERSAL_SINKS,
    }

    all_sinks = []
    sink_to_vuln_type = {}
    for vuln_type, sinks in sink_categories.items():
        for sink in sinks:
            if sink not in sink_to_vuln_type:
                sink_to_vuln_type[sink] = vuln_type
                all_sinks.append(sink)

    sink_list_str = ", ".join(f"'{s}'" for s in all_sinks)

    # Step 3: For each input source, find paths to dangerous sinks
    results = []

    for source in input_sources:
        # Query for sinks reachable from this source's basic block
        query = f"""
        MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
        WHERE b.sha256 = $sha256 AND f.name = $function_name
        MATCH (src_bb:BasicBlock {{start_address: $source_bb_addr}})
        MATCH (src_bb)-[:BRANCHES_TO*0..15]->(sink_bb:BasicBlock)-[:CALLS_TO]->(sink:ImportSymbol)
        WHERE sink.name IN [{sink_list_str}]
        RETURN DISTINCT
            sink.name AS sink_api,
            sink_bb.start_address AS sink_bb_addr
        """

        try:
            # Convert hex string back to int for query
            source_bb_int = int(source.basic_block_address, 16)

            with driver.session(database=database) as session:
                result = session.run(query, {
                    "sha256": sha256,
                    "function_name": source.function,
                    "source_bb_addr": source_bb_int,
                })
                records = list(result)

            for record in records:
                sink_api = record["sink_api"]
                sink_bb_addr = record["sink_bb_addr"]
                vuln_type = sink_to_vuln_type.get(sink_api, "unknown")

                results.append(DetailedSourceToSinkPath(
                    binary=source.binary,
                    sha256=source.sha256,
                    function=source.function,
                    function_address=source.function_address,
                    source_api=source.api_name,
                    source_basic_block=source.basic_block_address,
                    source_category=source.input_category,
                    sink_api=sink_api,
                    sink_basic_block=hex(sink_bb_addr) if sink_bb_addr else "0x0",
                    vulnerability_type=vuln_type,
                ))

        except Exception as e:
            logger.warning(f"Error querying paths from {source.api_name}: {e}")
            continue

    logger.info(f"Found {len(results)} source-to-sink paths")
    return results[:limit] if limit > 0 else results


# =============================================================================
# Report Generation
# =============================================================================


def generate_vulnerability_report(
    driver: Driver,
    database: str,
    sha256: str,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a markdown vulnerability report for a specific binary.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to analyze.
        output_path: Optional path to write the markdown report.

    Returns:
        The markdown report as a string.
    """
    if _USE_REFERENCE:
        return _ref.generate_vulnerability_report(driver, database, sha256, output_path)

    from lab_common.llm.client import llm_completion
    import json

    # Get binary info
    query = """
    MATCH (b:Binary)
    WHERE b.sha256 = $sha256
    OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(f:Function)
    RETURN b.name AS name, b.sha256 AS sha256, count(f) AS function_count
    """
    with driver.session(database=database) as session:
        result = session.run(query, {"sha256": sha256})
        record = result.single()
        if record:
            binary_info = {
                "name": record["name"],
                "sha256": record["sha256"],
                "function_count": record["function_count"],
            }
        else:
            raise ValueError(f"No binary found with SHA256: {sha256}")

    # Get all vulnerability paths for this binary
    all_paths = get_all_vulnerability_paths(driver, database, limit=0)

    # Filter to this binary
    binary_paths = {}
    total_vulns = 0
    for vuln_type, paths in all_paths.items():
        filtered = [p for p in paths if sha256 in p.binary or binary_info["name"] in p.binary]
        if filtered:
            binary_paths[vuln_type] = filtered
            total_vulns += len(filtered)

    # Generate LLM analysis
    summary_data = {
        "binary_name": binary_info["name"],
        "function_count": binary_info["function_count"],
        "vulnerability_summary": {vt: len(paths) for vt, paths in binary_paths.items()},
        "total_vulnerable_paths": total_vulns,
        "sample_paths": {
            vt: [{"function": p.function, "sources": p.source_apis, "sinks": p.sink_apis}
                 for p in paths[:3]]
            for vt, paths in binary_paths.items()
        },
    }

    system_prompt = """You are an expert security analyst specializing in binary vulnerability analysis.
Based on the source-to-sink path analysis data provided, generate a vulnerability assessment report.

IMPORTANT CONTEXT: The paths identified show CFG (Control Flow Graph) reachability from user-controlled
input sources to dangerous sink APIs. This means there is a potential data flow from attacker-controlled
input to security-sensitive operations. However, this is static analysis - actual exploitability depends
on runtime conditions and data flow.

RESPONSE FORMAT: Return ONLY valid JSON (no markdown, no explanation outside JSON).
Schema:
{
  "executive_summary": "<2-3 paragraph summary of the binary's vulnerability exposure>",
  "risk_level": "<critical|high|medium|low>",
  "risk_justification": "<brief justification for the risk level>",
  "key_findings": ["<finding 1>", "<finding 2>", ...],
  "exploitation_scenarios": ["<scenario 1>", "<scenario 2>", ...],
  "recommendations": ["<recommendation 1>", "<recommendation 2>", ...]
}

Consider:
- Buffer overflow paths indicate potential memory corruption
- Format string paths indicate potential information disclosure or code execution
- Command injection paths indicate potential arbitrary command execution
- Path traversal paths indicate potential unauthorized file access
- Multiple vulnerability types in the same function increase risk"""

    prompt = f"Analyze this binary's vulnerability exposure:\n{json.dumps(summary_data, indent=2)}"

    try:
        context = llm_completion(prompt, system_prompt=system_prompt)
        llm_analysis = json.loads(context.response.strip())
    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Failed to get LLM analysis: {e}")
        llm_analysis = {
            "executive_summary": "Unable to generate automated analysis. Manual review recommended.",
            "risk_level": "unknown",
            "risk_justification": "Automated analysis failed",
            "key_findings": ["Manual analysis required"],
            "exploitation_scenarios": [],
            "recommendations": ["Perform manual security review"],
        }

    # Build markdown report
    report_lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Header
    report_lines.append("# Source-to-Sink Vulnerability Analysis Report")
    report_lines.append("")
    report_lines.append(f"**Generated:** {timestamp}")
    report_lines.append("")
    report_lines.append("> **Note:** This report identifies potential vulnerability paths where user-controlled")
    report_lines.append("> input can reach dangerous sink APIs. Actual exploitability requires manual verification.")
    report_lines.append("")

    # Binary Info
    report_lines.append("## Binary Information")
    report_lines.append("")
    report_lines.append("| Property | Value |")
    report_lines.append("|----------|-------|")
    report_lines.append(f"| **Name** | `{binary_info['name']}` |")
    report_lines.append(f"| **SHA256** | `{sha256}` |")
    report_lines.append(f"| **Functions** | {binary_info['function_count']} |")
    report_lines.append(f"| **Vulnerable Paths** | {total_vulns} |")
    report_lines.append("")

    # Risk Assessment
    risk_level = llm_analysis.get("risk_level", "unknown").upper()
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk_level, "⚪")
    report_lines.append("## Risk Assessment")
    report_lines.append("")
    report_lines.append(f"**Risk Level:** {risk_emoji} **{risk_level}**")
    report_lines.append("")
    report_lines.append(f"**Justification:** {llm_analysis.get('risk_justification', 'N/A')}")
    report_lines.append("")

    # Executive Summary
    report_lines.append("## Executive Summary")
    report_lines.append("")
    report_lines.append(llm_analysis.get("executive_summary", "No summary available."))
    report_lines.append("")

    # Key Findings
    if llm_analysis.get("key_findings"):
        report_lines.append("## Key Findings")
        report_lines.append("")
        for finding in llm_analysis["key_findings"]:
            report_lines.append(f"- {finding}")
        report_lines.append("")

    # Vulnerability Details
    report_lines.append("## Vulnerability Paths by Category")
    report_lines.append("")

    vuln_emoji = {
        "buffer_overflow": "💥",
        "format_string": "📝",
        "command_injection": "⚡",
        "path_traversal": "📁",
    }

    for vuln_type in ["buffer_overflow", "format_string", "command_injection", "path_traversal"]:
        paths = binary_paths.get(vuln_type, [])
        emoji = vuln_emoji.get(vuln_type, "❓")
        title = vuln_type.replace("_", " ").title()

        report_lines.append(f"### {emoji} {title} ({len(paths)} paths)")
        report_lines.append("")

        if not paths:
            report_lines.append("*No vulnerable paths detected.*")
            report_lines.append("")
        else:
            # Show ASCII art visualization for the first path in each category
            first_path = paths[0]
            report_lines.append("**Example Data Flow:**")
            report_lines.append("")
            report_lines.append("```")
            # Generate ASCII art for the path
            sources_display = first_path.source_apis[:3]
            sinks_display = first_path.sink_apis[:3]
            max_src_len = max(len(s) for s in sources_display) if sources_display else 8
            max_sink_len = max(len(s) for s in sinks_display) if sinks_display else 8

            report_lines.append("┌" + "─" * (max_src_len + 2) + "┐")
            report_lines.append("│ " + "SOURCES".center(max_src_len) + " │")
            report_lines.append("├" + "─" * (max_src_len + 2) + "┤")
            for src in sources_display:
                report_lines.append("│ " + src.ljust(max_src_len) + " │")
            if len(first_path.source_apis) > 3:
                report_lines.append("│ " + f"+{len(first_path.source_apis) - 3} more".ljust(max_src_len) + " │")
            report_lines.append("└" + "─" * (max_src_len + 2) + "┘")
            report_lines.append("         │")
            report_lines.append("         ▼")
            func_display = first_path.function[:30] + "..." if len(first_path.function) > 30 else first_path.function
            func_len = len(func_display)
            report_lines.append("┌" + "─" * (func_len + 4) + "┐")
            report_lines.append("│  " + func_display + "  │")
            report_lines.append("└" + "─" * (func_len + 4) + "┘")
            report_lines.append("         │")
            report_lines.append("         ▼")
            report_lines.append("┌" + "─" * (max_sink_len + 2) + "┐")
            report_lines.append("│ " + "SINKS".center(max_sink_len) + " │")
            report_lines.append("├" + "─" * (max_sink_len + 2) + "┤")
            for sink in sinks_display:
                report_lines.append("│ " + sink.ljust(max_sink_len) + " │")
            if len(first_path.sink_apis) > 3:
                report_lines.append("│ " + f"+{len(first_path.sink_apis) - 3} more".ljust(max_sink_len) + " │")
            report_lines.append("└" + "─" * (max_sink_len + 2) + "┘")
            report_lines.append("```")
            report_lines.append("")

            # Show table with all paths
            report_lines.append("**All Paths:**")
            report_lines.append("")
            report_lines.append("| Function | Source APIs | Sink APIs |")
            report_lines.append("|----------|-------------|-----------|")
            for p in paths[:10]:  # Limit to 10 per category
                sources = ", ".join(p.source_apis[:3])
                if len(p.source_apis) > 3:
                    sources += "..."
                sinks = ", ".join(p.sink_apis[:3])
                if len(p.sink_apis) > 3:
                    sinks += "..."
                report_lines.append(f"| `{p.function}` | {sources} | {sinks} |")
            if len(paths) > 10:
                report_lines.append(f"| ... | *{len(paths) - 10} more paths* | |")
            report_lines.append("")

    # Exploitation Scenarios
    if llm_analysis.get("exploitation_scenarios"):
        report_lines.append("## Potential Exploitation Scenarios")
        report_lines.append("")
        for scenario in llm_analysis["exploitation_scenarios"]:
            report_lines.append(f"- {scenario}")
        report_lines.append("")

    # Recommendations
    if llm_analysis.get("recommendations"):
        report_lines.append("## Recommendations")
        report_lines.append("")
        for i, rec in enumerate(llm_analysis["recommendations"], 1):
            report_lines.append(f"{i}. {rec}")
        report_lines.append("")

    # Footer
    report_lines.append("---")
    report_lines.append("")
    report_lines.append("*Report generated by Lab 3.2 Source-to-Sink Path Analysis*")

    report = "\n".join(report_lines)

    # Write to file if output_path specified
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(report, encoding="utf-8")
        logger.info(f"Report written to: {output_path}")

    return report


# =============================================================================
# LLM-Based Dangerous Sink Classification
# =============================================================================


def classify_sink_api_with_llm(api_name: str) -> Dict[str, Any]:
    """
    Use LLM to classify an API and determine if it's a dangerous sink.

    This function is analogous to Lab 3.1's classify_api_with_llm() but focuses
    on identifying dangerous sinks (buffer overflow, format string, command
    injection, path traversal) rather than user-controlled input sources.

    Args:
        api_name: The name of the API to classify.

    Returns:
        Dictionary with classification results:
        - api: The API name
        - is_dangerous_sink: Boolean indicating if this API is a dangerous sink
        - sink_category: Category (buffer_overflow, format_string, command_injection, path_traversal, other, none)
        - confidence: Confidence level (high, medium, low)
        - description: Brief description of what this API does
        - vulnerability_notes: Security considerations and potential vulnerabilities

    Example:
        >>> result = classify_sink_api_with_llm("strcpy")
        >>> print(result["is_dangerous_sink"])  # True
        >>> print(result["sink_category"])  # "buffer_overflow"
    """
    if _USE_REFERENCE:
        return _ref.classify_sink_api_with_llm(api_name)

    from lab_common.llm.client import llm_completion
    import json

    # =========================================================================
    # STUDENTS: Implement the LLM-based dangerous sink classification.
    #
    # 1. Define a system_prompt that instructs the LLM to:
    #    - Analyze the API name and determine if it's a dangerous sink
    #    - Return ONLY valid JSON (no markdown, no extra text)
    #    - Use this schema:
    #      {
    #        "api": "<api name>",
    #        "is_dangerous_sink": <true/false>,
    #        "sink_category": "<buffer_overflow|format_string|command_injection|path_traversal|other|none>",
    #        "confidence": "<high|medium|low>",
    #        "description": "<brief description>",
    #        "vulnerability_notes": "<security considerations>"
    #      }
    #
    # 2. Create a prompt that asks the LLM to classify the given api_name
    #
    # 3. Call llm_completion(prompt, system_prompt=system_prompt)
    #
    # 4. Parse the JSON response and return it
    #
    # 5. Handle errors gracefully (JSONDecodeError, other exceptions)
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Use LLM to classify the API as a dangerous sink.
    # Return a dictionary with classification results.
    pass
    ### END YOUR CODE HERE ###


def classify_sink_apis_batch_with_llm(
    api_names: List[str],
    batch_size: int = 20,
) -> List[Dict[str, Any]]:
    """
    Classify multiple APIs as dangerous sinks in batches to reduce LLM calls.

    This function is analogous to Lab 3.1's classify_apis_batch_with_llm() but
    focuses on identifying dangerous sinks rather than user-controlled input sources.

    Args:
        api_names: List of API names to classify.
        batch_size: Maximum APIs per LLM call (default: 20).

    Returns:
        List of classification results for each API. Each result contains:
        - api: The API name
        - is_dangerous_sink: Boolean indicating if this API is a dangerous sink
        - sink_category: Category (buffer_overflow, format_string, command_injection, path_traversal, other, none)
        - confidence: Confidence level (high, medium, low)
        - description: Brief description of what the API does
        - vulnerability_notes: Security considerations and potential vulnerabilities

    Example:
        >>> results = classify_sink_apis_batch_with_llm(["strcpy", "printf", "system"])
        >>> for r in results:
        ...     print(f"{r['api']}: {r['sink_category']} ({r['confidence']})")
    """
    if _USE_REFERENCE:
        return _ref.classify_sink_apis_batch_with_llm(api_names, batch_size)

    from lab_common.llm.client import llm_completion
    import json

    if not api_names:
        return []

    all_results = []

    # =========================================================================
    # STUDENTS: Implement batch API classification for dangerous sinks.
    #
    # Process APIs in batches of `batch_size` to reduce LLM calls.
    # For each batch:
    #
    # 1. Define a system_prompt that instructs the LLM to:
    #    - Analyze multiple API names and classify each one as a dangerous sink
    #    - Return ONLY a valid JSON array (no markdown, no extra text)
    #    - Each element should follow this schema:
    #      {
    #        "api": "<api name>",
    #        "is_dangerous_sink": <true/false>,
    #        "sink_category": "<buffer_overflow|format_string|command_injection|path_traversal|other|none>",
    #        "confidence": "<high|medium|low>",
    #        "description": "<brief description>",
    #        "vulnerability_notes": "<security considerations>"
    #      }
    #
    # 2. Create a prompt listing the APIs in the current batch
    #
    # 3. Call llm_completion(prompt, system_prompt=system_prompt)
    #
    # 4. Parse the JSON array response and extend all_results
    #
    # 5. Handle errors gracefully - on failure, fall back to classifying
    #    each API individually using classify_sink_api_with_llm()
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Process APIs in batches and classify each as a dangerous sink using LLM.
    # Return a list of classification results.
    pass
    ### END YOUR CODE HERE ###


def get_binary_sink_apis(driver: Driver, database: str, sha256: str) -> List[str]:
    """
    Extract all unique API names that could be dangerous sinks from a binary.

    This function queries the database for all ImportSymbols called by the binary
    and returns them for classification. It's analogous to Lab 3.1's get_binary_apis().

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to scan.

    Returns:
        List of unique API names found in the binary.

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.
    """
    if _USE_REFERENCE:
        return _ref.get_binary_sink_apis(driver, database, sha256)

    query = """
    MATCH (b:Binary)-[:HAS_FUNCTION]->(:Function)-[:ENTRY_BLOCK]->(:BasicBlock)
          -[:BRANCHES_TO*0..20]->(:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE b.sha256 = $sha256
    RETURN DISTINCT imp.name AS api
    ORDER BY api
    """
    params = {"sha256": sha256}

    with driver.session(database=database) as session:
        result = session.run(query, params)
        apis = [record["api"] for record in result]

    if not apis:
        # Check if the binary exists at all
        check_query = "MATCH (b:Binary) WHERE b.sha256 = $sha256 RETURN b.name AS name"
        with driver.session(database=database) as session:
            check_result = session.run(check_query, params)
            record = check_result.single()
            if record is None:
                raise ValueError(f"No binary found with SHA256: {sha256}")

    return apis


def classify_binary_sink_apis_with_llm(
    driver: Driver,
    database: str,
    sha256: str,
    filter_dangerous: bool = True,
    batch_size: int = 20,
) -> List[Dict[str, Any]]:
    """
    Extract all APIs from a binary and classify them as dangerous sinks using LLM.

    This function scans a binary for all its API calls, then uses an LLM to classify
    each API and determine if it's a potential dangerous sink. APIs are processed
    in batches for efficiency.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to scan (must be ingested in database).
        filter_dangerous: If True, only return APIs classified as dangerous sinks.
        batch_size: Maximum APIs per LLM call (default: 20).

    Returns:
        List of classification results for each API.

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.
    """
    if _USE_REFERENCE:
        return _ref.classify_binary_sink_apis_with_llm(driver, database, sha256, filter_dangerous, batch_size)

    apis = get_binary_sink_apis(driver, database, sha256)
    logger.info(f"Found {len(apis)} unique APIs to classify as sinks for binary {sha256[:16]}...")

    # Use batch classification for efficiency
    all_results = classify_sink_apis_batch_with_llm(apis, batch_size=batch_size)

    # Filter to dangerous sinks if requested
    if filter_dangerous:
        return [r for r in all_results if r.get("is_dangerous_sink", False)]

    return all_results


# =============================================================================
# CLI and Output Functions
# =============================================================================


def _generate_path_ascii_art(sources: List[str], sinks: List[str], function_name: str) -> str:
    """
    Generate ASCII art visualization for a source-to-sink path.

    Args:
        sources: List of source API names.
        sinks: List of sink API names.
        function_name: Name of the function containing the path.

    Returns:
        ASCII art string showing the data flow.
    """
    lines = []

    # Determine the max width needed
    max_source_len = max(len(s) for s in sources) if sources else 10
    max_sink_len = max(len(s) for s in sinks) if sinks else 10
    func_len = len(function_name)

    # Build the visualization
    lines.append("  ┌" + "─" * (max_source_len + 2) + "┐")
    lines.append("  │ " + "SOURCES".center(max_source_len) + " │")
    lines.append("  ├" + "─" * (max_source_len + 2) + "┤")
    for src in sources[:3]:  # Limit to 3 sources for readability
        lines.append("  │ " + src.ljust(max_source_len) + " │")
    if len(sources) > 3:
        lines.append("  │ " + f"... +{len(sources) - 3} more".ljust(max_source_len) + " │")
    lines.append("  └" + "─" * (max_source_len + 2) + "┘")
    lines.append("           │")
    lines.append("           ▼")
    lines.append("  ┌" + "─" * (func_len + 4) + "┐")
    lines.append("  │  " + function_name + "  │")
    lines.append("  └" + "─" * (func_len + 4) + "┘")
    lines.append("           │")
    lines.append("           ▼")
    lines.append("  ┌" + "─" * (max_sink_len + 2) + "┐")
    lines.append("  │ " + "SINKS".center(max_sink_len) + " │")
    lines.append("  ├" + "─" * (max_sink_len + 2) + "┤")
    for sink in sinks[:3]:  # Limit to 3 sinks for readability
        lines.append("  │ " + sink.ljust(max_sink_len) + " │")
    if len(sinks) > 3:
        lines.append("  │ " + f"... +{len(sinks) - 3} more".ljust(max_sink_len) + " │")
    lines.append("  └" + "─" * (max_sink_len + 2) + "┘")

    return "\n".join(lines)


def print_results(vuln_type: str, results: List[SourceToSinkPath]) -> None:
    """Print results for a single vulnerability type with ASCII art visualization."""
    if results is None:
        results = []
    title = vuln_type.replace("_", " ").upper()
    print(f"\n{'=' * 60}")
    print(f"  {title} PATHS ({len(results)} results)")
    print(f"{'=' * 60}")

    if not results:
        print("  No vulnerable paths found.")
        return

    for r in results:
        print(f"\n  Binary: {r.binary}")
        print(f"  Function: {r.function}")
        if r.address:
            print(f"  Address: {r.address}")

        # Show ASCII art visualization for the path
        ascii_art = _generate_path_ascii_art(r.source_apis, r.sink_apis, r.function)
        print(f"\n{ascii_art}")

        print(f"\n  Sources ({r.source_count}): {', '.join(r.source_apis)}")
        print(f"  Sinks ({r.sink_count}): {', '.join(r.sink_apis)}")
        print(f"  {'─' * 56}")


def main() -> None:
    """CLI entry point for source-to-sink path analysis."""
    # Reconfigure stdout/stderr for Unicode support on Windows cp1252 consoles
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(
        description="Find CFG paths from user-controlled input sources to dangerous sinks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all source-to-sink queries (across all binaries in database)
  python -m student_labs.lab3.source_to_sink_analysis --all

  # Run specific vulnerability query
  python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow
  python -m student_labs.lab3.source_to_sink_analysis --format-string
  python -m student_labs.lab3.source_to_sink_analysis --command-injection
  python -m student_labs.lab3.source_to_sink_analysis --path-traversal

  # Find high-risk functions with multiple vulnerability types
  python -m student_labs.lab3.source_to_sink_analysis --high-risk

  # Generate vulnerability report for a specific binary (default output: output/lab3/)
  python -m student_labs.lab3.source_to_sink_analysis --sha256 5901ede53ed33d4feafbc9763ebb86209d542c456b3990bb887177982fb1ceb6

  # Generate report with custom output file
  python -m student_labs.lab3.source_to_sink_analysis --sha256 abc123... --output my_report.md
        """,
    )

    # Query selection arguments
    parser.add_argument("--all", action="store_true", help="Run all vulnerability path queries")
    parser.add_argument("--buffer-overflow", action="store_true", help="Find buffer overflow paths")
    parser.add_argument("--format-string", action="store_true", help="Find format string paths")
    parser.add_argument("--command-injection", action="store_true", help="Find command injection paths")
    parser.add_argument("--path-traversal", action="store_true", help="Find path traversal paths")
    parser.add_argument("--high-risk", action="store_true", help="Find functions with multiple vulnerability types")

    # Binary-specific analysis with report generation
    parser.add_argument("--sha256", type=str, metavar="HASH",
                        help="SHA256 hash of the binary to analyze (generates markdown report by default)")
    parser.add_argument("--output", "-o", type=str, metavar="FILE",
                        help="Output file for report (default: output/lab3/source_sink_report_<sha256>.md)")

    # Inter-procedural analysis arguments
    parser.add_argument("--interprocedural", action="store_true",
                        help="Enable inter-procedural analysis (trace paths across function calls)")
    parser.add_argument("--call-depth", type=int, default=2, metavar="N",
                        help="Maximum call depth for inter-procedural analysis (default: 2)")

    # Common arguments
    parser.add_argument("--limit", type=int, default=100, help="Maximum results per query (default: 100)")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Connect to Neo4j
    creds = get_neo4j_credentials()
    driver = GraphDatabase.driver(
        creds["uri"],
        auth=(creds["user"], creds["password"]),
    )
    database = creds.get("database", "neo4j")

    try:
        # Handle binary-specific analysis with report generation (default when --sha256 is provided)
        if args.sha256:
            # Generate markdown report by default
            if args.output:
                output_path = args.output
            else:
                output_dir = Path("output/lab3")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = str(output_dir / f"source_sink_report_{args.sha256[:16]}.md")

            print(f"\nGenerating source-to-sink vulnerability report...")
            print(f"Binary SHA256: {args.sha256}")
            print(f"Output file: {output_path}")

            try:
                report = generate_vulnerability_report(driver, database, args.sha256, output_path)
                print(f"\n✅ Report generated successfully: {output_path}")
                print(f"   Report length: {len(report)} characters")
            except ValueError as e:
                print(f"\nError: {e}")
                print("Make sure the binary has been ingested into the database.")
            return

        # Determine which queries to run
        run_all = args.all or not any([
            args.buffer_overflow, args.format_string, args.command_injection,
            args.path_traversal, args.high_risk
        ])

        if run_all or args.buffer_overflow:
            results = find_buffer_overflow_paths(driver, database, args.limit)
            print_results("buffer_overflow", results)

        if run_all or args.format_string:
            results = find_format_string_paths(driver, database, args.limit)
            print_results("format_string", results)

        if run_all or args.command_injection:
            results = find_command_injection_paths(driver, database, args.limit)
            print_results("command_injection", results)

        if run_all or args.path_traversal:
            results = find_path_traversal_paths(driver, database, args.limit)
            print_results("path_traversal", results)

        if args.high_risk:
            print(f"\n{'=' * 60}")
            print("  HIGH-RISK FUNCTIONS (Multiple Vulnerability Types)")
            print(f"{'=' * 60}")

            high_risk = get_high_risk_functions(driver, database, min_vuln_types=2, limit=args.limit)

            if not high_risk:
                print("  No high-risk functions found.")
            else:
                for func in high_risk:
                    print(f"\n  Binary: {func['binary']}")
                    print(f"  Function: {func['function']}")
                    if func['address']:
                        print(f"  Address: {func['address']}")
                    print(f"  Vulnerability Types ({func['vuln_count']}): {', '.join(func['vuln_types'])}")
                    print(f"  Source APIs: {', '.join(func['source_apis'][:5])}")
                    if len(func['source_apis']) > 5:
                        print(f"              ... and {len(func['source_apis']) - 5} more")
                    print(f"  Sink APIs: {', '.join(func['sink_apis'][:5])}")
                    if len(func['sink_apis']) > 5:
                        print(f"            ... and {len(func['sink_apis']) - 5} more")

    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Override the logger to use the file name
    logger = logging.getLogger(module_name)

    main()
