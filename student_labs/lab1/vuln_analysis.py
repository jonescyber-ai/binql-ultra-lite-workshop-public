"""
Vulnerability Analysis Script for Lab 1.7.

This script queries the Neo4j program graph to produce a vulnerability assessment
for a given binary. It focuses on code-level vulnerability indicators:
- Buffer-overflow-prone functions (strcpy, sprintf, gets, strcat)
- Format-string sinks (printf, fprintf, syslog)
- Memory management issues (malloc/free patterns)
- Call depth to risky functions

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab1.vuln_analysis --sha256 <binary_sha256>

    # Output as JSON
    python -m student_labs.lab1.vuln_analysis --sha256 <binary_sha256> --json

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab1.vuln_analysis --sha256 <binary_sha256>

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab1/lab_1_7_vuln_analysis.md
"""

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab1 import vuln_analysis_reference as _ref
    logger.info("Using reference implementation for vuln_analysis")

# Buffer overflow prone imports
BUFFER_OVERFLOW_IMPORTS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "sscanf", "fscanf",
    "strncpy",  # Still risky if misused
    "strncat",  # Still risky if misused
]

# Format string sinks
FORMAT_STRING_IMPORTS = [
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "syslog", "err", "warn",
]

# Memory management imports
MEMORY_IMPORTS = ["malloc", "calloc", "realloc", "free", "alloca"]

# High-risk functions for severity scoring
HIGH_RISK_FUNCTIONS = {"gets", "strcpy", "strcat", "sprintf"}


def get_binary_info(driver, database: str, sha256: str) -> Optional[Dict[str, Any]]:
    """
    Query basic binary information.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: Binary SHA256 hash

    Returns:
        Dictionary with binary info or None if not found
    """
    if _USE_REFERENCE:
        return _ref.get_binary_info(driver, database, sha256)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Query should return: name, architecture, function_count
    pass
    ### END YOUR CODE HERE ###


def get_buffer_overflow_imports(driver, database: str, sha256: str) -> List[str]:
    """
    Query imports that may cause buffer overflows.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: Binary SHA256 hash

    Returns:
        List of buffer-overflow-prone import names found in the binary
    """
    if _USE_REFERENCE:
        return _ref.get_buffer_overflow_imports(driver, database, sha256)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Query for imports in BUFFER_OVERFLOW_IMPORTS list
    pass
    ### END YOUR CODE HERE ###


def get_format_string_imports(driver, database: str, sha256: str) -> List[str]:
    """
    Query imports that may be format string sinks.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: Binary SHA256 hash

    Returns:
        List of format-string import names found in the binary
    """
    if _USE_REFERENCE:
        return _ref.get_format_string_imports(driver, database, sha256)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Query for imports in FORMAT_STRING_IMPORTS list
    pass
    ### END YOUR CODE HERE ###


def get_memory_imports(driver, database: str, sha256: str) -> List[Dict[str, Any]]:
    """
    Query memory management imports with call counts.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: Binary SHA256 hash

    Returns:
        List of dicts with 'name' and 'count' keys
    """
    if _USE_REFERENCE:
        return _ref.get_memory_imports(driver, database, sha256)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Query for imports in MEMORY_IMPORTS list with call counts
    pass
    ### END YOUR CODE HERE ###


def get_call_depth_to_sinks(
    driver, database: str, sha256: str, max_depth: int = 5
) -> List[Dict[str, Any]]:
    """
    Find call paths from entry functions to dangerous imports.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: Binary SHA256 hash
        max_depth: Maximum call depth to search

    Returns:
        List of dicts with 'entry_func', 'call_path', 'sink_import', 'depth' keys
    """
    if _USE_REFERENCE:
        return _ref.get_call_depth_to_sinks(driver, database, sha256, max_depth)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Find paths from main/_start/entry to dangerous functions like strcpy, gets, sprintf, system
    pass
    ### END YOUR CODE HERE ###


def compute_vuln_severity(
    buffer_imports: List[str],
    format_imports: List[str],
    call_paths: List[Dict[str, Any]],
) -> str:
    """
    Compute vulnerability severity based on findings.

    Scoring:
    - High-risk buffer overflow functions (gets, strcpy, strcat, sprintf): +3 each
    - Other buffer/format functions: +1 each
    - Short call paths (depth <= 3): +2 each

    Severity levels:
    - CRITICAL: score >= 12
    - HIGH: score >= 6
    - MEDIUM: score >= 3
    - LOW: score < 3

    Args:
        buffer_imports: List of buffer-overflow-prone import names
        format_imports: List of format-string import names
        call_paths: List of call path dicts

    Returns:
        Severity level string: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
    """
    if _USE_REFERENCE:
        return _ref.compute_vuln_severity(buffer_imports, format_imports, call_paths)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    pass
    ### END YOUR CODE HERE ###


def generate_report(
    sha256: str,
    binary_info: Dict[str, Any],
    buffer_imports: List[str],
    format_imports: List[str],
    memory_imports: List[Dict[str, Any]],
    call_paths: List[Dict[str, Any]],
    severity: str,
) -> str:
    """
    Generate a human-readable vulnerability analysis report.

    Args:
        sha256: Binary SHA256 hash
        binary_info: Dictionary with binary metadata
        buffer_imports: List of buffer-overflow-prone import names
        format_imports: List of format-string import names
        memory_imports: List of memory import dicts with counts
        call_paths: List of call path dicts
        severity: Computed severity level

    Returns:
        Formatted report string
    """
    lines = []
    lines.append("=== VULNERABILITY ANALYSIS REPORT ===")
    lines.append(f"SHA256: {sha256}")
    lines.append(f"Name: {binary_info.get('name', 'unknown')}")
    lines.append(f"Architecture: {binary_info.get('architecture', 'unknown')}")
    
    lines.append("")
    lines.append("--- Summary ---")
    lines.append(f"Functions:           {binary_info.get('function_count', 0)}")
    lines.append(f"Vulnerable Imports:  {len(buffer_imports) + len(format_imports)}")
    lines.append(f"Call Paths to Sinks: {len(call_paths)}")
    
    lines.append("")
    lines.append("--- Buffer Overflow Risk ---")
    if buffer_imports:
        for imp in buffer_imports:
            risk_note = "(no bounds checking)" if imp in HIGH_RISK_FUNCTIONS else "(risky if misused)"
            if imp == "gets":
                risk_note = "(deprecated, always vulnerable)"
            lines.append(f"  • {imp} {risk_note}")
    else:
        lines.append("  (none found)")
    
    lines.append("")
    lines.append("--- Format String Risk ---")
    if format_imports:
        for imp in format_imports:
            lines.append(f"  • {imp} (potential format string vulnerability)")
    else:
        lines.append("  (none found)")
    
    lines.append("")
    lines.append("--- Memory Management ---")
    if memory_imports:
        for mem in memory_imports:
            lines.append(f"  • {mem['name']} ({mem['count']} calls)")
    else:
        lines.append("  (none found)")
    
    lines.append("")
    lines.append("--- Call Depth Analysis ---")
    if call_paths:
        for path in call_paths[:5]:  # Limit display
            path_str = " -> ".join(path.get("call_path", []))
            lines.append(f"  • {path_str}: {path.get('depth', '?')} hops")
        if len(call_paths) > 5:
            lines.append(f"  ... and {len(call_paths) - 5} more paths")
    else:
        lines.append("  (no short paths to dangerous sinks found)")
    
    lines.append("")
    lines.append("--- Vulnerability Severity ---")
    lines.append(f"Severity: {severity}")
    lines.append(f"  - {len(buffer_imports)} buffer overflow risks")
    lines.append(f"  - {len(format_imports)} format string risks")
    short_paths = [p for p in call_paths if p.get("depth", 99) <= 3]
    if short_paths:
        lines.append(f"  - {len(short_paths)} short call paths to dangerous functions")
    
    lines.append("")
    lines.append("--- Recommendations ---")
    if "strcpy" in buffer_imports or "strcat" in buffer_imports:
        lines.append("  • Replace strcpy/strcat with strncpy/strncat")
    if "sprintf" in buffer_imports:
        lines.append("  • Replace sprintf with snprintf")
    if "gets" in buffer_imports:
        lines.append("  • Remove gets() entirely (use fgets)")
    if format_imports:
        lines.append("  • Audit printf-family calls for user-controlled format strings")
    if memory_imports:
        lines.append("  • Review malloc/free patterns for use-after-free or double-free")
    if severity == "LOW":
        lines.append("  • Binary has minimal vulnerability indicators")
    
    return "\n".join(lines)


def generate_json_report(
    sha256: str,
    binary_info: Dict[str, Any],
    buffer_imports: List[str],
    format_imports: List[str],
    memory_imports: List[Dict[str, Any]],
    call_paths: List[Dict[str, Any]],
    severity: str,
) -> str:
    """
    Generate a JSON vulnerability analysis report.

    Args:
        sha256: Binary SHA256 hash
        binary_info: Dictionary with binary metadata
        buffer_imports: List of buffer-overflow-prone import names
        format_imports: List of format-string import names
        memory_imports: List of memory import dicts with counts
        call_paths: List of call path dicts
        severity: Computed severity level

    Returns:
        JSON string
    """
    report = {
        "sha256": sha256,
        "name": binary_info.get("name"),
        "architecture": binary_info.get("architecture"),
        "function_count": binary_info.get("function_count", 0),
        "buffer_overflow_imports": buffer_imports,
        "format_string_imports": format_imports,
        "memory_imports": memory_imports,
        "call_paths": call_paths,
        "severity": severity,
    }
    return json.dumps(report, indent=2)


def run_analysis(
    driver,
    database: str,
    sha256: str,
    max_depth: int = 5,
    output_json: bool = False,
) -> str:
    """
    Run the complete vulnerability analysis.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: Binary SHA256 hash
        max_depth: Maximum call depth for path analysis
        output_json: If True, output JSON format

    Returns:
        Report string (text or JSON)
    """
    # Get binary info
    binary_info = get_binary_info(driver, database, sha256)
    if binary_info is None:
        return f"ERROR: Binary with SHA256 {sha256} not found in database"
    
    # Get buffer overflow imports
    buffer_imports = get_buffer_overflow_imports(driver, database, sha256) or []
    
    # Get format string imports
    format_imports = get_format_string_imports(driver, database, sha256) or []
    
    # Get memory imports
    memory_imports = get_memory_imports(driver, database, sha256) or []
    
    # Get call paths to sinks
    call_paths = get_call_depth_to_sinks(driver, database, sha256, max_depth) or []
    
    # Compute severity
    severity = compute_vuln_severity(buffer_imports, format_imports, call_paths)
    if severity is None:
        severity = "UNKNOWN"
    
    # Generate report
    if output_json:
        return generate_json_report(
            sha256, binary_info, buffer_imports, format_imports,
            memory_imports, call_paths, severity
        )
    else:
        return generate_report(
            sha256, binary_info, buffer_imports, format_imports,
            memory_imports, call_paths, severity
        )


def parse_args():
    """Parse command line arguments."""
    creds = get_neo4j_credentials()
    
    parser = argparse.ArgumentParser(
        description="Generate a vulnerability analysis report for a binary in the Neo4j graph."
    )
    parser.add_argument(
        "--sha256",
        required=True,
        help="SHA256 hash of the binary to analyze",
    )
    parser.add_argument(
        "--database",
        default=creds["database"],
        help=f"Neo4j database name (default: {creds['database']})",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum call depth for path analysis (default: 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output report as JSON",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )
    
    # Get credentials and connect
    creds = get_neo4j_credentials()
    driver = GraphDatabase.driver(
        creds["uri"],
        auth=(creds["user"], creds["password"]),
    )
    
    try:
        # Run analysis
        report = run_analysis(
            driver,
            args.database,
            args.sha256,
            max_depth=args.max_depth,
            output_json=args.output_json,
        )
        print(report)
    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
