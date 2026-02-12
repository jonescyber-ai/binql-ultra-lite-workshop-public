"""
Lab 3.3: Path Risk Analysis Module.

This module analyzes Lab 3.2's source-to-sink paths to produce quantified risk
scores for prioritized vulnerability triage. It calculates complexity metrics
and traversal likelihood for each path, then combines them into a risk score.

The module integrates with Lab 3.2 by importing its detection functions:
- find_buffer_overflow_paths()
- find_format_string_paths()
- find_command_injection_paths()
- find_path_traversal_paths()

Students implement 5 functions:
1. analyze_path_complexity() - Calculate complexity metrics for a path
2. analyze_path_traversal_likelihood() - Measure traversal likelihood
3. calculate_path_risk_score() - Combine metrics into risk score
4. get_paths_for_binary() - Retrieve Lab 3.2 paths for a binary
5. analyze_all_paths_for_binary() - Full analysis pipeline

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.complexity_analysis --help

    # Analyze all Lab 3.2 paths for a specific binary
    python -m student_labs.lab3.complexity_analysis --sha256 <binary_sha256>

    # Show only critical/high risk paths
    python -m student_labs.lab3.complexity_analysis --sha256 <hash> --min-risk high

    # Analyze all binaries in database
    python -m student_labs.lab3.complexity_analysis --all

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab3.complexity_analysis --all

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should fill in
      the query placeholders marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab3/lab_3_3_complexity_analysis.md
"""

import argparse
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from neo4j import Driver, GraphDatabase

from lab_common.binql import get_neo4j_credentials

# Import Lab 3.2 API for source-to-sink path detection
from student_labs.lab3.source_to_sink_analysis import (
    SourceToSinkPath,
    find_buffer_overflow_paths,
    find_format_string_paths,
    find_command_injection_paths,
    find_path_traversal_paths,
)

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab3 import complexity_analysis_reference as _ref
    logger.info("Using reference implementation for complexity_analysis")


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PathComplexityMetrics:
    """Complexity metrics for a source-to-sink path."""

    cyclomatic_complexity: int = 1  # McCabe's metric for the function
    branch_count: int = 0  # Number of conditional branches (edges)
    basic_block_count: int = 1  # Number of basic blocks in the function
    nesting_depth: int = 0  # Maximum nesting level (requires additional analysis)
    path_length: int = 0  # Number of basic blocks from source to sink


@dataclass
class PathTraversalMetrics:
    """Traversal likelihood metrics for a source-to-sink path."""

    entry_point_connectivity: int = 0  # How many entry points can reach this function
    path_in_degree: int = 0  # Sum of in-degrees for blocks on the path
    dark_code_ratio: float = 0.0  # Percentage of path in low-connectivity blocks
    is_error_handler: bool = False  # Is this path in an error handling branch
    caller_count: int = 0  # Number of functions that call this function


@dataclass
class PathRiskAnalysis:
    """Complete risk analysis for a Lab 3.2 source-to-sink path."""

    # Original Lab 3.2 data
    binary: str = ""
    function: str = ""
    address: Optional[str] = None
    source_apis: List[str] = field(default_factory=list)
    sink_apis: List[str] = field(default_factory=list)
    vulnerability_type: str = ""

    # Lab 3.3 complexity metrics
    complexity_metrics: PathComplexityMetrics = field(default_factory=PathComplexityMetrics)

    # Lab 3.3 traversal metrics
    traversal_metrics: PathTraversalMetrics = field(default_factory=PathTraversalMetrics)

    # Combined risk score
    complexity_score: float = 0.0  # 0-1 normalized
    traversal_score: float = 0.0  # 0-1 normalized (higher = more likely to execute)
    combined_risk_score: float = 0.0  # 0-100 final score
    risk_level: str = "low"  # "critical", "high", "medium", "low"

    # Triage recommendations
    priority_rank: int = 0  # 1 = highest priority
    recommendations: List[str] = field(default_factory=list)


# =============================================================================
# Helper Functions
# =============================================================================


def run_query(
    driver: Driver,
    database: str,
    query: str,
    params: Optional[Dict[str, Any]] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Execute a Cypher query and return results as a list of dictionaries.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        query: Cypher query string to execute.
        params: Optional dictionary of query parameters.
        limit: Maximum number of results (0 = no limit).

    Returns:
        List of dictionaries, where each dictionary represents a row with
        column names as keys.
    """
    # Add LIMIT clause if not already present and limit > 0
    query_upper = query.upper().strip()
    if limit > 0 and "LIMIT" not in query_upper:
        query = f"{query.rstrip().rstrip(';')} LIMIT {limit}"

    with driver.session(database=database) as session:
        result = session.run(query, params or {})
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
# Core Path Analysis Functions - Students Implement These
# =============================================================================


def analyze_path_complexity(
    driver: Driver,
    database: str,
    path: SourceToSinkPath,
) -> PathComplexityMetrics:
    """
    Calculate complexity metrics for a Lab 3.2 source-to-sink path.

    Uses the function containing the path to calculate:
    - Cyclomatic complexity (edges - nodes + 2)
    - Branch count (number of edges/conditional branches)
    - Basic block count (number of nodes)

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        path: A SourceToSinkPath object from Lab 3.2.

    Returns:
        PathComplexityMetrics with calculated values.

    Example:
        >>> metrics = analyze_path_complexity(driver, "neo4j", path)
        >>> print(f"Complexity: {metrics.cyclomatic_complexity}")
    """
    if _USE_REFERENCE:
        return _ref.analyze_path_complexity(driver, database, path)

    # =========================================================================
    # STUDENTS: Write a Cypher query to calculate complexity metrics.
    #
    # The query should:
    # 1. Find the function by name and binary
    # 2. Count basic blocks (nodes)
    # 3. Count edges (BRANCHES_TO relationships)
    # 4. Calculate cyclomatic complexity: E - N + 2
    #
    # Use $function_name and $binary_name as parameters.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Write a Cypher query to calculate complexity metrics for the function.
    # Return a PathComplexityMetrics dataclass with the calculated values.
    pass
    ### END YOUR CODE HERE ###


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

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        path: A SourceToSinkPath object from Lab 3.2.

    Returns:
        PathTraversalMetrics with calculated values.

    Example:
        >>> metrics = analyze_path_traversal_likelihood(driver, "neo4j", path)
        >>> print(f"Caller count: {metrics.caller_count}")
    """
    if _USE_REFERENCE:
        return _ref.analyze_path_traversal_likelihood(driver, database, path)

    # =========================================================================
    # STUDENTS: Write Cypher queries to calculate traversal likelihood metrics.
    #
    # You need to calculate:
    # 1. caller_count: How many functions call this function
    # 2. entry_point_connectivity: How many entry points (main, _start, etc.)
    #    exist in the binary
    # 3. dark_code_ratio: Percentage of basic blocks with in-degree <= 1
    #
    # Use $function_name and $binary_name as parameters.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Write Cypher queries to calculate traversal likelihood metrics.
    # Return a PathTraversalMetrics dataclass with the calculated values.
    pass
    ### END YOUR CODE HERE ###


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
    - Vulnerability severity: 25% (command injection > buffer overflow > etc.)

    Args:
        complexity: PathComplexityMetrics from analyze_path_complexity().
        traversal: PathTraversalMetrics from analyze_path_traversal_likelihood().
        vulnerability_type: Type of vulnerability (e.g., "buffer_overflow").

    Returns:
        Tuple of (score, risk_level) where:
        - score: Float 0-100
        - risk_level: "critical", "high", "medium", or "low"

    Example:
        >>> score, level = calculate_path_risk_score(complexity, traversal, "buffer_overflow")
        >>> print(f"Risk: {score:.1f}/100 ({level})")
    """
    if _USE_REFERENCE:
        return _ref.calculate_path_risk_score(complexity, traversal, vulnerability_type)

    # =========================================================================
    # STUDENTS: Implement the risk scoring formula.
    #
    # 1. Normalize complexity_score (0-1):
    #    - Base: cyclomatic_complexity / 30 (capped at 1.0)
    #    - Bonus: nesting_depth / 5 (capped at 0.3)
    #
    # 2. Normalize traversal_score (0-1):
    #    - entry_point_connectivity / 3 (capped at 0.4)
    #    - caller_count / 5 (capped at 0.3)
    #    - (1.0 - dark_code_ratio) * 0.3
    #    - If is_error_handler, multiply by 0.7
    #
    # 3. Severity multipliers:
    #    - command_injection: 1.0
    #    - buffer_overflow: 0.9
    #    - format_string: 0.85
    #    - path_traversal: 0.7
    #    - default: 0.5
    #
    # 4. Combined score = complexity_score * 40 + traversal_score * 35 + severity * 25
    #
    # 5. Risk levels:
    #    - >= 70: "critical"
    #    - >= 50: "high"
    #    - >= 30: "medium"
    #    - < 30: "low"
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Implement the risk scoring formula as described in the comments above.
    # Return a tuple of (score, risk_level).
    pass
    ### END YOUR CODE HERE ###


# =============================================================================
# Integration Functions - Students Implement These
# =============================================================================


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

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to analyze.

    Returns:
        List of SourceToSinkPath objects for the specified binary.

    Example:
        >>> paths = get_paths_for_binary(driver, "neo4j", "9409117e...")
        >>> print(f"Found {len(paths)} paths")
    """
    if _USE_REFERENCE:
        return _ref.get_paths_for_binary(driver, database, sha256)

    # =========================================================================
    # STUDENTS: Call Lab 3.2's detection functions and filter by binary.
    #
    # 1. Call all four find_*_paths() functions
    # 2. Combine results into a single list
    # 3. Filter to paths where sha256 appears in the binary name
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Call Lab 3.2's detection functions and filter by binary.
    # Return a list of SourceToSinkPath objects.
    pass
    ### END YOUR CODE HERE ###


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

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to analyze.

    Returns:
        List of PathRiskAnalysis objects, sorted by risk score (highest first).

    Example:
        >>> analyses = analyze_all_paths_for_binary(driver, "neo4j", "9409117e...")
        >>> for a in analyses[:5]:
        ...     print(f"#{a.priority_rank}: {a.function} - {a.risk_level} ({a.combined_risk_score:.1f})")
    """
    if _USE_REFERENCE:
        return _ref.analyze_all_paths_for_binary(driver, database, sha256)

    # =========================================================================
    # STUDENTS: Implement the full analysis pipeline.
    #
    # 1. Call get_paths_for_binary() to get Lab 3.2 paths
    # 2. For each path:
    #    a. Call analyze_path_complexity()
    #    b. Call analyze_path_traversal_likelihood()
    #    c. Call calculate_path_risk_score()
    #    d. Create a PathRiskAnalysis object
    # 3. Sort by combined_risk_score (descending)
    # 4. Set priority_rank (1 = highest risk)
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Implement the full analysis pipeline as described in the comments above.
    # Return a list of PathRiskAnalysis objects sorted by risk score.
    pass
    ### END YOUR CODE HERE ###


# =============================================================================
# CLI and Main
# =============================================================================


def _format_risk_level(level: str) -> str:
    """Format risk level with emoji."""
    emoji_map = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }
    return f"{emoji_map.get(level, '⚪')} {level.upper()}"


def _get_complexity_interpretation(cyclomatic: int) -> str:
    """Interpret cyclomatic complexity value."""
    if cyclomatic >= 20:
        return "Very High (many execution paths, high bug probability)"
    elif cyclomatic >= 10:
        return "High (complex logic, moderate bug probability)"
    elif cyclomatic >= 5:
        return "Moderate (manageable complexity)"
    else:
        return "Low (simple, straightforward code)"


def _get_dark_code_interpretation(ratio: float) -> str:
    """Interpret dark code ratio."""
    if ratio >= 0.5:
        return "High (significant untested code regions)"
    elif ratio >= 0.25:
        return "Moderate (some rarely-executed paths)"
    else:
        return "Low (well-covered code)"


def _get_connectivity_interpretation(callers: int, entry_points: int) -> str:
    """Interpret function connectivity."""
    if callers >= 5 or entry_points >= 2:
        return "High (frequently called, likely to be executed)"
    elif callers >= 2 or entry_points >= 1:
        return "Moderate (reachable from common paths)"
    else:
        return "Low (isolated, may be rarely executed)"


def _get_vulnerability_description(vuln_type: str) -> str:
    """Get description and CWE for vulnerability type."""
    descriptions = {
        "buffer_overflow": "Buffer Overflow (CWE-120/121) - Memory corruption leading to potential code execution",
        "format_string": "Format String (CWE-134) - Arbitrary memory read/write via format specifiers",
        "command_injection": "Command Injection (CWE-78) - Arbitrary OS command execution",
        "path_traversal": "Path Traversal (CWE-22) - Unauthorized file system access",
    }
    return descriptions.get(vuln_type, vuln_type)


def _get_recommendation(analysis: PathRiskAnalysis) -> str:
    """Generate actionable recommendation based on analysis."""
    vuln_type = analysis.vulnerability_type
    source_apis = ", ".join(analysis.source_apis)
    sink_apis = ", ".join(analysis.sink_apis)
    
    recommendations = {
        "buffer_overflow": f"Validate input size from {source_apis} before passing to {sink_apis}. "
                          f"Consider using bounded alternatives (strncpy, snprintf) with explicit size checks.",
        "format_string": f"Never pass user input from {source_apis} directly as format string to {sink_apis}. "
                        f"Use fixed format strings with user data as arguments.",
        "command_injection": f"Sanitize/escape input from {source_apis} before passing to {sink_apis}. "
                            f"Consider using parameterized APIs or allowlists instead of shell execution.",
        "path_traversal": f"Validate and canonicalize paths from {source_apis} before using with {sink_apis}. "
                         f"Implement allowlist-based path validation.",
    }
    return recommendations.get(vuln_type, "Review the data flow from source to sink for potential exploitation.")


def _get_risk_factors(analysis: PathRiskAnalysis) -> List[str]:
    """Identify key risk factors contributing to the score."""
    factors = []
    
    # Complexity factors
    cc = analysis.complexity_metrics.cyclomatic_complexity
    if cc >= 20:
        factors.append(f"⚠️  Very high cyclomatic complexity ({cc}) increases attack surface")
    elif cc >= 10:
        factors.append(f"⚠️  High cyclomatic complexity ({cc}) provides multiple exploitation paths")
    
    # Traversal factors
    if analysis.traversal_metrics.caller_count >= 3:
        factors.append(f"⚠️  Called by {analysis.traversal_metrics.caller_count} functions (high exposure)")
    
    if analysis.traversal_metrics.dark_code_ratio >= 0.3:
        factors.append(f"⚠️  {analysis.traversal_metrics.dark_code_ratio:.0%} dark code ratio (likely untested)")
    
    if analysis.traversal_metrics.is_error_handler:
        factors.append("ℹ️  Located in error handling path (lower execution likelihood)")
    
    # Vulnerability severity
    if analysis.vulnerability_type == "command_injection":
        factors.append("🔥 Command injection enables arbitrary code execution")
    elif analysis.vulnerability_type == "buffer_overflow":
        factors.append("🔥 Buffer overflow can lead to memory corruption and RCE")
    
    if not factors:
        factors.append("ℹ️  Standard risk profile, no exceptional factors identified")
    
    return factors


def _print_analysis_results(analyses: List[PathRiskAnalysis], verbose: bool = False) -> None:
    """Print analysis results to console with detailed insights."""
    if not analyses:
        print("No paths found for analysis.")
        return

    # Summary statistics
    critical = sum(1 for a in analyses if a.risk_level == "critical")
    high = sum(1 for a in analyses if a.risk_level == "high")
    medium = sum(1 for a in analyses if a.risk_level == "medium")
    low = sum(1 for a in analyses if a.risk_level == "low")
    
    # Calculate aggregate metrics
    avg_complexity = sum(a.complexity_metrics.cyclomatic_complexity for a in analyses) / len(analyses)
    avg_dark_code = sum(a.traversal_metrics.dark_code_ratio for a in analyses) / len(analyses)
    vuln_types = {}
    for a in analyses:
        vuln_types[a.vulnerability_type] = vuln_types.get(a.vulnerability_type, 0) + 1

    print(f"\n{'='*80}")
    print(f"{'PATH RISK ANALYSIS REPORT':^80}")
    print(f"{'='*80}")
    
    # Executive Summary
    print(f"\n📊 EXECUTIVE SUMMARY")
    print(f"{'─'*80}")
    print(f"Total vulnerability paths analyzed: {len(analyses)}")
    print(f"\nRisk Distribution:")
    print(f"  🔴 Critical: {critical:3d} {'█' * critical}")
    print(f"  🟠 High:     {high:3d} {'█' * high}")
    print(f"  🟡 Medium:   {medium:3d} {'█' * medium}")
    print(f"  🟢 Low:      {low:3d} {'█' * low}")
    
    print(f"\nVulnerability Types Found:")
    for vtype, count in sorted(vuln_types.items(), key=lambda x: -x[1]):
        print(f"  • {vtype.replace('_', ' ').title()}: {count}")
    
    print(f"\nAggregate Metrics:")
    print(f"  • Average cyclomatic complexity: {avg_complexity:.1f} - {_get_complexity_interpretation(int(avg_complexity))}")
    print(f"  • Average dark code ratio: {avg_dark_code:.1%} - {_get_dark_code_interpretation(avg_dark_code)}")
    
    # Key findings
    if critical > 0 or high > 0:
        print(f"\n⚠️  ATTENTION: {critical + high} high-priority paths require immediate review")
    
    print(f"\n{'='*80}")
    print(f"{'DETAILED PATH ANALYSIS':^80}")
    print(f"{'='*80}")

    # Detailed results for each path
    for analysis in analyses:
        print(f"\n{'─'*80}")
        print(f"#{analysis.priority_rank} {_format_risk_level(analysis.risk_level)} "
              f"(Score: {analysis.combined_risk_score:.1f}/100)")
        print(f"{'─'*80}")
        
        # Basic info
        print(f"\n📍 Location:")
        print(f"   Function: {analysis.function}")
        print(f"   Binary:   {analysis.binary}")
        if analysis.address:
            print(f"   Address:  {analysis.address}")
        
        # Vulnerability details
        print(f"\n🎯 Vulnerability:")
        print(f"   Type: {_get_vulnerability_description(analysis.vulnerability_type)}")
        print(f"   Data Flow: {', '.join(analysis.source_apis)} → {', '.join(analysis.sink_apis)}")
        
        # Score breakdown
        print(f"\n📈 Score Breakdown:")
        complexity_contrib = analysis.complexity_score * 40
        traversal_contrib = analysis.traversal_score * 35
        severity_multipliers = {"command_injection": 1.0, "buffer_overflow": 0.9, "format_string": 0.85, "path_traversal": 0.7}
        severity_contrib = severity_multipliers.get(analysis.vulnerability_type, 0.5) * 25
        print(f"   Complexity Score:  {analysis.complexity_score:.2f} × 40 = {complexity_contrib:.1f} pts")
        print(f"   Traversal Score:   {analysis.traversal_score:.2f} × 35 = {traversal_contrib:.1f} pts")
        print(f"   Severity Score:    {severity_multipliers.get(analysis.vulnerability_type, 0.5):.2f} × 25 = {severity_contrib:.1f} pts")
        print(f"   {'─'*40}")
        print(f"   Total:             {analysis.combined_risk_score:.1f}/100")
        
        # Metrics with interpretation
        print(f"\n📊 Complexity Analysis:")
        cc = analysis.complexity_metrics.cyclomatic_complexity
        print(f"   Cyclomatic Complexity: {cc} - {_get_complexity_interpretation(cc)}")
        print(f"   Branch Count: {analysis.complexity_metrics.branch_count}")
        print(f"   Basic Blocks: {analysis.complexity_metrics.basic_block_count}")
        
        print(f"\n🔗 Reachability Analysis:")
        print(f"   Caller Count: {analysis.traversal_metrics.caller_count}")
        print(f"   Entry Point Connectivity: {analysis.traversal_metrics.entry_point_connectivity}")
        connectivity = _get_connectivity_interpretation(
            analysis.traversal_metrics.caller_count,
            analysis.traversal_metrics.entry_point_connectivity
        )
        print(f"   Connectivity: {connectivity}")
        print(f"   Dark Code Ratio: {analysis.traversal_metrics.dark_code_ratio:.1%} - "
              f"{_get_dark_code_interpretation(analysis.traversal_metrics.dark_code_ratio)}")
        if analysis.traversal_metrics.is_error_handler:
            print(f"   ⚠️  Located in error handling code path")
        
        # Risk factors
        print(f"\n🚨 Key Risk Factors:")
        for factor in _get_risk_factors(analysis):
            print(f"   {factor}")
        
        # Recommendation
        print(f"\n💡 Recommendation:")
        recommendation = _get_recommendation(analysis)
        # Word wrap the recommendation
        words = recommendation.split()
        line = "   "
        for word in words:
            if len(line) + len(word) + 1 > 78:
                print(line)
                line = "   " + word
            else:
                line += " " + word if line != "   " else word
        if line.strip():
            print(line)

    # Footer
    print(f"\n{'='*80}")
    print(f"{'END OF REPORT':^80}")
    print(f"{'='*80}\n")


def main() -> None:
    """Main entry point for the complexity analysis CLI."""
    parser = argparse.ArgumentParser(
        description="Lab 3.3: Path Risk Analysis - Rank Lab 3.2 paths by complexity and traversal likelihood",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all Lab 3.2 paths for a specific binary
  python -m student_labs.lab3.complexity_analysis --sha256 9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd

  # Show only critical/high risk paths
  python -m student_labs.lab3.complexity_analysis --sha256 <hash> --min-risk high

  # Analyze all binaries in database
  python -m student_labs.lab3.complexity_analysis --all

  # Show detailed metrics for each path
  python -m student_labs.lab3.complexity_analysis --sha256 <hash> --verbose
        """,
    )

    # Analysis options
    parser.add_argument(
        "--sha256",
        type=str,
        help="SHA256 hash of the binary to analyze",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Analyze all binaries in database",
    )
    parser.add_argument(
        "--min-risk",
        type=str,
        choices=["critical", "high", "medium", "low"],
        default="low",
        help="Minimum risk level to display (default: low)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed metrics for each path",
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.sha256 and not args.all:
        parser.error("Either --sha256 or --all is required")

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Get Neo4j credentials
    creds = get_neo4j_credentials()
    neo4j_uri = creds["uri"]
    neo4j_user = creds["user"]
    neo4j_password = creds["password"]
    database = creds.get("database", "neo4j")

    # Connect to Neo4j
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    try:
        if args.all:
            # Get all binaries from database
            query = "MATCH (b:Binary) RETURN b.sha256 AS sha256"
            with driver.session(database=database) as session:
                result = session.run(query)
                binaries = [record["sha256"] for record in result]

            print(f"Analyzing {len(binaries)} binaries...")

            all_analyses = []
            for sha256 in binaries:
                analyses = analyze_all_paths_for_binary(driver, database, sha256)
                all_analyses.extend(analyses)

            # Re-rank all analyses
            all_analyses.sort(key=lambda x: x.combined_risk_score, reverse=True)
            for i, analysis in enumerate(all_analyses):
                analysis.priority_rank = i + 1

            # Filter by min risk level
            risk_order = ["critical", "high", "medium", "low"]
            min_risk_idx = risk_order.index(args.min_risk)
            filtered = [a for a in all_analyses if risk_order.index(a.risk_level) <= min_risk_idx]

            _print_analysis_results(filtered, args.verbose)

        else:
            # Analyze specific binary
            analyses = analyze_all_paths_for_binary(driver, database, args.sha256)

            # Filter by min risk level
            risk_order = ["critical", "high", "medium", "low"]
            min_risk_idx = risk_order.index(args.min_risk)
            filtered = [a for a in analyses if risk_order.index(a.risk_level) <= min_risk_idx]

            _print_analysis_results(filtered, args.verbose)

    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(module_name)
    main()
