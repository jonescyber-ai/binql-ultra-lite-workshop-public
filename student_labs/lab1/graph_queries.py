"""
Graph Queries Script for Lab 1.2.

This script queries the Neo4j program graph to validate its structure and run
analysis queries. It demonstrates programmatic graph querying using the Neo4j
Python driver — the same pattern used in later labs and agent workflows.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab1.graph_queries

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab1.graph_queries

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab1/lab_1_2_graph_queries.md
"""

import argparse
import logging
import os
from typing import Any, Dict, List

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    from labs.lab1 import graph_queries_reference as _ref
    logger.info("Using reference implementation for graph_queries")

# Dangerous imports to search for in analysis queries
DANGEROUS_IMPORTS = [
    "system", "execve", "popen", "strcpy", "gets", "sprintf",
]


def count_entity_types(driver, database: str) -> List[Dict[str, Any]]:
    """
    Count all entity types in the graph.

    Args:
        driver: Neo4j driver instance
        database: Database name

    Returns:
        List of dicts with 'label' and 'count' keys, one per entity type.
        Expected labels: Binary, Function, BasicBlock, StringLiteral,
        ImportSymbol, ExportSymbol, Library.
    """
    if _USE_REFERENCE:
        return _ref.count_entity_types(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Write a UNION ALL query that counts each entity type
    # Hint: MATCH (b:Binary) RETURN 'Binary' AS label, count(b) AS count UNION ALL ...
    pass
    ### END YOUR CODE HERE ###


def check_duplicates(driver, database: str) -> List[Dict[str, Any]]:
    """
    Check for duplicate binaries (same SHA256 appearing more than once).

    Args:
        driver: Neo4j driver instance
        database: Database name

    Returns:
        List of dicts with 'sha256' and 'count' keys.
        An empty list means no duplicates (expected after idempotent ingestion).
    """
    if _USE_REFERENCE:
        return _ref.check_duplicates(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Group binaries by sha256, filter where count > 1
    pass
    ### END YOUR CODE HERE ###


def get_relationship_counts(driver, database: str) -> List[Dict[str, Any]]:
    """
    Get relationship counts (functions, blocks, strings, imports) per binary.

    Args:
        driver: Neo4j driver instance
        database: Database name

    Returns:
        List of dicts with 'name', 'functions', 'blocks', 'strings', 'imports' keys.
    """
    if _USE_REFERENCE:
        return _ref.get_relationship_counts(driver, database)
    ### YOUR CODE HERE ###
    # TODO: For each Binary, count related Functions, BasicBlocks, StringLiterals, ImportSymbols
    # Hint: Use OPTIONAL MATCH for each relationship type
    pass
    ### END YOUR CODE HERE ###


def get_binary_metadata(driver, database: str) -> List[Dict[str, Any]]:
    """
    Get classification and tags for all binaries.

    Args:
        driver: Neo4j driver instance
        database: Database name

    Returns:
        List of dicts with 'name', 'classification', 'tags' keys.
    """
    if _USE_REFERENCE:
        return _ref.get_binary_metadata(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Return name, classification, and tags for all binaries
    pass
    ### END YOUR CODE HERE ###


def find_dangerous_import_calls(driver, database: str) -> List[Dict[str, Any]]:
    """
    Find functions that call dangerous imports (shell execution, unsafe string ops).

    Args:
        driver: Neo4j driver instance
        database: Database name

    Returns:
        List of dicts with 'function_name', 'dangerous_imports', 'binary' keys.
    """
    if _USE_REFERENCE:
        return _ref.find_dangerous_import_calls(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Find functions whose basic blocks call imports in DANGEROUS_IMPORTS
    # Hint: MATCH (f:Function)-[:ENTRY_BLOCK|ORPHAN_BLOCK]->(bb:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    pass
    ### END YOUR CODE HERE ###


def get_call_graph(driver, database: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Get call graph edges (caller → callee function pairs).

    Args:
        driver: Neo4j driver instance
        database: Database name
        limit: Maximum number of edges to return

    Returns:
        List of dicts with 'caller' and 'callee' keys.
    """
    if _USE_REFERENCE:
        return _ref.get_call_graph(driver, database, limit)
    ### YOUR CODE HERE ###
    # TODO: Match CALLS_FUNCTION relationships between functions
    pass
    ### END YOUR CODE HERE ###


# =============================================================================
# Report generation (provided — do not modify)
# =============================================================================

def print_entity_counts(counts: List[Dict[str, Any]]) -> None:
    """Print entity counts in a formatted table."""
    print("=" * 40)
    print("ENTITY COUNTS")
    print("=" * 40)
    print(f"{'Label':<20} {'Count':>10}")
    print("-" * 40)
    for row in counts:
        print(f"{row['label']:<20} {row['count']:>10}")
    print("=" * 40)


def print_relationship_counts(counts: List[Dict[str, Any]]) -> None:
    """Print relationship counts per binary."""
    print("=" * 80)
    print("RELATIONSHIP COUNTS PER BINARY")
    print("=" * 80)
    print(f"{'Name':<30} {'Functions':>10} {'Blocks':>10} {'Strings':>10} {'Imports':>10}")
    print("-" * 80)
    for row in counts:
        name = row["name"] or "N/A"
        if len(name) > 28:
            name = name[:25] + "..."
        print(f"{name:<30} {row['functions']:>10} {row['blocks']:>10} {row['strings']:>10} {row['imports']:>10}")
    print("=" * 80)


def print_dangerous_imports(results: List[Dict[str, Any]]) -> None:
    """Print functions calling dangerous imports."""
    print("=" * 80)
    print("FUNCTIONS CALLING DANGEROUS IMPORTS")
    print("=" * 80)
    if not results:
        print("  (none found)")
    else:
        for row in results:
            print(f"  {row['function_name']:<30} imports: {', '.join(row['dangerous_imports'])}")
    print("=" * 80)


def print_call_graph(edges: List[Dict[str, Any]]) -> None:
    """Print call graph edges."""
    print("=" * 60)
    print("CALL GRAPH (sample)")
    print("=" * 60)
    if not edges:
        print("  (no call edges found)")
    else:
        for row in edges:
            print(f"  {row['caller']:<30} → {row['callee']}")
    print("=" * 60)


def run_all_queries(driver, database: str) -> None:
    """Run all graph queries and print results."""
    # 1. Entity counts
    counts = count_entity_types(driver, database)
    if counts:
        print_entity_counts(counts)
    print()

    # 2. Duplicate check
    duplicates = check_duplicates(driver, database)
    if duplicates:
        print(f"⚠️  Found {len(duplicates)} duplicate SHA256(s)!")
        for d in duplicates:
            print(f"  {d['sha256']}: {d['count']} copies")
    else:
        print("✓ No duplicate binaries found.")
    print()

    # 3. Relationship counts
    rel_counts = get_relationship_counts(driver, database)
    if rel_counts:
        print_relationship_counts(rel_counts)
    print()

    # 4. Metadata
    metadata = get_binary_metadata(driver, database)
    if metadata:
        print("=" * 60)
        print("BINARY METADATA")
        print("=" * 60)
        for row in metadata:
            tags = row.get("tags") or []
            print(f"  {row['name']:<30} class={row['classification']:<12} tags={tags}")
        print("=" * 60)
    print()

    # 5. Dangerous imports
    dangerous = find_dangerous_import_calls(driver, database)
    print_dangerous_imports(dangerous)
    print()

    # 6. Call graph
    edges = get_call_graph(driver, database)
    print_call_graph(edges)


def parse_args():
    """Parse command line arguments."""
    creds = get_neo4j_credentials()
    parser = argparse.ArgumentParser(
        description="Lab 1.2: Graph Queries — validate and analyze the Neo4j program graph."
    )
    parser.add_argument("--uri", default=creds["uri"], help=f"Neo4j URI (default: {creds['uri']})")
    parser.add_argument("--user", default=creds["user"], help=f"Neo4j user (default: {creds['user']})")
    parser.add_argument("--password", default=creds["password"], help="Neo4j password")
    parser.add_argument("--database", default=creds["database"], help=f"Database (default: {creds['database']})")
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    try:
        run_all_queries(driver, args.database)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
