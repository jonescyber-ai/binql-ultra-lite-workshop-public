"""
Schema Enrichment Module for Lab 2.2.

This module enriches schema metadata with sample property values, dramatically
improving LLM query generation accuracy by showing what values are actually valid.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab2.schema_enrichment --compare

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab2.schema_enrichment --compare

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab2/lab_2_2_schema_enrichment.md
"""

import argparse
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from neo4j import Driver, GraphDatabase

from lab_common.binql import get_neo4j_credentials
from student_labs.lab2.schema_export import export_node_metadata

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab2 import schema_enrichment_reference as _ref
    logger.info("Using reference implementation for schema_enrichment")


def get_sample_values(
    driver: Driver,
    database: str,
    label: str,
    property_name: str,
    max_samples: int = 5,
) -> List[Any]:
    """
    Query sample values for a specific property.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        label: Node label (e.g., "Binary").
        property_name: Property name (e.g., "classification").
        max_samples: Maximum number of sample values to return.

    Returns:
        List of sample values (strings, integers, etc.).
    """
    if _USE_REFERENCE:
        return _ref.get_sample_values(driver, database, label, property_name, max_samples)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Clean the label - remove backticks and colons if present (e.g., ":`Binary`" -> "Binary")
    # Query for DISTINCT values of the property, limited to max_samples
    pass
    ### END YOUR CODE HERE ###


def enrich_node_properties(
    driver: Driver,
    database: str,
    nodes: List[Dict[str, Any]],
    max_samples: int = 5,
) -> List[Dict[str, Any]]:
    """
    Add sample values to node property metadata.

    Takes the output from export_node_metadata() and enriches each property
    with sample values from the database.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        nodes: List of node metadata records from export_node_metadata().
        max_samples: Maximum number of sample values per property.

    Returns:
        Enriched list with 'sampleValues' added to each record.
    """
    if _USE_REFERENCE:
        return _ref.enrich_node_properties(driver, database, nodes, max_samples)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # For each node record, call get_sample_values() and add the result as 'sampleValues'
    # Use a cache to avoid querying the same (label, property) combination multiple times
    pass
    ### END YOUR CODE HERE ###


def main() -> None:
    """Main entry point for testing schema enrichment."""
    parser = argparse.ArgumentParser(
        description="Enrich Neo4j schema metadata with sample values."
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare raw vs enriched schema output",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=5,
        help="Maximum sample values per property (default: 5)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

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
        if args.compare:
            print("=== Raw Node Metadata ===")
            nodes = export_node_metadata(driver, creds["database"])
            if nodes:
                for node in nodes[:5]:
                    print(f"  {node}")
            else:
                print("  (no results)")

            print("\n=== Enriched Node Metadata ===")
            enriched = enrich_node_properties(driver, creds["database"], nodes, args.max_samples)
            if enriched:
                for node in enriched[:5]:
                    print(f"  {node}")
            else:
                print("  (no results or not implemented)")

            print("\n=== Comparison ===")
            if nodes and enriched:
                raw_keys = set(nodes[0].keys()) if nodes else set()
                enriched_keys = set(enriched[0].keys()) if enriched else set()
                new_keys = enriched_keys - raw_keys
                print(f"  New keys added: {new_keys}")
            else:
                print("  (cannot compare - missing data)")
    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
