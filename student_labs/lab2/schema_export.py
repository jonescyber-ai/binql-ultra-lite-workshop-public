"""
Schema Export Module for Lab 2.1.

This module exports Neo4j database schema metadata using APOC procedures.
The exported schema provides LLMs with the context they need to generate accurate Cypher queries.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab2.schema_export --test

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab2.schema_export --test

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab2/lab_2_1_schema_export.md
"""

import argparse
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from neo4j import Driver, GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab2 import schema_export_reference as _ref
    logger.info("Using reference implementation for schema_export")


def export_node_metadata(driver: Driver, database: str) -> List[Dict[str, Any]]:
    """
    Export node labels and their properties using APOC.

    Uses APOC's apoc.meta.nodeTypeProperties() to get comprehensive node metadata.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        List of dictionaries containing node metadata with keys:
        - nodeType: The node label (e.g., ":`Binary`")
        - nodeLabels: Array of labels
        - propertyName: Name of each property
        - propertyTypes: Data types (STRING, INTEGER, etc.)
        - mandatory: Whether the property is required
    """
    if _USE_REFERENCE:
        return _ref.export_node_metadata(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Use APOC's apoc.meta.nodeTypeProperties() procedure
    # Query should return: nodeType, nodeLabels, propertyName, propertyTypes, mandatory
    pass
    ### END YOUR CODE HERE ###


def export_relationship_metadata(driver: Driver, database: str) -> List[Dict[str, Any]]:
    """
    Export relationship types with source/target labels and properties.

    Uses APOC's apoc.meta.relTypeProperties() to get comprehensive relationship metadata.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        List of dictionaries containing relationship metadata with keys:
        - relType: The relationship type (e.g., ":`HAS_FUNCTION`")
        - sourceNodeLabels: Array of source node labels
        - targetNodeLabels: Array of target node labels
        - propertyName: Name of each property (if any)
        - propertyTypes: Data types
        - mandatory: Whether the property is required
    """
    if _USE_REFERENCE:
        return _ref.export_relationship_metadata(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Use APOC's apoc.meta.relTypeProperties() procedure
    # Query should return: relType, sourceNodeLabels, targetNodeLabels, propertyName, propertyTypes, mandatory
    pass
    ### END YOUR CODE HERE ###


def export_schema_ddl(driver: Driver, database: str) -> str:
    """
    Export constraints and indexes as Cypher DDL statements.

    Uses APOC's apoc.export.cypher.schema() to get schema as Cypher statements.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        String containing Cypher DDL statements for constraints and indexes.
    """
    if _USE_REFERENCE:
        return _ref.export_schema_ddl(driver, database)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Use APOC's apoc.export.cypher.schema() procedure
    # Return the DDL statements as a string
    pass
    ### END YOUR CODE HERE ###


def main() -> None:
    """Main entry point for testing schema export."""
    parser = argparse.ArgumentParser(
        description="Export Neo4j schema metadata using APOC procedures."
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run test export and display results",
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
        if args.test:
            print("=== Node Metadata ===")
            nodes = export_node_metadata(driver, creds["database"])
            if nodes:
                for node in nodes[:10]:  # Show first 10
                    print(f"  {node}")
                if len(nodes) > 10:
                    print(f"  ... and {len(nodes) - 10} more")
            else:
                print("  (no results or not implemented)")

            print("\n=== Relationship Metadata ===")
            rels = export_relationship_metadata(driver, creds["database"])
            if rels:
                for rel in rels[:10]:  # Show first 10
                    print(f"  {rel}")
                if len(rels) > 10:
                    print(f"  ... and {len(rels) - 10} more")
            else:
                print("  (no results or not implemented)")

            print("\n=== Schema DDL ===")
            ddl = export_schema_ddl(driver, creds["database"])
            if ddl:
                print(ddl[:1000])  # Show first 1000 chars
                if len(ddl) > 1000:
                    print(f"... ({len(ddl) - 1000} more characters)")
            else:
                print("  (no results or not implemented)")
    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
