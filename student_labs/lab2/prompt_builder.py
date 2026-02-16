"""
Prompt Builder Module for Lab 2.3.

This module builds LLM prompts that combine schema metadata with instructions
to create effective prompts for Cypher generation.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab2.prompt_builder --test

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab2.prompt_builder --test

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab2/lab_2_3_prompt_builder.md
"""

import argparse
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials
from student_labs.lab2.schema_export import export_node_metadata, export_relationship_metadata
from student_labs.lab2.schema_enrichment import enrich_node_properties

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab2 import prompt_builder_reference as _ref
    logger.info("Using reference implementation for prompt_builder")


def format_relationships_for_llm(relationships: List[Dict[str, Any]]) -> str:
    """
    Format relationship metadata into LLM-friendly text.

    Args:
        relationships: List of relationship records from APOC.

    Returns:
        Formatted string describing relationship patterns.
    """
    if _USE_REFERENCE:
        return _ref.format_relationships_for_llm(relationships)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Group relationships by type, clean type names, and format as readable text
    # Show source -> target patterns for each relationship type
    pass
    ### END YOUR CODE HERE ###


def format_nodes_for_llm(
    nodes: List[Dict[str, Any]],
    descriptions: Optional[Dict[str, str]] = None,
) -> str:
    """
    Format node metadata with properties and sample values.

    Args:
        nodes: List of node records from APOC (optionally enriched with sample values).
        descriptions: Optional dict mapping property names to descriptions.

    Returns:
        Formatted string describing node labels and their properties.
    """
    if _USE_REFERENCE:
        return _ref.format_nodes_for_llm(nodes, descriptions)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Group nodes by type, clean type names, and format properties as readable text
    # Include sample values if available (from enrichment step)
    pass
    ### END YOUR CODE HERE ###


def build_cypher_generation_prompt(schema_text: str) -> str:
    """
    Build the complete system prompt for Cypher generation.

    Args:
        schema_text: Formatted schema text from format_relationships_for_llm and format_nodes_for_llm.

    Returns:
        Complete system prompt ready for LLM consumption.
    """
    if _USE_REFERENCE:
        return _ref.build_cypher_generation_prompt(schema_text)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Build a system prompt that includes the schema text and instructions for Cypher generation
    # Include guidelines for valid Cypher syntax, code block formatting, and a LIMIT clause
    pass
    ### END YOUR CODE HERE ###


def main() -> None:
    """Main entry point for testing prompt builder."""
    parser = argparse.ArgumentParser(
        description="Build LLM prompts with schema context."
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run test and display formatted output",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Include sample values in schema",
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
            # Get schema metadata
            nodes = export_node_metadata(driver, creds["database"])
            relationships = export_relationship_metadata(driver, creds["database"])

            # Optionally enrich with sample values
            if args.enrich and nodes:
                nodes = enrich_node_properties(driver, creds["database"], nodes)

            print("=== Formatted Relationships ===")
            rel_text = format_relationships_for_llm(relationships)
            if rel_text:
                print(rel_text[:2000])
                if len(rel_text) > 2000:
                    print(f"... ({len(rel_text) - 2000} more characters)")
            else:
                print("  (not implemented)")

            print("\n=== Formatted Nodes ===")
            node_text = format_nodes_for_llm(nodes)
            if node_text:
                print(node_text[:2000])
                if len(node_text) > 2000:
                    print(f"... ({len(node_text) - 2000} more characters)")
            else:
                print("  (not implemented)")

            print("\n=== System Prompt ===")
            if rel_text and node_text:
                schema_text = f"{rel_text}\n{node_text}"
                prompt = build_cypher_generation_prompt(schema_text)
                if prompt:
                    print(prompt[:3000])
                    if len(prompt) > 3000:
                        print(f"... ({len(prompt) - 3000} more characters)")
                else:
                    print("  (not implemented)")
            else:
                print("  (cannot build - missing schema text)")
    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
