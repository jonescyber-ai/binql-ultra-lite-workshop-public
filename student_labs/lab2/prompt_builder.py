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
    lines = []
    lines.append("=" * 60)
    lines.append("RELATIONSHIP TYPES (Graph Topology)")
    lines.append("=" * 60)
    lines.append("")

    # Group by relationship type
    rel_groups: Dict[str, List[Dict[str, Any]]] = {}
    for rel in relationships:
        rel_type = rel.get("relType", "UNKNOWN")
        if rel_type not in rel_groups:
            rel_groups[rel_type] = []
        rel_groups[rel_type].append(rel)

    for rel_type, rels in sorted(rel_groups.items()):
        # Clean the relationship type name
        clean_type = rel_type.replace(":`", "").replace("`", "").replace(":", "")
        lines.append(f"Relationship: {clean_type}")

        # Show source -> target patterns
        patterns = set()
        for rel in rels:
            sources = rel.get("sourceNodeLabels", [])
            targets = rel.get("targetNodeLabels", [])
            for src in sources:
                for tgt in targets:
                    patterns.add(f"  ({src})-[:{clean_type}]->({tgt})")

        for pattern in sorted(patterns):
            lines.append(pattern)
        lines.append("")

    return "\n".join(lines)
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
    lines = []
    lines.append("=" * 60)
    lines.append("NODE LABELS AND PROPERTIES")
    lines.append("=" * 60)
    lines.append("")

    # Group by node type
    node_groups: Dict[str, List[Dict[str, Any]]] = {}
    for node in nodes:
        node_type = node.get("nodeType", "UNKNOWN")
        if node_type not in node_groups:
            node_groups[node_type] = []
        node_groups[node_type].append(node)

    for node_type, props in sorted(node_groups.items()):
        # Clean the node type name
        clean_type = node_type.replace(":`", "").replace("`", "").replace(":", "")
        lines.append(f"Node: {clean_type}")

        for prop in props:
            prop_name = prop.get("propertyName", "unknown")
            prop_types = prop.get("propertyTypes", [])
            mandatory = prop.get("mandatory", False)
            samples = prop.get("sampleValues", [])

            type_str = ", ".join(prop_types) if prop_types else "UNKNOWN"
            req_str = "required" if mandatory else "optional"

            lines.append(f"  - {prop_name} ({type_str}, {req_str})")

            # Add sample values if available
            if samples:
                # Truncate long values for display
                display_samples = []
                for s in samples[:3]:
                    s_str = str(s)
                    if len(s_str) > 30:
                        s_str = s_str[:27] + "..."
                    display_samples.append(f'"{s_str}"')
                lines.append(f"    Samples: [{', '.join(display_samples)}]")

        lines.append("")

    return "\n".join(lines)
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
    prompt = f"""You are an expert Neo4j Cypher query generator. Given a natural language question, generate an accurate Cypher query.

DATABASE SCHEMA:
{schema_text}

INSTRUCTIONS:
1. Generate ONLY valid Cypher syntax
2. Use exact node labels and relationship types from the schema
3. Use only properties that exist in the schema
4. Respect property types (STRING, INTEGER, etc.)
5. Follow relationship direction: (Source)-[:TYPE]->(Target)
6. Use MATCH for queries, not CREATE/MERGE unless explicitly asked
7. Return your Cypher query inside ```cypher and ``` code blocks
8. Add a brief explanation after the query
9. Include LIMIT 25 unless the user specifies a different limit

EXAMPLE:
User: "Find all binaries with more than 100 functions"
Assistant:
```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
WITH b, count(f) AS func_count
WHERE func_count > 100
RETURN b.name, b.sha256, func_count
ORDER BY func_count DESC
LIMIT 25
```

This query finds binaries with more than 100 functions and returns their name, SHA256 hash, and function count.
"""
    return prompt
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
