"""
NL2GQL: Natural Language to Graph Query Language.

This is the main entry point that ties together all Lab 2 modules to convert
natural language questions into executable Cypher queries.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab2.nl2gql --query "Find all binaries with more than 100 functions"

    # With schema enrichment (better accuracy)
    python -m student_labs.lab2.nl2gql --query "Find all benign binaries" --enrich

    # Export schema only
    python -m student_labs.lab2.nl2gql --export-schema

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab2.nl2gql --query "Find all binaries with more than 100 functions"

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions in the individual module files instead.

Reference: docs/labs/lab2/lab_2_0_overview.md
"""

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials
from lab_common.llm.client import llm_completion

# Import from student modules
from student_labs.lab2.schema_export import (
    export_node_metadata,
    export_relationship_metadata,
    export_schema_ddl,
)
from student_labs.lab2.schema_enrichment import enrich_node_properties
from student_labs.lab2.prompt_builder import (
    format_relationships_for_llm,
    format_nodes_for_llm,
    build_cypher_generation_prompt,
)
from student_labs.lab2.response_parser import (
    extract_cypher_from_response,
    validate_cypher_basic,
    clean_cypher_query,
)
from student_labs.lab2.query_executor import (
    execute_cypher_query,
    build_refinement_prompt,
    execute_with_retry,
)

logger = logging.getLogger(__name__)


def natural_language_to_cypher(
    driver,
    database: str,
    question: str,
    enrich: bool = True,
    max_samples: int = 5,
    execute: bool = True,
    limit: int = 25,
    max_retries: int = 3,
) -> Dict[str, Any]:
    """
    Convert a natural language question to Cypher and optionally execute it.

    This is the main orchestration function that ties together all Lab 2 modules.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        question: Natural language question.
        enrich: Whether to enrich schema with sample values.
        max_samples: Maximum sample values per property.
        execute: Whether to execute the generated query.
        limit: Maximum results to return.
        max_retries: Maximum retry attempts on error.

    Returns:
        Dict with question, cypher, results (if executed), and metadata.
    """
    logger.info(f"Processing question: {question}")

    # Step 1: Export schema metadata (Lab 2.1)
    logger.info("Exporting schema metadata...")
    nodes = export_node_metadata(driver, database)
    relationships = export_relationship_metadata(driver, database)

    if not nodes and not relationships:
        return {
            "success": False,
            "error": "Failed to export schema metadata. Are the functions implemented?",
            "question": question,
        }

    # Step 2: Enrich schema with sample values (Lab 2.2)
    if enrich and nodes:
        logger.info("Enriching schema with sample values...")
        nodes = enrich_node_properties(driver, database, nodes, max_samples)

    # Step 3: Build prompt with schema context (Lab 2.3)
    logger.info("Building LLM prompt...")
    rel_text = format_relationships_for_llm(relationships) or ""
    node_text = format_nodes_for_llm(nodes) or ""
    schema_text = f"{rel_text}\n{node_text}"

    system_prompt = build_cypher_generation_prompt(schema_text)
    if not system_prompt:
        return {
            "success": False,
            "error": "Failed to build system prompt. Is build_cypher_generation_prompt implemented?",
            "question": question,
        }

    # Step 4: Call LLM to generate Cypher
    logger.info("Calling LLM to generate Cypher...")
    try:
        llm_response = llm_completion(question, system_prompt=system_prompt)
        full_response = llm_response.response
        tokens_used = llm_response.total_tokens
    except Exception as e:
        return {
            "success": False,
            "error": f"LLM call failed: {e}",
            "question": question,
        }

    # Step 5: Parse response to extract Cypher (Lab 2.4)
    logger.info("Parsing LLM response...")
    cypher = extract_cypher_from_response(full_response)
    if not cypher:
        return {
            "success": False,
            "error": "Failed to extract Cypher from LLM response",
            "question": question,
            "llm_response": full_response,
        }

    cypher = clean_cypher_query(cypher) if clean_cypher_query(cypher) else cypher

    # Validate basic syntax
    if validate_cypher_basic and not validate_cypher_basic(cypher):
        logger.warning("Generated Cypher failed basic validation")

    result = {
        "success": True,
        "question": question,
        "cypher": cypher,
        "llm_response": full_response,
        "tokens_used": tokens_used,
        "schema_enriched": enrich,
    }

    # Step 6: Execute query with retry (Lab 2.5)
    if execute:
        logger.info("Executing generated Cypher...")
        exec_result = execute_with_retry(
            driver, database, cypher, question, schema_text, max_retries
        )
        if exec_result:
            result["execution"] = exec_result
        else:
            # Fall back to simple execution if execute_with_retry not implemented
            exec_result = execute_cypher_query(driver, database, cypher, limit)
            if exec_result:
                result["execution"] = exec_result

    return result


def main() -> None:
    """Main entry point for NL2GQL."""
    parser = argparse.ArgumentParser(
        description="Convert natural language to Cypher queries."
    )
    parser.add_argument(
        "--query",
        type=str,
        help="Natural language question to convert to Cypher",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        default=True,
        help="Enrich schema with sample values (default: True)",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Disable schema enrichment",
    )
    parser.add_argument(
        "--no-execute",
        action="store_true",
        help="Generate Cypher without executing",
    )
    parser.add_argument(
        "--export-schema",
        action="store_true",
        help="Export schema and exit",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum results to return (default: 25)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts on error (default: 3)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
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
        if args.export_schema:
            # Export schema only
            print("=== Exporting Schema ===\n")
            nodes = export_node_metadata(driver, creds["database"])
            relationships = export_relationship_metadata(driver, creds["database"])

            if not args.no_enrich and nodes:
                nodes = enrich_node_properties(driver, creds["database"], nodes)

            rel_text = format_relationships_for_llm(relationships)
            node_text = format_nodes_for_llm(nodes)

            if rel_text:
                print(rel_text)
            if node_text:
                print(node_text)

            if not rel_text and not node_text:
                print("Schema export returned no results. Are the functions implemented?")

        elif args.query:
            # Process natural language query
            enrich = not args.no_enrich
            execute = not args.no_execute

            result = natural_language_to_cypher(
                driver,
                creds["database"],
                args.query,
                enrich=enrich,
                execute=execute,
                limit=args.limit,
                max_retries=args.max_retries,
            )

            if args.json:
                print(json.dumps(result, indent=2, default=str))
            else:
                print(f"\n{'=' * 60}")
                print("NL2GQL Result")
                print('=' * 60)
                print(f"\nQuestion: {result.get('question')}")
                print(f"\nGenerated Cypher:\n{result.get('cypher', '(none)')}")

                if result.get('execution'):
                    exec_result = result['execution']
                    print(f"\nExecution: {'Success' if exec_result.get('success') else 'Failed'}")
                    if exec_result.get('success'):
                        print(f"Results ({exec_result.get('count', 0)} rows):")
                        for row in exec_result.get('results', [])[:10]:
                            print(f"  {row}")
                        if exec_result.get('count', 0) > 10:
                            print(f"  ... and {exec_result['count'] - 10} more")
                    else:
                        print(f"Error: {exec_result.get('error')}")

                if not result.get('success'):
                    print(f"\nError: {result.get('error')}")

        else:
            parser.print_help()
            print("\nExamples:")
            print("  python -m student_labs.lab2.nl2gql --query 'Find all binaries with more than 100 functions'")
            print("  python -m student_labs.lab2.nl2gql --export-schema")
            print("  python -m student_labs.lab2.nl2gql --query 'List functions' --no-execute")

    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
