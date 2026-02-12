"""
Query Executor Module for Lab 2.5.

This module executes Cypher queries with automatic retry on errors. When a generated
query fails, the system feeds the error back to the LLM for correction — a key feature
that dramatically improves reliability.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab2.query_executor --test-retry

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab2.query_executor --test-retry

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab2/lab_2_5_query_executor.md
"""

import argparse
import logging
import os
from pathlib import Path
from typing import Any, Dict

from neo4j import Driver, GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab2 import query_executor_reference as _ref
    logger.info("Using reference implementation for query_executor")


def execute_cypher_query(
    driver: Driver,
    database: str,
    cypher: str,
    limit: int = 25,
) -> Dict[str, Any]:
    """
    Execute a Cypher query against Neo4j.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        cypher: Cypher query to execute.
        limit: Maximum results to return.

    Returns:
        Dict with 'success', 'results' or 'error', and 'query'.
    """
    if _USE_REFERENCE:
        return _ref.execute_cypher_query(driver, database, cypher, limit)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # 1. Execute the query using driver.session()
    # 2. Convert results to list of dicts
    # 3. Apply limit if results exceed it
    # 4. Return success dict with results, or error dict on exception
    pass
    ### END YOUR CODE HERE ###


def build_refinement_prompt(
    question: str,
    failed_query: str,
    error_message: str,
    schema_text: str,
) -> str:
    """
    Build prompt for query refinement after error.

    Args:
        question: Original natural language question.
        failed_query: The Cypher query that failed.
        error_message: Error message from Neo4j.
        schema_text: Schema context for the LLM.

    Returns:
        System prompt for query refinement.
    """
    if _USE_REFERENCE:
        return _ref.build_refinement_prompt(question, failed_query, error_message, schema_text)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Build a prompt that includes:
    # 1. The original question
    # 2. The failed query
    # 3. The error message
    # 4. Schema context
    # 5. Instructions to fix the query
    pass
    ### END YOUR CODE HERE ###


def execute_with_retry(
    driver: Driver,
    database: str,
    cypher: str,
    question: str,
    schema_text: str,
    max_retries: int = 3,
) -> Dict[str, Any]:
    """
    Execute query with automatic retry on errors.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        cypher: Initial Cypher query to execute.
        question: Original natural language question (for refinement).
        schema_text: Schema context (for refinement prompts).
        max_retries: Maximum number of retry attempts.

    Returns:
        Dict with execution results and retry history.
    """
    if _USE_REFERENCE:
        return _ref.execute_with_retry(driver, database, cypher, question, schema_text, max_retries)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # 1. Try to execute the query
    # 2. If it fails, build a refinement prompt with the error
    # 3. Call LLM to get a corrected query
    # 4. Retry up to max_retries times
    # 5. Track retry history
    pass
    ### END YOUR CODE HERE ###


def main() -> None:
    """Main entry point for testing query executor."""
    parser = argparse.ArgumentParser(
        description="Execute Cypher queries with retry logic."
    )
    parser.add_argument(
        "--test-retry",
        action="store_true",
        help="Test the retry mechanism with a broken query",
    )
    parser.add_argument(
        "--query",
        type=str,
        help="Execute a specific Cypher query",
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
        if args.test_retry:
            print("=== Testing Query Execution ===\n")

            # Test with a valid query
            print("--- Valid Query ---")
            valid_query = "MATCH (b:Binary) RETURN b.name LIMIT 5"
            result = execute_cypher_query(driver, creds["database"], valid_query)
            if result:
                print(f"Success: {result.get('success')}")
                print(f"Count: {result.get('count', 'N/A')}")
            else:
                print("  (not implemented)")

            # Test with an invalid query
            print("\n--- Invalid Query ---")
            invalid_query = "MATCH (x:NonExistentLabel) RETURN x.undefined_property"
            result = execute_cypher_query(driver, creds["database"], invalid_query)
            if result:
                print(f"Success: {result.get('success')}")
                if not result.get('success'):
                    print(f"Error: {result.get('error', 'N/A')[:100]}...")
            else:
                print("  (not implemented)")

        elif args.query:
            print(f"Executing: {args.query}")
            result = execute_cypher_query(driver, creds["database"], args.query)
            if result:
                print(f"Success: {result.get('success')}")
                if result.get('success'):
                    print(f"Results: {result.get('results', [])[:5]}")
                else:
                    print(f"Error: {result.get('error')}")
            else:
                print("  (not implemented)")
        else:
            print("Use --test-retry or --query to test the executor")

    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
