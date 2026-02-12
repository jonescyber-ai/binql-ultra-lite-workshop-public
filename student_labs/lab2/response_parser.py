"""
Response Parser Module for Lab 2.4.

This module extracts Cypher queries from LLM responses. LLMs return free-form text,
so robust parsing is essential for reliable query execution.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab2.response_parser --test

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab2.response_parser --test

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should implement
      the stub functions marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab2/lab_2_4_response_parser.md
"""

import argparse
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab2 import response_parser_reference as _ref
    logger.info("Using reference implementation for response_parser")


def extract_cypher_from_response(response_text: str) -> str:
    """
    Extract Cypher query from LLM response.

    Looks for Cypher code blocks marked with ```cypher or ```

    Args:
        response_text: Raw LLM response text.

    Returns:
        Extracted Cypher query string, or empty string if not found.
    """
    if _USE_REFERENCE:
        return _ref.extract_cypher_from_response(response_text)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # 1. Try to find code blocks with ```cypher marker
    # 2. Fall back to any ``` code block
    # 3. If no code block, return the stripped response
    pass
    ### END YOUR CODE HERE ###


def validate_cypher_basic(cypher: str) -> bool:
    """
    Perform basic validation of Cypher query syntax.

    Args:
        cypher: Cypher query string to validate.

    Returns:
        True if the query passes basic validation, False otherwise.
    """
    if _USE_REFERENCE:
        return _ref.validate_cypher_basic(cypher)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Check for:
    # 1. Non-empty query
    # 2. Contains at least one Cypher keyword (MATCH, RETURN, CREATE, etc.)
    # 3. Balanced parentheses and brackets
    pass
    ### END YOUR CODE HERE ###


def clean_cypher_query(cypher: str) -> str:
    """
    Clean and normalize a Cypher query.

    Args:
        cypher: Raw Cypher query string.

    Returns:
        Cleaned Cypher query string.
    """
    if _USE_REFERENCE:
        return _ref.clean_cypher_query(cypher)
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # 1. Strip whitespace
    # 2. Remove any leading/trailing semicolons
    # 3. Normalize whitespace (collapse multiple spaces)
    pass
    ### END YOUR CODE HERE ###


# Sample LLM responses for testing
SAMPLE_RESPONSES = [
    # Response with cypher code block
    """Here's the query to find all binaries with their function counts:

```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
RETURN b.name, b.sha256, count(f) AS func_count
ORDER BY func_count DESC
LIMIT 25
```

This query counts functions per binary and returns them sorted.""",

    # Response with generic code block
    """To find functions that call system:

```
MATCH (f:Function)-[:ENTRY_BLOCK|ORPHAN_BLOCK]->(bb:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
WHERE imp.name = 'system'
RETURN f.name, f.binary_sha256
```""",

    # Response with just the query (no code block)
    """MATCH (b:Binary) WHERE b.classification = 'benign' RETURN b.name LIMIT 10""",

    # Response with explanation but no query
    """I would need more information about what you're looking for. Could you please clarify?""",
]


def main() -> None:
    """Main entry point for testing response parser."""
    parser = argparse.ArgumentParser(
        description="Parse Cypher queries from LLM responses."
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run tests with sample LLM responses",
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

    if args.test:
        print("=== Testing Response Parser ===\n")

        for i, response in enumerate(SAMPLE_RESPONSES, 1):
            print(f"--- Sample {i} ---")
            print(f"Response preview: {response[:100]}...")

            # Extract Cypher
            cypher = extract_cypher_from_response(response)
            print(f"Extracted: {cypher[:100] if cypher else '(none)'}...")

            # Validate
            if cypher:
                valid = validate_cypher_basic(cypher)
                print(f"Valid: {valid}")

                # Clean
                cleaned = clean_cypher_query(cypher)
                print(f"Cleaned: {cleaned[:100] if cleaned else '(none)'}...")
            else:
                print("Valid: N/A (no query extracted)")
                print("Cleaned: N/A")

            print()


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logger = logging.getLogger(module_name)
    main()
