"""
Test Module for Lab 2.4 - Response Parser.

This module tests the response parsing functions that extract Cypher queries
from LLM responses for reliable query execution.

IMPORTANT: This test module does NOT use mocks. Instead, it uses the _reference
design pattern where:
1. Tests verify that student functions are importable and callable
2. Tests use sample data to verify function behavior
3. When USE_REFERENCE=1 is set, the reference implementation is used

Usage:
    source venv/bin/activate
    python -m student_labs.lab2.test.test_lab_2_4

    # To test with reference implementation:
    USE_REFERENCE=1 python -m student_labs.lab2.test.test_lab_2_4

Reference: docs/labs/lab2/lab_2_4_response_parser.md
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str


class Lab2_4_Test:
    """Test suite for Lab 2.4 - Response Parser."""

    def __init__(self, verbose: bool = False) -> None:
        """
        Initialize the test suite.

        Args:
            verbose: Enable verbose logging output.
        """
        self.verbose = verbose
        self.results: List[TestResult] = []

    def test_extract_cypher_from_cypher_block(self) -> TestResult:
        """Test that extract_cypher_from_response extracts from ```cypher blocks."""
        test_name = "test_extract_cypher_from_cypher_block"
        try:
            from student_labs.lab2.response_parser import extract_cypher_from_response

            # Sample LLM response with cypher code block
            sample_response = """Here's a Cypher query to find all binaries with their function counts:

```cypher
MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)
RETURN b.name, b.sha256, count(f) AS func_count
ORDER BY func_count DESC
LIMIT 25
```

This query counts functions per binary and returns them sorted."""

            result = extract_cypher_from_response(sample_response)

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a string
            if not isinstance(result, str):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected string, got {type(result).__name__}",
                )

            # Verify result contains expected content
            checks = [
                ("MATCH" in result, "Missing 'MATCH' keyword"),
                ("Binary" in result, "Missing 'Binary' node label"),
                ("RETURN" in result, "Missing 'RETURN' keyword"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            # Verify it doesn't contain the explanation text
            if "Here's a Cypher query" in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Result contains explanation text outside code block",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully extracts from ```cypher blocks",
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Import error: {e}",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Unexpected error: {e}",
            )

    def test_extract_cypher_from_generic_block(self) -> TestResult:
        """Test that extract_cypher_from_response extracts from generic ``` blocks."""
        test_name = "test_extract_cypher_from_generic_block"
        try:
            from student_labs.lab2.response_parser import extract_cypher_from_response

            # Sample LLM response with generic code block
            sample_response = """Here's the query:

```
MATCH (b:Binary)
RETURN b.name
LIMIT 10
```

This returns binary names."""

            result = extract_cypher_from_response(sample_response)

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result contains expected content
            checks = [
                ("MATCH" in result, "Missing 'MATCH' keyword"),
                ("Binary" in result, "Missing 'Binary' node label"),
                ("RETURN" in result, "Missing 'RETURN' keyword"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully extracts from generic ``` blocks",
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Import error: {e}",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Unexpected error: {e}",
            )

    def test_extract_cypher_handles_no_code_block(self) -> TestResult:
        """Test that extract_cypher_from_response handles responses without code blocks."""
        test_name = "test_extract_cypher_handles_no_code_block"
        try:
            from student_labs.lab2.response_parser import extract_cypher_from_response

            # Sample LLM response without code block (raw query)
            sample_response = "MATCH (b:Binary) RETURN b.name LIMIT 10"

            result = extract_cypher_from_response(sample_response)

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result contains expected content
            if "MATCH" not in result or "RETURN" not in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Failed to return raw query when no code block present",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully handles responses without code blocks",
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Import error: {e}",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Unexpected error: {e}",
            )

    def test_validate_cypher_basic(self) -> TestResult:
        """Test that validate_cypher_basic accepts valid queries and rejects invalid ones."""
        test_name = "test_validate_cypher_basic"
        try:
            from student_labs.lab2.response_parser import validate_cypher_basic

            # Test valid queries
            valid_queries = [
                "MATCH (b:Binary) RETURN b",
                "MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function) RETURN f.name",
                "CREATE (n:Node {name: 'test'})",
                "MERGE (n:Node {id: 1}) RETURN n",
            ]

            for query in valid_queries:
                result = validate_cypher_basic(query)
                if result is None:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message="Function returned None - not implemented",
                    )
                if not result:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Valid query rejected: {query}",
                    )

            # Test invalid queries
            invalid_queries = [
                "",  # Empty
                "   ",  # Whitespace only
                "SELECT * FROM table",  # SQL, not Cypher
                "MATCH (b:Binary",  # Unbalanced parentheses
            ]

            for query in invalid_queries:
                result = validate_cypher_basic(query)
                if result:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Invalid query accepted: {query}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message="Correctly validates and rejects queries",
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Import error: {e}",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Unexpected error: {e}",
            )

    def test_clean_cypher_query(self) -> TestResult:
        """Test that clean_cypher_query removes comments and normalizes whitespace."""
        test_name = "test_clean_cypher_query"
        try:
            from student_labs.lab2.response_parser import clean_cypher_query

            # Sample query with comments and extra whitespace
            sample_query = """MATCH (b:Binary)  // Find binaries
WHERE b.classification = 'benign'
// Return the results
RETURN b.name,   b.sha256
LIMIT 25"""

            result = clean_cypher_query(sample_query)

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a string
            if not isinstance(result, str):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected string, got {type(result).__name__}",
                )

            # Verify comments are removed
            if "//" in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Comments not removed from query",
                )

            # Verify query still contains essential parts
            checks = [
                ("MATCH" in result, "Missing 'MATCH' keyword after cleaning"),
                ("Binary" in result, "Missing 'Binary' after cleaning"),
                ("RETURN" in result, "Missing 'RETURN' keyword after cleaning"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully removes comments and normalizes whitespace",
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Import error: {e}",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Unexpected error: {e}",
            )

    def run_all(self) -> List[TestResult]:
        """
        Run all tests and return results.

        Returns:
            List of TestResult objects for each test.
        """
        tests = [
            self.test_extract_cypher_from_cypher_block,
            self.test_extract_cypher_from_generic_block,
            self.test_extract_cypher_handles_no_code_block,
            self.test_validate_cypher_basic,
            self.test_clean_cypher_query,
        ]

        self.results = []
        for test_func in tests:
            result = test_func()
            self.results.append(result)

            status = "✓ PASS" if result.passed else "✗ FAIL"
            print(f"{status}: {result.name}")
            if self.verbose or not result.passed:
                print(f"       {result.message}")

        return self.results

    def print_summary(self) -> None:
        """Print a summary of test results."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print("\n" + "=" * 40)
        print("===== Test Summary =====")
        print(f"Total Tests: {total}")
        print(f"Passed:      {passed}")
        print(f"Failed:      {failed}")
        print("=" * 40)

        if failed > 0:
            print("\nFailed tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  - {result.name}: {result.message}")


def main() -> None:
    """Main entry point for running tests."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Run tests for Lab 2.4 - Response Parser"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )

    # Override logger for script execution
    module_name = Path(__file__).stem
    global logger
    logger = logging.getLogger(module_name)

    print("=" * 40)
    print("Lab 2.4 - Response Parser Tests")
    print("=" * 40)
    print()

    # Run tests
    test_suite = Lab2_4_Test(verbose=args.verbose)
    test_suite.run_all()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
