"""
Test Module for Lab 2.5 - Query Executor.

This module tests the query execution functions with automatic retry
on errors for reliable Cypher query execution.

IMPORTANT: This test module does NOT use mocks. Instead, it uses the _reference
design pattern where:
1. Tests verify that student functions are importable and callable
2. Tests use real Neo4j connections to verify function behavior
3. Tests use sample data for functions that don't need database access
4. When USE_REFERENCE=1 is set, the reference implementation is used

Usage:
    source venv/bin/activate
    python -m student_labs.lab2.test.test_lab_2_5

    # To test with reference implementation:
    USE_REFERENCE=1 python -m student_labs.lab2.test.test_lab_2_5

Reference: docs/labs/lab2/lab_2_5_query_executor.md
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str


class Lab2_5_Test:
    """
    Test suite for Lab 2.5 - Query Executor.

    This test suite validates student implementations by:
    1. Checking that functions are importable and callable
    2. Testing with a real Neo4j connection (when available)
    3. Using sample data for functions that don't need database access

    NOTE: No mocks are used. Tests use the _reference design pattern.
    """

    def __init__(self, verbose: bool = False) -> None:
        """
        Initialize the test suite.

        Args:
            verbose: Enable verbose logging output.
        """
        self.verbose = verbose
        self.results: List[TestResult] = []
        self._driver = None
        self._database = None

    def _get_driver(self) -> Optional[Any]:
        """Get Neo4j driver, creating if necessary."""
        if self._driver is None:
            try:
                creds = get_neo4j_credentials()
                self._driver = GraphDatabase.driver(
                    creds["uri"],
                    auth=(creds["user"], creds["password"]),
                )
                self._database = creds["database"]
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j: {e}")
                return None
        return self._driver

    def _close_driver(self) -> None:
        """Close the Neo4j driver if open."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def test_functions_are_importable(self) -> TestResult:
        """Test that all required functions can be imported from the module."""
        test_name = "test_functions_are_importable"
        try:
            from student_labs.lab2.query_executor import (
                execute_cypher_query,
                build_refinement_prompt,
                execute_with_retry,
            )

            # Verify functions are callable
            checks = [
                (callable(execute_cypher_query), "execute_cypher_query is not callable"),
                (callable(build_refinement_prompt), "build_refinement_prompt is not callable"),
                (callable(execute_with_retry), "execute_with_retry is not callable"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="All required functions are importable and callable",
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

    def test_execute_cypher_query_success(self) -> TestResult:
        """
        Test that execute_cypher_query returns success with valid queries.

        This test connects to Neo4j and verifies the function returns properly
        structured data. No mocks are used - the test uses real database calls.
        """
        test_name = "test_execute_cypher_query_success"
        try:
            from student_labs.lab2.query_executor import execute_cypher_query

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            # Use a simple query that should work on any database
            result = execute_cypher_query(
                driver, self._database, "MATCH (n) RETURN count(n) AS count LIMIT 1"
            )

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a dict
            if not isinstance(result, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(result).__name__}",
                )

            # Verify success key exists
            if "success" not in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Result missing 'success' key",
                )

            # Verify results key exists when successful
            if result.get("success") and "results" not in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Result missing 'results' key for successful query",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully returns dict with success={result.get('success')}",
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

    def test_execute_cypher_query_error(self) -> TestResult:
        """
        Test that execute_cypher_query returns error info with invalid queries.

        This test connects to Neo4j and verifies the function handles errors
        properly. No mocks are used - the test uses real database calls.
        """
        test_name = "test_execute_cypher_query_error"
        try:
            from student_labs.lab2.query_executor import execute_cypher_query

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            # Use an intentionally invalid query
            result = execute_cypher_query(
                driver, self._database, "THIS IS NOT VALID CYPHER SYNTAX"
            )

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a dict
            if not isinstance(result, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(result).__name__}",
                )

            # Verify success key exists and is False
            if "success" not in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Result missing 'success' key",
                )

            if result.get("success"):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Expected success=False for invalid query",
                )

            # Verify error key exists
            if "error" not in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Result missing 'error' key for failed query",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully returns error info with invalid queries",
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

    def test_build_refinement_prompt_includes_context(self) -> TestResult:
        """
        Test that build_refinement_prompt includes all required context.

        This test uses sample data - no database connection needed.
        """
        test_name = "test_build_refinement_prompt_includes_context"
        try:
            from student_labs.lab2.query_executor import build_refinement_prompt

            # Sample inputs for testing
            question = "Find all binaries with more than 100 functions"
            failed_query = "MATCH (b:Binary) RETURN b.undefined_property"
            error_message = "Property 'undefined_property' does not exist"
            schema_text = "Node: Binary\n  - sha256 (STRING)\n  - name (STRING)"

            result = build_refinement_prompt(
                question, failed_query, error_message, schema_text
            )

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

            # Verify all context is included
            checks = [
                (question in result, "Missing original question in prompt"),
                (failed_query in result, "Missing failed query in prompt"),
                (error_message in result, "Missing error message in prompt"),
                (schema_text in result, "Missing schema text in prompt"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully includes all required context",
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

    def test_execute_with_retry_returns_dict(self) -> TestResult:
        """
        Test that execute_with_retry returns a properly structured dict.

        This test connects to Neo4j and verifies the function returns properly
        structured data. No mocks are used - the test uses real database calls.
        """
        test_name = "test_execute_with_retry_returns_dict"
        try:
            from student_labs.lab2.query_executor import execute_with_retry

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            # Use a valid query that should succeed on first try
            result = execute_with_retry(
                driver,
                self._database,
                "MATCH (n) RETURN count(n) AS count LIMIT 1",
                "Count all nodes",
                "Schema: Any nodes",
                max_retries=1
            )

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a dict
            if not isinstance(result, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(result).__name__}",
                )

            # Verify success key exists
            if "success" not in result:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Result missing 'success' key",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully returns dict with success={result.get('success')}",
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
            self.test_functions_are_importable,
            self.test_execute_cypher_query_success,
            self.test_execute_cypher_query_error,
            self.test_build_refinement_prompt_includes_context,
            self.test_execute_with_retry_returns_dict,
        ]

        self.results = []
        for test_func in tests:
            result = test_func()
            self.results.append(result)

            status = "✓ PASS" if result.passed else "✗ FAIL"
            print(f"{status}: {result.name}")
            if self.verbose or not result.passed:
                print(f"       {result.message}")

        # Clean up driver
        self._close_driver()

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
        description="Run tests for Lab 2.5 - Query Executor"
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
    print("Lab 2.5 - Query Executor Tests")
    print("=" * 40)
    print()
    print("NOTE: This test uses real Neo4j connections, not mocks.")
    print("      Set USE_REFERENCE=1 to test with reference implementation.")
    print()

    # Run tests
    test_suite = Lab2_5_Test(verbose=args.verbose)
    test_suite.run_all()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
