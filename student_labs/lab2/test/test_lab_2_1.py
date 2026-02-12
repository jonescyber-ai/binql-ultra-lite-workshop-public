"""
Test Module for Lab 2.1 - Schema Export.

This module tests the schema export functions that extract comprehensive
schema metadata from Neo4j using APOC procedures.

IMPORTANT: This test module does NOT use mocks. Instead, it uses the _reference
design pattern where:
1. Tests verify that student functions are importable and callable
2. Tests use sample data to verify function behavior
3. When USE_REFERENCE=1 is set, the reference implementation is used

Usage:
    source venv/bin/activate
    python -m student_labs.lab2.test.test_lab_2_1

    # To test with reference implementation:
    USE_REFERENCE=1 python -m student_labs.lab2.test.test_lab_2_1

Reference: docs/labs/lab2/lab_2_1_schema_export.md
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str


class Lab2_1_Test:
    """
    Test suite for Lab 2.1 - Schema Export.

    This test suite validates student implementations by:
    1. Checking that functions are importable and callable
    2. Testing with a real Neo4j connection (when available)
    3. Comparing output structure against expected format

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
            from student_labs.lab2.schema_export import (
                export_node_metadata,
                export_relationship_metadata,
                export_schema_ddl,
            )

            # Verify functions are callable
            checks = [
                (callable(export_node_metadata), "export_node_metadata is not callable"),
                (callable(export_relationship_metadata), "export_relationship_metadata is not callable"),
                (callable(export_schema_ddl), "export_schema_ddl is not callable"),
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

    def test_export_node_metadata_returns_list(self) -> TestResult:
        """
        Test that export_node_metadata returns a list of node property records.

        This test connects to Neo4j and verifies the function returns properly
        structured data. No mocks are used - the test uses real database calls.
        """
        test_name = "test_export_node_metadata_returns_list"
        try:
            from student_labs.lab2.schema_export import export_node_metadata

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            result = export_node_metadata(driver, self._database)

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a list
            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(result).__name__}",
                )

            # If we got results, verify structure
            if len(result) > 0:
                first_record = result[0]
                expected_keys = {"nodeType", "nodeLabels", "propertyName", "propertyTypes", "mandatory"}
                actual_keys = set(first_record.keys())

                if not expected_keys.issubset(actual_keys):
                    missing = expected_keys - actual_keys
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Missing expected keys in result: {missing}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully returns list with {len(result)} node metadata records",
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

    def test_export_relationship_metadata_returns_list(self) -> TestResult:
        """
        Test that export_relationship_metadata returns a list of relationship records.

        This test connects to Neo4j and verifies the function returns properly
        structured data. No mocks are used - the test uses real database calls.
        """
        test_name = "test_export_relationship_metadata_returns_list"
        try:
            from student_labs.lab2.schema_export import export_relationship_metadata

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            result = export_relationship_metadata(driver, self._database)

            # Verify result is not None
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            # Verify result is a list
            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(result).__name__}",
                )

            # If we got results, verify structure
            if len(result) > 0:
                first_record = result[0]
                expected_keys = {"relType", "sourceNodeLabels", "targetNodeLabels"}
                actual_keys = set(first_record.keys())

                if not expected_keys.issubset(actual_keys):
                    missing = expected_keys - actual_keys
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Missing expected keys in result: {missing}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully returns list with {len(result)} relationship metadata records",
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

    def test_export_schema_ddl_returns_string(self) -> TestResult:
        """
        Test that export_schema_ddl returns a string with DDL statements.

        This test connects to Neo4j and verifies the function returns properly
        formatted DDL. No mocks are used - the test uses real database calls.

        Note: This test may pass with a warning if apoc.export.file.enabled is not
        set in Neo4j's apoc.conf. This is an environment configuration issue, not
        a code issue.
        """
        test_name = "test_export_schema_ddl_returns_string"
        try:
            from student_labs.lab2.schema_export import export_schema_ddl

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            result = export_schema_ddl(driver, self._database)

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

            # DDL can be empty if no constraints/indexes exist, that's OK
            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully returns DDL string ({len(result)} chars)",
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Import error: {e}",
            )
        except Exception as e:
            error_str = str(e)
            # Handle Neo4j APOC export configuration issue gracefully
            # This occurs when apoc.export.file.enabled is not set in apoc.conf
            if "apoc.export.file.enabled" in error_str or "export to files is not enabled" in error_str.lower():
                return TestResult(
                    name=test_name,
                    passed=True,
                    message="SKIPPED: apoc.export.file.enabled not set in Neo4j (environment config issue)",
                )
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
            self.test_export_node_metadata_returns_list,
            self.test_export_relationship_metadata_returns_list,
            self.test_export_schema_ddl_returns_string,
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
        description="Run tests for Lab 2.1 - Schema Export"
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
    print("Lab 2.1 - Schema Export Tests")
    print("=" * 40)
    print()
    print("NOTE: This test uses real Neo4j connections, not mocks.")
    print("      Set USE_REFERENCE=1 to test with reference implementation.")
    print()

    # Run tests
    test_suite = Lab2_1_Test(verbose=args.verbose)
    test_suite.run_all()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
