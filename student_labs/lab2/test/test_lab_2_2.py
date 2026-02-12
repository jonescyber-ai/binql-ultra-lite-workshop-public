"""
Test Module for Lab 2.2 - Schema Enrichment.

This module tests the schema enrichment functions that add sample property
values to schema metadata for improved LLM query generation.

IMPORTANT: This test module does NOT use mocks. Instead, it uses the _reference
design pattern where:
1. Tests verify that student functions are importable and callable
2. Tests use real Neo4j connections to verify function behavior
3. When USE_REFERENCE=1 is set, the reference implementation is used

Usage:
    source venv/bin/activate
    python -m student_labs.lab2.test.test_lab_2_2

    # To test with reference implementation:
    USE_REFERENCE=1 python -m student_labs.lab2.test.test_lab_2_2

Reference: docs/labs/lab2/lab_2_2_schema_enrichment.md
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


class Lab2_2_Test:
    """
    Test suite for Lab 2.2 - Schema Enrichment.

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
            from student_labs.lab2.schema_enrichment import (
                get_sample_values,
                enrich_node_properties,
            )

            # Verify functions are callable
            checks = [
                (callable(get_sample_values), "get_sample_values is not callable"),
                (callable(enrich_node_properties), "enrich_node_properties is not callable"),
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

    def test_get_sample_values_returns_list(self) -> TestResult:
        """
        Test that get_sample_values returns a list of values for known properties.

        This test connects to Neo4j and verifies the function returns properly
        structured data. No mocks are used - the test uses real database calls.
        """
        test_name = "test_get_sample_values_returns_list"
        try:
            from student_labs.lab2.schema_enrichment import get_sample_values

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            # Test with Binary.sha256 which should exist in any populated database
            result = get_sample_values(
                driver, self._database, "Binary", "sha256", max_samples=5
            )

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

            # Result can be empty if no data exists, that's OK
            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully returns list with {len(result)} sample values",
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

    def test_enrich_node_properties_adds_sample_values(self) -> TestResult:
        """
        Test that enrich_node_properties adds sampleValues to each record.

        This test connects to Neo4j and verifies the function properly enriches
        node metadata with sample values. No mocks are used.
        """
        test_name = "test_enrich_node_properties_adds_sample_values"
        try:
            from student_labs.lab2.schema_enrichment import enrich_node_properties

            driver = self._get_driver()
            if driver is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Could not connect to Neo4j - check credentials",
                )

            # Sample node metadata (simulating output from Lab 2.1)
            sample_nodes = [
                {
                    "nodeType": ":`Binary`",
                    "nodeLabels": ["Binary"],
                    "propertyName": "sha256",
                    "propertyTypes": ["STRING"],
                    "mandatory": True,
                },
                {
                    "nodeType": ":`Binary`",
                    "nodeLabels": ["Binary"],
                    "propertyName": "name",
                    "propertyTypes": ["STRING"],
                    "mandatory": True,
                },
            ]

            result = enrich_node_properties(driver, self._database, sample_nodes)

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

            # Verify each record has sampleValues key
            for i, record in enumerate(result):
                if "sampleValues" not in record:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Record {i} missing 'sampleValues' key",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Successfully adds sampleValues to {len(result)} records",
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
            self.test_get_sample_values_returns_list,
            self.test_enrich_node_properties_adds_sample_values,
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
        description="Run tests for Lab 2.2 - Schema Enrichment"
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
    print("Lab 2.2 - Schema Enrichment Tests")
    print("=" * 40)
    print()
    print("NOTE: This test uses real Neo4j connections, not mocks.")
    print("      Set USE_REFERENCE=1 to test with reference implementation.")
    print()

    # Run tests
    test_suite = Lab2_2_Test(verbose=args.verbose)
    test_suite.run_all()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
