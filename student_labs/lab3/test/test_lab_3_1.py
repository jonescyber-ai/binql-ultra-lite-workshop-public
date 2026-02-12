"""
Lab 3.1 Test: User-Controlled Input Detection Functions.

This test validates Lab 3.1 from lab_3_1_user_input_detection.md:
- The user_input_detection module is importable
- The Lab 3 dataset is ingested (binaries from dataset/lab3/)
- All 6 input detection functions execute successfully
- Functions return InputSourceResult objects with expected fields
- The aggregation functions work correctly

This is the student test file containing all test logic. The instructor test
in labs/lab3/test/test_lab_3_1.py is a thin wrapper that delegates to this file.

Reference: docs/labs/lab3/lab_3_1_user_input_detection.md

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.test.test_lab_3_1

    # Run with verbose output
    python -m student_labs.lab3.test.test_lab_3_1 -v
"""

import argparse
import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

# Reconfigure stdout for Unicode support on Windows cp1252 consoles
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

logger = logging.getLogger(__name__)

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent

# Expected dataset directory
EXPECTED_DATASET_DIR = PROJECT_ROOT / "dataset" / "lab3"

# Test binary SHA256 (libpng16.so.16.50.0 from dataset/lab3/)
TEST_BINARY_SHA256 = "5901ede53ed33d4feafbc9763ebb86209d542c456b3990bb887177982fb1ceb6"


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    results_data: Optional[List[Any]] = None
    input_source_type: Optional[str] = None


class Lab5_1_Test:
    """
    Test suite for Lab 3.1 - User-Controlled Input Detection Functions.

    This test suite validates the student-implemented functions in
    student_labs/lab3/user_input_detection.py:
    1. The module is importable
    2. Lab 3 binaries are ingested in Neo4j
    3. All 6 input detection functions execute successfully
    4. Functions return properly structured InputSourceResult objects
    5. Aggregation functions work correctly

    NOTE: This is a query implementation lab test that validates function implementations.
    """

    def __init__(self, verbose: bool = False) -> None:
        """
        Initialize the test suite.

        Args:
            verbose: Enable verbose logging output.
        """
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.driver = None
        self.database = None

    def setup(self) -> None:
        """Set up Neo4j connection for tests."""
        creds = get_neo4j_credentials()
        self.driver = GraphDatabase.driver(
            creds["uri"],
            auth=(creds["user"], creds["password"]),
        )
        self.database = creds.get("database", "neo4j")

    def teardown(self) -> None:
        """Clean up Neo4j connection."""
        if self.driver:
            self.driver.close()

    def test_module_importable(self) -> TestResult:
        """
        Test that the user_input_detection module is importable.

        From lab_3_1_user_input_detection.md:
        - Student file: student_labs/lab3/user_input_detection.py
        """
        test_name = "test_module_importable"

        try:
            from student_labs.lab3 import user_input_detection

            # Check that required functions exist
            required_functions = [
                "detect_network_input",
                "detect_file_input",
                "detect_stdin_input",
                "detect_environment_input",
                "detect_ipc_input",
                "detect_cmdline_input",
                "get_all_input_sources",
                "get_high_risk_functions",
            ]

            missing_functions = []
            for func_name in required_functions:
                if not hasattr(user_input_detection, func_name):
                    missing_functions.append(func_name)

            if missing_functions:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Module missing required functions: {missing_functions}",
                    details={"missing_functions": missing_functions},
                )

            # Check that InputSourceResult dataclass exists
            if not hasattr(user_input_detection, "InputSourceResult"):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Module missing InputSourceResult dataclass",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="Module importable with all required functions",
                details={"functions": required_functions},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Failed to import module: {e}",
            )

    def test_binaries_ingested(self) -> TestResult:
        """
        Test that binaries are ingested in Neo4j.

        From lab_3_0_overview.md:
        - Binaries should be ingested from dataset/lab3/ or other sources
        - The test binary (libpng16.so.16.50.0) should be present
        """
        test_name = "test_binaries_ingested"

        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("MATCH (b:Binary) RETURN count(b) AS count")
                record = result.single()
                count = record["count"] if record else 0

            if count == 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="No binaries found in Neo4j. Run Lab 3 setup first.",
                    details={"binary_count": count},
                )

            # Check for the specific test binary
            with self.driver.session(database=self.database) as session:
                result = session.run(
                    "MATCH (b:Binary) WHERE b.sha256 = $sha256 RETURN b.name AS name",
                    {"sha256": TEST_BINARY_SHA256}
                )
                record = result.single()

            if record is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Test binary not found. Expected SHA256: {TEST_BINARY_SHA256[:16]}...",
                    details={"binary_count": count, "test_binary_found": False},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Found {count} binaries in Neo4j, including test binary: {record['name']}",
                details={"binary_count": count, "test_binary_found": True, "test_binary_name": record["name"]},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Failed to query Neo4j: {e}",
            )

    def test_detect_network_input(self) -> TestResult:
        """
        Test detect_network_input function.

        From lab_3_1_user_input_detection.md:
        - Query 1: detect_network_input()
        - Should find functions with network input APIs (recv, WSARecv, etc.)
        """
        test_name = "test_detect_network_input"

        try:
            from student_labs.lab3.user_input_detection import (
                InputSourceResult,
                detect_network_input,
            )

            results = detect_network_input(self.driver, self.database, limit=10)

            # Verify return type
            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    input_source_type="network",
                )

            # Verify result structure if we have results
            if results:
                first_result = results[0]
                if not isinstance(first_result, InputSourceResult):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Expected InputSourceResult, got {type(first_result).__name__}",
                        input_source_type="network",
                    )

                # Check required fields
                required_fields = ["binary", "function", "apis", "count"]
                for field_name in required_fields:
                    if not hasattr(first_result, field_name):
                        return TestResult(
                            name=test_name,
                            passed=False,
                            message=f"InputSourceResult missing field: {field_name}",
                            input_source_type="network",
                        )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"detect_network_input returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                input_source_type="network",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                input_source_type="network",
            )

    def test_detect_file_input(self) -> TestResult:
        """
        Test detect_file_input function.

        From lab_3_1_user_input_detection.md:
        - Query 2: detect_file_input()
        - Should find functions with file input APIs (fread, ReadFile, etc.)
        """
        test_name = "test_detect_file_input"

        try:
            from student_labs.lab3.user_input_detection import (
                InputSourceResult,
                detect_file_input,
            )

            results = detect_file_input(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    input_source_type="file",
                )

            # Use duck-typing check instead of isinstance to handle reference implementation
            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "apis", "count"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        input_source_type="file",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"detect_file_input returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                input_source_type="file",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                input_source_type="file",
            )

    def test_detect_stdin_input(self) -> TestResult:
        """
        Test detect_stdin_input function.

        From lab_3_1_user_input_detection.md:
        - Query 3: detect_stdin_input()
        - Should find functions with stdin input APIs (scanf, gets, etc.)
        """
        test_name = "test_detect_stdin_input"

        try:
            from student_labs.lab3.user_input_detection import (
                InputSourceResult,
                detect_stdin_input,
            )

            results = detect_stdin_input(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    input_source_type="stdin",
                )

            # Use duck-typing check instead of isinstance to handle reference implementation
            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "apis", "count"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        input_source_type="stdin",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"detect_stdin_input returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                input_source_type="stdin",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                input_source_type="stdin",
            )

    def test_detect_environment_input(self) -> TestResult:
        """
        Test detect_environment_input function.

        From lab_3_1_user_input_detection.md:
        - Query 4: detect_environment_input()
        - Should find functions with environment input APIs (getenv, etc.)
        """
        test_name = "test_detect_environment_input"

        try:
            from student_labs.lab3.user_input_detection import (
                InputSourceResult,
                detect_environment_input,
            )

            results = detect_environment_input(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    input_source_type="environment",
                )

            # Use duck-typing check instead of isinstance to handle reference implementation
            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "apis", "count"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        input_source_type="environment",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"detect_environment_input returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                input_source_type="environment",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                input_source_type="environment",
            )

    def test_detect_ipc_input(self) -> TestResult:
        """
        Test detect_ipc_input function.

        From lab_3_1_user_input_detection.md:
        - Query 5: detect_ipc_input()
        - Should find functions with IPC input APIs (msgrcv, shmat, etc.)
        """
        test_name = "test_detect_ipc_input"

        try:
            from student_labs.lab3.user_input_detection import (
                InputSourceResult,
                detect_ipc_input,
            )

            results = detect_ipc_input(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    input_source_type="ipc",
                )

            if results and not isinstance(results[0], InputSourceResult):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected InputSourceResult, got {type(results[0]).__name__}",
                    input_source_type="ipc",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"detect_ipc_input returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                input_source_type="ipc",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                input_source_type="ipc",
            )

    def test_detect_cmdline_input(self) -> TestResult:
        """
        Test detect_cmdline_input function.

        From lab_3_1_user_input_detection.md:
        - Query 6: detect_cmdline_input()
        - Should find functions with command-line input APIs (getopt, etc.)
        """
        test_name = "test_detect_cmdline_input"

        try:
            from student_labs.lab3.user_input_detection import (
                InputSourceResult,
                detect_cmdline_input,
            )

            results = detect_cmdline_input(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    input_source_type="cmdline",
                )

            if results and not isinstance(results[0], InputSourceResult):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected InputSourceResult, got {type(results[0]).__name__}",
                    input_source_type="cmdline",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"detect_cmdline_input returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                input_source_type="cmdline",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                input_source_type="cmdline",
            )

    def test_get_all_input_sources(self) -> TestResult:
        """
        Test get_all_input_sources aggregation function.

        From lab_3_1_user_input_detection.md:
        - Should return a dictionary with all 6 input source categories
        """
        test_name = "test_get_all_input_sources"

        try:
            from student_labs.lab3.user_input_detection import get_all_input_sources

            results = get_all_input_sources(self.driver, self.database, limit=5)

            if not isinstance(results, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(results).__name__}",
                )

            expected_keys = ["network", "file", "stdin", "environment", "ipc", "cmdline"]
            missing_keys = [k for k in expected_keys if k not in results]

            if missing_keys:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing expected keys: {missing_keys}",
                    details={"missing_keys": missing_keys, "actual_keys": list(results.keys())},
                )

            total_results = sum(len(v) for v in results.values())

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_all_input_sources returned {total_results} total results across 6 categories",
                details={
                    "categories": list(results.keys()),
                    "counts": {k: len(v) for k, v in results.items()},
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
            )

    def test_get_high_risk_functions(self) -> TestResult:
        """
        Test get_high_risk_functions aggregation function.

        From lab_3_1_user_input_detection.md:
        - Should return functions with multiple input source categories
        """
        test_name = "test_get_high_risk_functions"

        try:
            from student_labs.lab3.user_input_detection import get_high_risk_functions

            results = get_high_risk_functions(self.driver, self.database, min_categories=2, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                )

            # Verify structure if we have results
            if results:
                first_result = results[0]
                if not isinstance(first_result, dict):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Expected dict items, got {type(first_result).__name__}",
                    )

                required_keys = ["binary", "function", "categories", "category_count"]
                missing_keys = [k for k in required_keys if k not in first_result]

                if missing_keys:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result dict missing keys: {missing_keys}",
                        details={"missing_keys": missing_keys},
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_high_risk_functions returned {len(results)} high-risk functions",
                details={"result_count": len(results)},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
            )

    def test_cli_help(self) -> TestResult:
        """
        Test that the CLI --help works.

        From lab_3_1_user_input_detection.md:
        - CLI should be accessible via python -m student_labs.lab3.user_input_detection
        """
        test_name = "test_cli_help"

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.user_input_detection", "--help"],
                capture_output=True,                text=True,                timeout=30,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --help failed with return code {result.returncode}",
                    details={"stderr": result.stderr},
                )

            # Check for expected flags in help output
            expected_flags = ["--all", "--network", "--file", "--stdin", "--env", "--ipc", "--cmdline", "--high-risk"]
            missing_flags = [f for f in expected_flags if f not in result.stdout]

            if missing_flags:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI help missing expected flags: {missing_flags}",
                    details={"missing_flags": missing_flags, "stdout": result.stdout[:500]},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --help works and shows all expected flags",
                details={"flags_found": expected_flags},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --help timed out after 30 seconds",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"CLI test failed: {e}",
            )

    def _print_verbose_details(self, result: TestResult) -> None:
        """
        Print detailed information about a test result in verbose mode.

        Shows additional context like APIs found, result counts, and sample data
        to help students understand what the test discovered.
        """
        indent = "      "  # Extra indentation for details

        # Show details dictionary if present
        if result.details:
            for key, value in result.details.items():
                if key == "result_count":
                    continue  # Already shown in message
                if isinstance(value, list) and len(value) > 5:
                    print(f"{indent}{key}: {value[:5]} ... ({len(value)} total)")
                else:
                    print(f"{indent}{key}: {value}")

        # Show sample results data for detection functions
        if result.results_data and result.input_source_type:
            print(f"{indent}Sample results ({result.input_source_type} input sources):")
            for i, r in enumerate(result.results_data[:3]):  # Show up to 3 samples
                # Handle both InputSourceResult objects and dicts
                if hasattr(r, 'binary'):
                    binary = r.binary
                    function = r.function
                    apis = r.apis if hasattr(r, 'apis') else []
                    address = r.address if hasattr(r, 'address') else None
                else:
                    binary = r.get('binary', 'unknown')
                    function = r.get('function', 'unknown')
                    apis = r.get('apis', [])
                    address = r.get('address')

                api_str = ", ".join(apis[:5]) if apis else "none"
                if len(apis) > 5:
                    api_str += f" ... (+{len(apis) - 5} more)"

                addr_str = f" @ {address}" if address else ""
                print(f"{indent}  [{i+1}] {binary}::{function}{addr_str}")
                print(f"{indent}      APIs: {api_str}")

            if len(result.results_data) > 3:
                print(f"{indent}  ... and {len(result.results_data) - 3} more results")

    def run_all(self) -> List[TestResult]:
        """Run all tests and return results."""
        self.results = []

        # Setup
        try:
            self.setup()
        except Exception as e:
            self.results.append(TestResult(
                name="setup",
                passed=False,
                message=f"Setup failed: {e}",
            ))
            return self.results

        # Run tests
        tests = [
            self.test_module_importable,
            self.test_binaries_ingested,
            self.test_detect_network_input,
            self.test_detect_file_input,
            self.test_detect_stdin_input,
            self.test_detect_environment_input,
            self.test_detect_ipc_input,
            self.test_detect_cmdline_input,
            self.test_get_all_input_sources,
            self.test_get_high_risk_functions,
            self.test_cli_help,
        ]

        for test in tests:
            try:
                result = test()
                self.results.append(result)
                if self.verbose:
                    status = "✓" if result.passed else "✗"
                    print(f"  {status} {result.name}: {result.message}")
                    # Show detailed results for verbose mode
                    self._print_verbose_details(result)
            except Exception as e:
                self.results.append(TestResult(
                    name=test.__name__,
                    passed=False,
                    message=f"Test raised exception: {e}",
                ))

        # Teardown
        self.teardown()

        return self.results

    def print_summary(self) -> None:
        """Print test summary."""
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        print("\n" + "=" * 60)
        print("  Lab 3.1 Test Summary - User-Controlled Input Detection")
        print("=" * 60)
        print(f"  Total Tests: {total}")
        print(f"  Passed:      {passed}")
        print(f"  Failed:      {failed}")
        print("=" * 60)

        if failed > 0:
            print("\nFailed Tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  ✗ {result.name}: {result.message}")


def main() -> int:
    """Main entry point for the test suite."""
    parser = argparse.ArgumentParser(
        description="Lab 3.1 Test: User-Controlled Input Detection Functions",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("\n" + "=" * 60)
    print("  Lab 3.1 Test: User-Controlled Input Detection Functions")
    print("=" * 60)
    print("  Reference: docs/labs/lab3/lab_3_1_user_input_detection.md")
    print("  Student file: student_labs/lab3/user_input_detection.py")
    print("=" * 60 + "\n")

    # Run tests
    test_suite = Lab5_1_Test(verbose=args.verbose)
    results = test_suite.run_all()
    test_suite.print_summary()

    # Return exit code
    failed = sum(1 for r in results if not r.passed)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
