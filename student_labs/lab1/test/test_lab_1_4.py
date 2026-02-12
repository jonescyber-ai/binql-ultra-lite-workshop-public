"""
Lab 1.4 Test: Vulnerability Analysis Script.

This test validates Lab 1.4 from the lab_1_0_overview.md:
- Neo4j connectivity using get_neo4j_credentials()
- get_binary_info() returns expected fields
- get_buffer_overflow_imports() returns a list of import names
- get_format_string_imports() returns a list of import names
- get_memory_imports() returns import names with call counts
- get_call_depth_to_sinks() returns call path information
- compute_vuln_severity() returns valid severity levels
- CLI runs without error and produces output

Reference: docs/labs/lab1/lab_1_0_overview.md (Lab 1.4 section)

Usage:
    source venv/bin/activate
    python -m student_labs.lab1.test.test_lab_1_4

    # Run with verbose output
    python -m student_labs.lab1.test.test_lab_1_4 -v

    # Run with reference implementation (instructor validation)
    USE_REFERENCE=1 python -m student_labs.lab1.test.test_lab_1_4
"""

import argparse
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

# Load default credentials from lab_common
_DEFAULT_CREDENTIALS = get_neo4j_credentials()

PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Known SHA256 for Bison test binary
BISON_SHA256 = "9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd"


@dataclass
class TestResult:
    """Result of a single test case."""

    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


class Lab1_7_Test:
    """
    Test runner for Lab 1.4: Vulnerability Analysis Script.

    Tests covered:
    1. Neo4j connectivity using get_neo4j_credentials()
    2. get_binary_info() returns expected fields
    3. get_buffer_overflow_imports() returns a list
    4. get_format_string_imports() returns a list
    5. get_memory_imports() returns list of dicts with counts
    6. get_call_depth_to_sinks() returns call path info
    7. compute_vuln_severity() returns valid severity levels
    8. CLI runs without error
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        neo4j_database: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the test runner with Neo4j credentials."""
        self.neo4j_uri = neo4j_uri or _DEFAULT_CREDENTIALS["uri"]
        self.neo4j_user = neo4j_user or _DEFAULT_CREDENTIALS["user"]
        self.neo4j_password = neo4j_password or _DEFAULT_CREDENTIALS["password"]
        self.neo4j_database = neo4j_database or _DEFAULT_CREDENTIALS["database"]
        self.verbose = verbose
        self._driver = None
        self.results: List[TestResult] = []

    def _get_driver(self):
        """Get or create Neo4j driver."""
        if self._driver is None:
            self._driver = GraphDatabase.driver(
                self.neo4j_uri, auth=(self.neo4j_user, self.neo4j_password)
            )
        return self._driver

    def _close_driver(self) -> None:
        """Close Neo4j driver if open."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def test_neo4j_connectivity(self) -> TestResult:
        """
        Test 1.4.1: Verify Neo4j connectivity using get_neo4j_credentials().
        """
        test_name = "Lab 1.4.1: Neo4j connectivity"
        logger.info(f"Running {test_name}...")

        try:
            creds = get_neo4j_credentials()
            required_keys = {"uri", "user", "password", "database"}
            if not required_keys.issubset(creds.keys()):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_neo4j_credentials() missing keys: {required_keys - set(creds.keys())}",
                )

            driver = self._get_driver()
            driver.verify_connectivity()

            return TestResult(
                name=test_name,
                passed=True,
                message="Neo4j connectivity verified",
                details={"uri": creds["uri"], "database": creds["database"]},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Neo4j connectivity failed: {e}",
            )

    def test_get_binary_info(self) -> TestResult:
        """
        Test 1.4.2: Verify get_binary_info() returns expected fields.

        From lab_1_0_overview.md:
        - Query should return: name, architecture, function_count
        """
        test_name = "Lab 1.4.2: get_binary_info()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.vuln_analysis import get_binary_info

            driver = self._get_driver()
            result = get_binary_info(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_binary_info() returned None for SHA256 {BISON_SHA256[:16]}...",
                )

            expected_fields = {"name", "architecture", "function_count"}
            missing_fields = expected_fields - set(result.keys())
            if missing_fields:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_binary_info() missing fields: {missing_fields}",
                    details={"returned_keys": list(result.keys())},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="get_binary_info() returned expected fields",
                details={
                    "name": result.get("name"),
                    "architecture": result.get("architecture"),
                    "function_count": result.get("function_count"),
                },
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_binary_info: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_binary_info() failed: {e}",
            )

    def test_get_buffer_overflow_imports(self) -> TestResult:
        """
        Test 1.4.3: Verify get_buffer_overflow_imports() returns a list.

        From lab_1_0_overview.md:
        - Query for imports that may cause buffer overflows
        - Returns list of import names
        """
        test_name = "Lab 1.4.3: get_buffer_overflow_imports()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.vuln_analysis import get_buffer_overflow_imports

            driver = self._get_driver()
            result = get_buffer_overflow_imports(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_buffer_overflow_imports() returned None instead of a list",
                )

            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_buffer_overflow_imports() returned {type(result).__name__} instead of list",
                )

            non_strings = [item for item in result if not isinstance(item, str)]
            if non_strings:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_buffer_overflow_imports() returned non-string items: {non_strings[:3]}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_buffer_overflow_imports() returned {len(result)} imports",
                details={"import_count": len(result), "sample": result[:5]},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_buffer_overflow_imports: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_buffer_overflow_imports() failed: {e}",
            )

    def test_get_format_string_imports(self) -> TestResult:
        """
        Test 1.4.4: Verify get_format_string_imports() returns a list.

        From lab_1_0_overview.md:
        - Query for imports that may be format string sinks
        - Returns list of import names
        """
        test_name = "Lab 1.4.4: get_format_string_imports()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.vuln_analysis import get_format_string_imports

            driver = self._get_driver()
            result = get_format_string_imports(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_format_string_imports() returned None instead of a list",
                )

            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_format_string_imports() returned {type(result).__name__} instead of list",
                )

            non_strings = [item for item in result if not isinstance(item, str)]
            if non_strings:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_format_string_imports() returned non-string items",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_format_string_imports() returned {len(result)} imports",
                details={"import_count": len(result), "sample": result[:5]},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_format_string_imports: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_format_string_imports() failed: {e}",
            )

    def test_get_memory_imports(self) -> TestResult:
        """
        Test 1.4.5: Verify get_memory_imports() returns list of dicts with counts.

        From lab_1_0_overview.md:
        - Query memory management imports with call counts
        - Returns list of dicts with 'name' and 'count' keys
        """
        test_name = "Lab 1.4.5: get_memory_imports()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.vuln_analysis import get_memory_imports

            driver = self._get_driver()
            result = get_memory_imports(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_memory_imports() returned None instead of a list",
                )

            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_memory_imports() returned {type(result).__name__} instead of list",
                )

            # Check that items are dicts with expected keys
            for item in result:
                if not isinstance(item, dict):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"get_memory_imports() items should be dicts, got {type(item).__name__}",
                    )
                if "name" not in item or "count" not in item:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"get_memory_imports() items missing 'name' or 'count' keys",
                        details={"item_keys": list(item.keys())},
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_memory_imports() returned {len(result)} memory functions",
                details={"count": len(result), "sample": result[:3]},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_memory_imports: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_memory_imports() failed: {e}",
            )

    def test_get_call_depth_to_sinks(self) -> TestResult:
        """
        Test 1.4.6: Verify get_call_depth_to_sinks() returns call path info.

        From lab_1_0_overview.md:
        - Find call paths from entry functions to dangerous imports
        - Returns list of dicts with 'entry_func', 'call_path', 'sink_import', 'depth' keys
        """
        test_name = "Lab 1.4.6: get_call_depth_to_sinks()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.vuln_analysis import get_call_depth_to_sinks

            driver = self._get_driver()
            result = get_call_depth_to_sinks(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_call_depth_to_sinks() returned None instead of a list",
                )

            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_call_depth_to_sinks() returned {type(result).__name__} instead of list",
                )

            # Check structure of items (if any exist)
            for item in result[:3]:  # Check first few
                if not isinstance(item, dict):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"get_call_depth_to_sinks() items should be dicts",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_call_depth_to_sinks() returned {len(result)} paths",
                details={"path_count": len(result)},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_call_depth_to_sinks: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_call_depth_to_sinks() failed: {e}",
            )

    def test_compute_vuln_severity(self) -> TestResult:
        """
        Test 1.4.7: Verify compute_vuln_severity() returns valid severity levels.

        From lab_1_0_overview.md:
        - Compute vulnerability severity based on findings
        - Returns: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        """
        test_name = "Lab 1.4.7: compute_vuln_severity()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.vuln_analysis import compute_vuln_severity

            valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

            # Test case 1: Empty inputs -> LOW
            result1 = compute_vuln_severity([], [], [])
            if result1 not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"compute_vuln_severity([],[],[]) returned invalid level: {result1}",
                )

            # Test case 2: Some buffer overflow imports
            result2 = compute_vuln_severity(["strcpy", "gets"], [], [])
            if result2 not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"compute_vuln_severity with buffer imports returned invalid level: {result2}",
                )

            # Test case 3: Multiple vulnerabilities + short paths
            result3 = compute_vuln_severity(
                ["strcpy", "gets", "sprintf"],
                ["printf", "fprintf"],
                [{"depth": 2}, {"depth": 1}]
            )
            if result3 not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"compute_vuln_severity with multiple vulns returned invalid level: {result3}",
                )

            # Verify severity increases with more indicators
            if result1 == "CRITICAL" and result3 == "LOW":
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Severity levels don't increase with more indicators",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="compute_vuln_severity() returns valid severity levels",
                details={
                    "empty_inputs": result1,
                    "with_buffer": result2,
                    "with_multiple": result3,
                },
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import compute_vuln_severity: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"compute_vuln_severity() failed: {e}",
            )

    def test_cli_runs(self) -> TestResult:
        """
        Test 1.4.8: Verify CLI runs without error.

        From lab_1_0_overview.md:
        - python -m student_labs.lab1.vuln_analysis --sha256 <sha256>
        """
        test_name = "Lab 1.4.8: CLI execution"
        logger.info(f"Running {test_name}...")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab1.vuln_analysis", "--help"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --help failed with return code {result.returncode}",
                    details={"stderr": result.stderr[:500]},
                )

            if "sha256" not in result.stdout.lower():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="CLI --help output doesn't mention sha256 argument",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --help runs successfully",
                details={"help_length": len(result.stdout)},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI timed out after 30 seconds",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"CLI execution failed: {e}",
            )

    def run_all(self) -> List[TestResult]:
        """Run all Lab 1.4 tests."""
        logger.info("=" * 60)
        logger.info("LAB 1.7 TESTS: Vulnerability Analysis Script")
        logger.info("=" * 60)

        self.results = []

        # Test 1.4.1: Neo4j connectivity
        self.results.append(self.test_neo4j_connectivity())

        # Test 1.4.2: get_binary_info()
        self.results.append(self.test_get_binary_info())

        # Test 1.4.3: get_buffer_overflow_imports()
        self.results.append(self.test_get_buffer_overflow_imports())

        # Test 1.4.4: get_format_string_imports()
        self.results.append(self.test_get_format_string_imports())

        # Test 1.4.5: get_memory_imports()
        self.results.append(self.test_get_memory_imports())

        # Test 1.4.6: get_call_depth_to_sinks()
        self.results.append(self.test_get_call_depth_to_sinks())

        # Test 1.4.7: compute_vuln_severity()
        self.results.append(self.test_compute_vuln_severity())

        # Test 1.4.8: CLI runs
        self.results.append(self.test_cli_runs())

        return self.results

    def print_summary(self) -> None:
        """Print test summary."""
        logger.info("")
        logger.info("=" * 60)
        logger.info("LAB 1.7 TEST SUMMARY")
        logger.info("=" * 60)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)

        for result in self.results:
            status = "✓ PASS" if result.passed else "✗ FAIL"
            logger.info(f"  {status}: {result.name}")
            if not result.passed:
                logger.info(f"         {result.message}")

        logger.info("-" * 60)
        logger.info(f"Total: {len(self.results)} | Passed: {passed} | Failed: {failed}")
        logger.info("=" * 60)

    def cleanup(self) -> None:
        """Clean up resources."""
        self._close_driver()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Lab 1.4 Test: Vulnerability Analysis Script"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--uri",
        default=_DEFAULT_CREDENTIALS["uri"],
        help=f"Neo4j URI (default: {_DEFAULT_CREDENTIALS['uri']})",
    )
    parser.add_argument(
        "--user",
        default=_DEFAULT_CREDENTIALS["user"],
        help=f"Neo4j user (default: {_DEFAULT_CREDENTIALS['user']})",
    )
    parser.add_argument(
        "--password",
        default=_DEFAULT_CREDENTIALS["password"],
        help="Neo4j password",
    )
    parser.add_argument(
        "--database",
        default=_DEFAULT_CREDENTIALS["database"],
        help=f"Neo4j database (default: {_DEFAULT_CREDENTIALS['database']})",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )

    # Run tests
    test_runner = Lab1_7_Test(
        neo4j_uri=args.uri,
        neo4j_user=args.user,
        neo4j_password=args.password,
        neo4j_database=args.database,
        verbose=args.verbose,
    )

    try:
        test_runner.run_all()
        test_runner.print_summary()

        # Return exit code based on test results
        failed = sum(1 for r in test_runner.results if not r.passed)
        return 1 if failed > 0 else 0
    finally:
        test_runner.cleanup()


if __name__ == "__main__":
    sys.exit(main())
