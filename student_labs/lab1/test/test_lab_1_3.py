"""
Lab 1.3 Test: Malware Triage Script.

This test validates Lab 1.3 from the lab_1_0_overview.md:
- Neo4j connectivity using get_neo4j_credentials()
- get_binary_info() returns expected fields (name, classification, etc.)
- get_behavioral_imports() returns a list of import names
- get_suspicious_strings() returns a list of string values
- get_import_count() returns an integer
- compute_malware_risk() returns valid risk levels
- CLI runs without error and produces output

Reference: docs/labs/lab1/lab_1_0_overview.md (Lab 1.3 section)

Usage:
    source venv/bin/activate
    python -m student_labs.lab1.test.test_lab_1_3

    # Run with verbose output
    python -m student_labs.lab1.test.test_lab_1_3 -v

    # Run with reference implementation (instructor validation)
    USE_REFERENCE=1 python -m student_labs.lab1.test.test_lab_1_3
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


class Lab1_6_Test:
    """
    Test runner for Lab 1.3: Malware Triage Script.

    Tests covered:
    1. Neo4j connectivity using get_neo4j_credentials()
    2. get_binary_info() returns expected fields
    3. get_behavioral_imports() returns a list
    4. get_suspicious_strings() returns a list
    5. get_import_count() returns an integer
    6. compute_malware_risk() returns valid risk levels
    7. CLI runs without error
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
        Test 1.3.1: Verify Neo4j connectivity using get_neo4j_credentials().

        From lab_1_0_overview.md:
        - Use get_neo4j_credentials() from lab_common to get connection settings.
        - Create a Neo4j driver instance.
        """
        test_name = "Lab 1.3.1: Neo4j connectivity"
        logger.info(f"Running {test_name}...")

        try:
            # Test that get_neo4j_credentials returns expected keys
            creds = get_neo4j_credentials()
            required_keys = {"uri", "user", "password", "database"}
            if not required_keys.issubset(creds.keys()):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_neo4j_credentials() missing keys: {required_keys - set(creds.keys())}",
                )

            # Test connection
            driver = self._get_driver()
            driver.verify_connectivity()

            return TestResult(
                name=test_name,
                passed=True,
                message="Neo4j connectivity verified using get_neo4j_credentials()",
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
        Test 1.3.2: Verify get_binary_info() returns expected fields.

        From lab_1_0_overview.md:
        - Query should return: name, architecture, classification, tags, malware_family, function_count
        """
        test_name = "Lab 1.3.2: get_binary_info()"
        logger.info(f"Running {test_name}...")

        try:
            # Import the function from student_labs.lab1.malware_triage
            from student_labs.lab1.malware_triage import get_binary_info

            driver = self._get_driver()
            result = get_binary_info(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_binary_info() returned None for SHA256 {BISON_SHA256[:16]}...",
                )

            # Check for expected fields
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
                message=f"get_binary_info() returned expected fields",
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

    def test_get_behavioral_imports(self) -> TestResult:
        """
        Test 1.3.3: Verify get_behavioral_imports() returns a list of import names.

        From lab_1_0_overview.md:
        - Query for imports that indicate potential malicious behavior
        - Returns list of import names
        """
        test_name = "Lab 1.3.3: get_behavioral_imports()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.malware_triage import get_behavioral_imports

            driver = self._get_driver()
            result = get_behavioral_imports(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_behavioral_imports() returned None instead of a list",
                )

            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_behavioral_imports() returned {type(result).__name__} instead of list",
                )

            # All items should be strings
            non_strings = [item for item in result if not isinstance(item, str)]
            if non_strings:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_behavioral_imports() returned non-string items: {non_strings[:3]}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_behavioral_imports() returned {len(result)} imports",
                details={"import_count": len(result), "sample": result[:5]},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_behavioral_imports: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_behavioral_imports() failed: {e}",
            )

    def test_get_suspicious_strings(self) -> TestResult:
        """
        Test 1.3.4: Verify get_suspicious_strings() returns a list of string values.

        From lab_1_0_overview.md:
        - Query strings that may indicate malicious behavior
        - Returns list of string values (limited to 20)
        """
        test_name = "Lab 1.3.4: get_suspicious_strings()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.malware_triage import get_suspicious_strings

            driver = self._get_driver()
            result = get_suspicious_strings(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_suspicious_strings() returned None instead of a list",
                )

            if not isinstance(result, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_suspicious_strings() returned {type(result).__name__} instead of list",
                )

            # All items should be strings
            non_strings = [item for item in result if not isinstance(item, str)]
            if non_strings:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_suspicious_strings() returned non-string items",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_suspicious_strings() returned {len(result)} strings",
                details={"string_count": len(result), "sample": result[:3]},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_suspicious_strings: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_suspicious_strings() failed: {e}",
            )

    def test_get_import_count(self) -> TestResult:
        """
        Test 1.3.5: Verify get_import_count() returns an integer.

        From lab_1_0_overview.md:
        - Get total count of imports for the binary
        - Returns integer
        """
        test_name = "Lab 1.3.5: get_import_count()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.malware_triage import get_import_count

            driver = self._get_driver()
            result = get_import_count(driver, self.neo4j_database, BISON_SHA256)

            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="get_import_count() returned None instead of an integer",
                )

            if not isinstance(result, int):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_import_count() returned {type(result).__name__} instead of int",
                )

            if result < 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"get_import_count() returned negative value: {result}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_import_count() returned {result}",
                details={"import_count": result},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import get_import_count: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"get_import_count() failed: {e}",
            )

    def test_compute_malware_risk(self) -> TestResult:
        """
        Test 1.3.6: Verify compute_malware_risk() returns valid risk levels.

        From lab_1_0_overview.md:
        - Compute malware risk level based on behavioral indicators
        - Returns: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        """
        test_name = "Lab 1.3.6: compute_malware_risk()"
        logger.info(f"Running {test_name}...")

        try:
            from student_labs.lab1.malware_triage import compute_malware_risk

            valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

            # Test case 1: Empty inputs -> LOW
            result1 = compute_malware_risk([], [], None)
            if result1 not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"compute_malware_risk([],[],None) returned invalid level: {result1}",
                )

            # Test case 2: Some imports -> should be MEDIUM or higher
            result2 = compute_malware_risk(["system", "execve"], [], None)
            if result2 not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"compute_malware_risk with imports returned invalid level: {result2}",
                )

            # Test case 3: Known malware family -> should be HIGH or CRITICAL
            result3 = compute_malware_risk(["system"], ["http://evil.com"], "zeus")
            if result3 not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"compute_malware_risk with family returned invalid level: {result3}",
                )

            # Verify risk increases with more indicators
            if result1 == "CRITICAL" and result3 == "LOW":
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Risk levels don't increase with more indicators",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="compute_malware_risk() returns valid risk levels",
                details={
                    "empty_inputs": result1,
                    "with_imports": result2,
                    "with_family": result3,
                },
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Could not import compute_malware_risk: {e}. Students need to implement this function.",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"compute_malware_risk() failed: {e}",
            )

    def test_cli_runs(self) -> TestResult:
        """
        Test 1.3.7: Verify CLI runs without error.

        From lab_1_0_overview.md:
        - python -m student_labs.lab1.malware_triage --sha256 <sha256>
        """
        test_name = "Lab 1.3.7: CLI execution"
        logger.info(f"Running {test_name}...")

        try:
            # Test --help works
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab1.malware_triage", "--help"],
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
        """Run all Lab 1.3 tests."""
        logger.info("=" * 60)
        logger.info("LAB 1.6 TESTS: Malware Triage Script")
        logger.info("=" * 60)

        self.results = []

        # Test 1.3.1: Neo4j connectivity
        self.results.append(self.test_neo4j_connectivity())

        # Test 1.3.2: get_binary_info()
        self.results.append(self.test_get_binary_info())

        # Test 1.3.3: get_behavioral_imports()
        self.results.append(self.test_get_behavioral_imports())

        # Test 1.3.4: get_suspicious_strings()
        self.results.append(self.test_get_suspicious_strings())

        # Test 1.3.5: get_import_count()
        self.results.append(self.test_get_import_count())

        # Test 1.3.6: compute_malware_risk()
        self.results.append(self.test_compute_malware_risk())

        # Test 1.3.7: CLI runs
        self.results.append(self.test_cli_runs())

        return self.results

    def print_summary(self) -> None:
        """Print test summary."""
        logger.info("")
        logger.info("=" * 60)
        logger.info("LAB 1.6 TEST SUMMARY")
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
        description="Lab 1.3 Test: Malware Triage Script"
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
    test_runner = Lab1_6_Test(
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
