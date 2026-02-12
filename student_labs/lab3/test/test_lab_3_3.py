"""
Lab 3.3 Test: Path Risk Analysis Functions.

This test validates Lab 3.3 from lab_3_3_complexity_analysis.md:
- The complexity_analysis module is importable
- The Lab 3 dataset is ingested (binaries from dataset/lab3/)
- All 5 path analysis functions execute successfully
- Functions return properly structured dataclass objects
- Risk scoring produces meaningful differentiation

Reference: docs/labs/lab3/lab_3_3_complexity_analysis.md

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.test.test_lab_3_3

    # Run with verbose output
    python -m student_labs.lab3.test.test_lab_3_3 -v
"""

import argparse
import logging
import subprocess
import sys
from dataclasses import dataclass
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

# Test binary SHA256 (bison binary from dataset/lab3/ - has source-to-sink paths)
TEST_BINARY_SHA256 = "9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd"


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    results_data: Optional[List[Any]] = None


class Lab5_3_Test:
    """
    Test suite for Lab 3.3 - Path Risk Analysis Functions.

    This test suite validates the student-implemented functions in
    student_labs/lab3/complexity_analysis.py:
    1. The module is importable
    2. Lab 3 binaries are ingested in Neo4j
    3. All 5 path analysis functions execute successfully
    4. Functions return properly structured dataclass objects
    5. Risk scoring produces meaningful differentiation
    6. CLI commands work correctly
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
        Test that the complexity_analysis module is importable.

        From lab_3_3_complexity_analysis.md:
        - Student file: student_labs/lab3/complexity_analysis.py
        """
        test_name = "test_module_importable"

        try:
            # Import the module
            from student_labs.lab3 import complexity_analysis

            # Check for required classes
            required_classes = [
                "PathComplexityMetrics",
                "PathTraversalMetrics",
                "PathRiskAnalysis",
            ]

            missing_classes = []
            for cls_name in required_classes:
                if not hasattr(complexity_analysis, cls_name):
                    missing_classes.append(cls_name)

            if missing_classes:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing classes: {missing_classes}",
                )

            # Check for required functions
            required_functions = [
                "analyze_path_complexity",
                "analyze_path_traversal_likelihood",
                "calculate_path_risk_score",
                "get_paths_for_binary",
                "analyze_all_paths_for_binary",
            ]

            missing_functions = []
            for func_name in required_functions:
                if not hasattr(complexity_analysis, func_name):
                    missing_functions.append(func_name)

            if missing_functions:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing functions: {missing_functions}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="Module importable with all required classes and functions",
                details={
                    "classes": required_classes,
                    "functions": required_functions,
                },
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

    def test_binaries_ingested(self) -> TestResult:
        """
        Test that Lab 3 binaries are ingested in Neo4j.

        From lab_3_0_overview.md:
        - Binaries from dataset/lab3/ should be ingested
        """
        test_name = "test_binaries_ingested"

        try:
            query = "MATCH (b:Binary) RETURN count(b) AS count"
            with self.driver.session(database=self.database) as session:
                result = session.run(query)
                record = result.single()
                count = record["count"] if record else 0

            if count == 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="No binaries found in Neo4j. Run Lab 3 setup first.",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Found {count} binaries in Neo4j",
                details={"binary_count": count},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error checking binaries: {e}",
            )

    def test_analyze_path_complexity(self) -> TestResult:
        """
        Test the analyze_path_complexity function.

        From lab_3_3_complexity_analysis.md:
        - Function should calculate complexity metrics for a Lab 3.2 path
        - Returns PathComplexityMetrics dataclass
        """
        test_name = "test_analyze_path_complexity"

        try:
            from student_labs.lab3.complexity_analysis import (
                analyze_path_complexity,
                PathComplexityMetrics,
            )
            from student_labs.lab3.source_to_sink_analysis import SourceToSinkPath

            # Create a mock path for testing
            mock_path = SourceToSinkPath(
                binary=TEST_BINARY_SHA256,
                function="main",
                address="0x1000",
                source_apis=["getenv"],
                sink_apis=["memcpy"],
                vulnerability_type="buffer_overflow",
            )

            # Call the function
            result = analyze_path_complexity(self.driver, self.database, mock_path)

            # Verify return type (use class name to handle reference implementation)
            if type(result).__name__ != "PathComplexityMetrics":
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected PathComplexityMetrics, got {type(result).__name__}",
                )

            # Verify fields exist
            required_fields = [
                "cyclomatic_complexity",
                "branch_count",
                "basic_block_count",
            ]
            for field_name in required_fields:
                if not hasattr(result, field_name):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Missing field: {field_name}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message="analyze_path_complexity returns valid PathComplexityMetrics",
                details={
                    "cyclomatic_complexity": result.cyclomatic_complexity,
                    "branch_count": result.branch_count,
                    "basic_block_count": result.basic_block_count,
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_analyze_path_traversal_likelihood(self) -> TestResult:
        """
        Test the analyze_path_traversal_likelihood function.

        From lab_3_3_complexity_analysis.md:
        - Function should measure traversal likelihood for a Lab 3.2 path
        - Returns PathTraversalMetrics dataclass
        """
        test_name = "test_analyze_path_traversal_likelihood"

        try:
            from student_labs.lab3.complexity_analysis import (
                analyze_path_traversal_likelihood,
                PathTraversalMetrics,
            )
            from student_labs.lab3.source_to_sink_analysis import SourceToSinkPath

            # Create a mock path for testing
            mock_path = SourceToSinkPath(
                binary=TEST_BINARY_SHA256,
                function="main",
                address="0x1000",
                source_apis=["getenv"],
                sink_apis=["memcpy"],
                vulnerability_type="buffer_overflow",
            )

            # Call the function
            result = analyze_path_traversal_likelihood(self.driver, self.database, mock_path)

            # Verify return type (use class name to handle reference implementation)
            if type(result).__name__ != "PathTraversalMetrics":
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected PathTraversalMetrics, got {type(result).__name__}",
                )

            # Verify fields exist
            required_fields = [
                "entry_point_connectivity",
                "caller_count",
                "dark_code_ratio",
                "is_error_handler",
            ]
            for field_name in required_fields:
                if not hasattr(result, field_name):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Missing field: {field_name}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message="analyze_path_traversal_likelihood returns valid PathTraversalMetrics",
                details={
                    "entry_point_connectivity": result.entry_point_connectivity,
                    "caller_count": result.caller_count,
                    "dark_code_ratio": result.dark_code_ratio,
                    "is_error_handler": result.is_error_handler,
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_calculate_path_risk_score(self) -> TestResult:
        """
        Test the calculate_path_risk_score function.

        From lab_3_3_complexity_analysis.md:
        - Function should combine complexity + traversal + severity into risk score
        - Returns tuple of (score, risk_level)
        - Score should be 0-100
        - Risk level should be "critical", "high", "medium", or "low"
        """
        test_name = "test_calculate_path_risk_score"

        try:
            from student_labs.lab3.complexity_analysis import (
                calculate_path_risk_score,
                PathComplexityMetrics,
                PathTraversalMetrics,
            )

            # Create test metrics
            complexity = PathComplexityMetrics(
                cyclomatic_complexity=15,
                branch_count=10,
                basic_block_count=20,
            )
            traversal = PathTraversalMetrics(
                entry_point_connectivity=2,
                caller_count=3,
                dark_code_ratio=0.2,
                is_error_handler=False,
            )

            # Call the function
            score, risk_level = calculate_path_risk_score(
                complexity, traversal, "buffer_overflow"
            )

            # Verify score is in range
            if not (0 <= score <= 100):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Score {score} is not in range 0-100",
                )

            # Verify risk level is valid
            valid_levels = ["critical", "high", "medium", "low"]
            if risk_level not in valid_levels:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Invalid risk level: {risk_level}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"calculate_path_risk_score returns valid score ({score:.1f}) and level ({risk_level})",
                details={
                    "score": score,
                    "risk_level": risk_level,
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_get_paths_for_binary(self) -> TestResult:
        """
        Test the get_paths_for_binary function.

        From lab_3_3_complexity_analysis.md:
        - Function should retrieve Lab 3.2 paths for a specific binary
        - Returns list of SourceToSinkPath objects
        """
        test_name = "test_get_paths_for_binary"

        try:
            from student_labs.lab3.complexity_analysis import get_paths_for_binary
            from student_labs.lab3.source_to_sink_analysis import SourceToSinkPath

            # Call the function
            paths = get_paths_for_binary(self.driver, self.database, TEST_BINARY_SHA256)

            # Verify return type
            if not isinstance(paths, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(paths).__name__}",
                )

            # If paths found, verify they are SourceToSinkPath objects
            # Use class name to handle reference implementation
            if paths:
                for path in paths[:3]:  # Check first 3
                    if type(path).__name__ != "SourceToSinkPath":
                        return TestResult(
                            name=test_name,
                            passed=False,
                            message=f"Expected SourceToSinkPath, got {type(path).__name__}",
                        )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_paths_for_binary returns {len(paths)} paths",
                details={"path_count": len(paths)},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_analyze_all_paths_for_binary(self) -> TestResult:
        """
        Test the analyze_all_paths_for_binary function.

        From lab_3_3_complexity_analysis.md:
        - Function should analyze all Lab 3.2 paths for a binary
        - Returns list of PathRiskAnalysis objects sorted by risk score
        """
        test_name = "test_analyze_all_paths_for_binary"

        try:
            from student_labs.lab3.complexity_analysis import (
                analyze_all_paths_for_binary,
                PathRiskAnalysis,
            )

            # Call the function
            analyses = analyze_all_paths_for_binary(self.driver, self.database, TEST_BINARY_SHA256)

            # Verify return type
            if not isinstance(analyses, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(analyses).__name__}",
                )

            # If analyses found, verify they are PathRiskAnalysis objects
            # Use class name to handle reference implementation
            if analyses:
                for analysis in analyses[:3]:  # Check first 3
                    if type(analysis).__name__ != "PathRiskAnalysis":
                        return TestResult(
                            name=test_name,
                            passed=False,
                            message=f"Expected PathRiskAnalysis, got {type(analysis).__name__}",
                        )

                # Verify sorted by risk score (descending)
                scores = [a.combined_risk_score for a in analyses]
                if scores != sorted(scores, reverse=True):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message="Results not sorted by risk score (descending)",
                    )

                # Verify priority ranks are set
                for i, analysis in enumerate(analyses):
                    if analysis.priority_rank != i + 1:
                        return TestResult(
                            name=test_name,
                            passed=False,
                            message=f"Priority rank mismatch at index {i}",
                        )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"analyze_all_paths_for_binary returns {len(analyses)} ranked analyses",
                details={"analysis_count": len(analyses)},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_cli_help(self) -> TestResult:
        """
        Test that the CLI --help command works.

        From lab_3_3_complexity_analysis.md:
        - CLI should provide help output
        """
        test_name = "test_cli_help"

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "student_labs.lab3.complexity_analysis",
                    "--help",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
                cwd=PROJECT_ROOT,
            )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --help failed with return code {result.returncode}",
                    details={"stderr": result.stderr},
                )

            # Check for expected content in help output
            expected_terms = ["--sha256", "--all", "--min-risk", "--verbose"]
            missing_terms = [term for term in expected_terms if term not in result.stdout]

            if missing_terms:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Help output missing terms: {missing_terms}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --help works correctly",
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --help timed out",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_cli_sha256(self) -> TestResult:
        """
        Test the CLI --sha256 command.

        From lab_3_3_complexity_analysis.md:
        - CLI should analyze paths for a specific binary
        """
        test_name = "test_cli_sha256"

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "student_labs.lab3.complexity_analysis",
                    "--sha256",
                    TEST_BINARY_SHA256,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="replace",
                cwd=PROJECT_ROOT,
            )

            # Check for expected output patterns
            # The CLI should output analysis results or "No paths found"
            output = result.stdout + result.stderr

            if result.returncode != 0:
                # Check if it's a known acceptable error
                if "No paths found" in output or "0 paths" in output.lower():
                    return TestResult(
                        name=test_name,
                        passed=True,
                        message="CLI --sha256 works (no paths found for this binary)",
                    )
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --sha256 failed with return code {result.returncode}",
                    details={"stderr": result.stderr, "stdout": result.stdout},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --sha256 works correctly",
                details={"output_length": len(result.stdout)},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --sha256 timed out",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_risk_score_differentiation(self) -> TestResult:
        """
        Test that risk scoring produces meaningful differentiation.

        From lab_3_3_complexity_analysis.md:
        - Different complexity/traversal metrics should produce different scores
        """
        test_name = "test_risk_score_differentiation"

        try:
            from student_labs.lab3.complexity_analysis import (
                calculate_path_risk_score,
                PathComplexityMetrics,
                PathTraversalMetrics,
            )

            # Test case 1: High complexity, high traversal
            high_complexity = PathComplexityMetrics(
                cyclomatic_complexity=25,
                branch_count=20,
                basic_block_count=30,
                nesting_depth=4,
            )
            high_traversal = PathTraversalMetrics(
                entry_point_connectivity=3,
                caller_count=5,
                dark_code_ratio=0.1,
                is_error_handler=False,
            )
            score_high, level_high = calculate_path_risk_score(
                high_complexity, high_traversal, "command_injection"
            )

            # Test case 2: Low complexity, low traversal
            low_complexity = PathComplexityMetrics(
                cyclomatic_complexity=2,
                branch_count=1,
                basic_block_count=3,
                nesting_depth=0,
            )
            low_traversal = PathTraversalMetrics(
                entry_point_connectivity=0,
                caller_count=0,
                dark_code_ratio=0.8,
                is_error_handler=True,
            )
            score_low, level_low = calculate_path_risk_score(
                low_complexity, low_traversal, "path_traversal"
            )

            # Verify differentiation
            if score_high <= score_low:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"High risk ({score_high}) should be > low risk ({score_low})",
                )

            # Verify meaningful difference (at least 10 points)
            if score_high - score_low < 10:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Insufficient differentiation: {score_high} vs {score_low}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Risk scoring differentiates: high={score_high:.1f} ({level_high}), low={score_low:.1f} ({level_low})",
                details={
                    "high_score": score_high,
                    "high_level": level_high,
                    "low_score": score_low,
                    "low_level": level_low,
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def run_all_tests(self) -> None:
        """Run all tests in the suite."""
        self.setup()

        try:
            # Core tests
            self.results.append(self.test_module_importable())
            self.results.append(self.test_binaries_ingested())

            # Function tests
            self.results.append(self.test_analyze_path_complexity())
            self.results.append(self.test_analyze_path_traversal_likelihood())
            self.results.append(self.test_calculate_path_risk_score())
            self.results.append(self.test_get_paths_for_binary())
            self.results.append(self.test_analyze_all_paths_for_binary())

            # CLI tests
            self.results.append(self.test_cli_help())
            self.results.append(self.test_cli_sha256())

            # Integration tests
            self.results.append(self.test_risk_score_differentiation())

        finally:
            self.teardown()

    def print_summary(self) -> None:
        """Print test results summary."""
        print("\n" + "=" * 70)
        print("LAB 5.3 TEST RESULTS: Path Risk Analysis")
        print("=" * 70)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)

        for result in self.results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            print(f"{status}: {result.name}")
            if self.verbose or not result.passed:
                print(f"       {result.message}")
                if result.details and self.verbose:
                    for key, value in result.details.items():
                        print(f"       - {key}: {value}")

        print("=" * 70)
        print(f"SUMMARY: {passed} passed, {failed} failed, {len(self.results)} total")
        print("=" * 70)

        if failed > 0:
            print("\n⚠️  Some tests failed. Review the output above for details.")
            print("   Make sure you have:")
            print("   1. Completed Lab 3 setup (ingested binaries)")
            print("   2. Implemented all required functions in complexity_analysis.py")
            print("   3. Filled in the ### YOUR CODE HERE ### sections")
        else:
            print("\n🎉 All tests passed! Lab 3.3 implementation is complete.")


def main() -> None:
    """Main entry point for the test suite."""
    parser = argparse.ArgumentParser(
        description="Lab 3.3 Test: Path Risk Analysis Functions"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run tests
    test_suite = Lab5_3_Test(verbose=args.verbose)
    test_suite.run_all_tests()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(module_name)
    main()
