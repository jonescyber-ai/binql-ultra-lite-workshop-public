"""
Lab 3.4 Test: Vulnerability Triage Report Functions.

This test validates Lab 3.4 from lab_3_4_vulnerability_triage_report.md:
- The vulnerability_triage_report module is importable
- The Lab 3 dataset is ingested (binaries from dataset/lab3/)
- All 5 report generation functions execute successfully
- Functions return properly structured dataclass objects
- LLM integration produces meaningful output

Reference: docs/labs/lab3/lab_3_4_vulnerability_triage_report.md

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.test.test_lab_3_4

    # Run with verbose output
    python -m student_labs.lab3.test.test_lab_3_4 -v
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


class Lab3_4_Test:
    """
    Test suite for Lab 3.4 - Vulnerability Triage Report Functions.

    This test suite validates the student-implemented functions in
    student_labs/lab3/vulnerability_triage_report.py:
    1. The module is importable
    2. Lab 3 binaries are ingested in Neo4j
    3. All 5 report generation functions execute successfully
    4. Functions return properly structured dataclass objects
    5. LLM integration produces meaningful output
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
        # Cached results to avoid redundant Neo4j queries and LLM calls
        self._cached_findings: Optional[Dict[str, Any]] = None
        self._cached_findings_text: Optional[str] = None
        self._cached_executive_summary: Optional[str] = None
        self._cached_triage_report: Optional[Any] = None

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
        Test that the vulnerability_triage_report module is importable.

        From lab_3_4_vulnerability_triage_report.md:
        - Student file: student_labs/lab3/vulnerability_triage_report.py
        """
        test_name = "test_module_importable"

        try:
            # Import the module
            from student_labs.lab3 import vulnerability_triage_report

            # Check for required classes
            required_classes = [
                "VulnerabilityTriageReport",
            ]

            missing_classes = []
            for cls_name in required_classes:
                if not hasattr(vulnerability_triage_report, cls_name):
                    missing_classes.append(cls_name)

            if missing_classes:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing classes: {missing_classes}",
                )

            # Check for required functions
            required_functions = [
                "collect_lab3_findings",
                "format_findings_for_llm",
                "generate_executive_summary",
                "generate_vulnerability_triage_report",
                "create_triage_report",
            ]

            missing_functions = []
            for func_name in required_functions:
                if not hasattr(vulnerability_triage_report, func_name):
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

    def _get_findings(self) -> Dict[str, Any]:
        """Get cached findings or collect them once."""
        if self._cached_findings is None:
            from student_labs.lab3.vulnerability_triage_report import collect_lab3_findings
            self._cached_findings = collect_lab3_findings(self.driver, self.database, TEST_BINARY_SHA256)
        return self._cached_findings

    def _get_findings_text(self) -> str:
        """Get cached formatted findings or format them once."""
        if self._cached_findings_text is None:
            from student_labs.lab3.vulnerability_triage_report import format_findings_for_llm
            self._cached_findings_text = format_findings_for_llm(self._get_findings())
        return self._cached_findings_text

    def _get_executive_summary(self) -> str:
        """Get cached executive summary or generate it once."""
        if self._cached_executive_summary is None:
            from student_labs.lab3.vulnerability_triage_report import generate_executive_summary
            self._cached_executive_summary = generate_executive_summary(
                self._get_findings(), self._get_findings_text()
            )
        return self._cached_executive_summary

    def _get_triage_report(self):
        """Get cached triage report or create it once."""
        if self._cached_triage_report is None:
            from student_labs.lab3.vulnerability_triage_report import create_triage_report
            self._cached_triage_report = create_triage_report(
                self.driver, self.database, TEST_BINARY_SHA256, summary_only=False
            )
        return self._cached_triage_report

    def test_collect_lab3_findings(self) -> TestResult:
        """
        Test the collect_lab3_findings function.

        From lab_3_4_vulnerability_triage_report.md:
        - Function should gather findings from Labs 3.1, 3.2, and 3.3
        - Returns dictionary with input_sources, paths, risk_analyses, binary_name
        """
        test_name = "test_collect_lab3_findings"

        try:
            # Use cached findings to avoid redundant Neo4j queries
            findings = self._get_findings()

            # Verify return type
            if not isinstance(findings, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(findings).__name__}",
                )

            # Verify required keys
            required_keys = ["input_sources", "paths", "risk_analyses", "binary_name", "sha256"]
            missing_keys = [k for k in required_keys if k not in findings]

            if missing_keys:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing keys: {missing_keys}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="collect_lab3_findings returns valid dictionary",
                details={
                    "input_sources_count": len(findings.get("input_sources", [])),
                    "paths_count": len(findings.get("paths", [])),
                    "risk_analyses_count": len(findings.get("risk_analyses", [])),
                    "binary_name": findings.get("binary_name", "unknown"),
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_format_findings_for_llm(self) -> TestResult:
        """
        Test the format_findings_for_llm function.

        From lab_3_4_vulnerability_triage_report.md:
        - Function should format findings into a structured prompt
        - Returns a string with binary metadata, input sources, paths, risk analysis
        """
        test_name = "test_format_findings_for_llm"

        try:
            # Use cached findings and formatted text
            formatted = self._get_findings_text()

            # Verify return type
            if not isinstance(formatted, str):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected str, got {type(formatted).__name__}",
                )

            # Verify content includes expected sections
            expected_sections = ["Binary:", "SHA256:", "Input Sources", "Source-to-Sink Paths", "Risk Analysis"]
            missing_sections = [s for s in expected_sections if s not in formatted]

            if missing_sections:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing sections: {missing_sections}",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"format_findings_for_llm returns valid formatted string ({len(formatted)} chars)",
                details={
                    "length": len(formatted),
                    "sections_found": [s for s in expected_sections if s in formatted],
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_generate_executive_summary(self) -> TestResult:
        """
        Test the generate_executive_summary function.

        From lab_3_4_vulnerability_triage_report.md:
        - Function should use LLM to generate a 3-5 sentence summary
        - Returns a string with risk assessment and recommendations
        """
        test_name = "test_generate_executive_summary"

        try:
            # Use cached executive summary to avoid redundant LLM calls
            summary = self._get_executive_summary()

            # Verify return type
            if not isinstance(summary, str):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected str, got {type(summary).__name__}",
                )

            # Verify summary is not empty
            if len(summary.strip()) < 50:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Summary too short ({len(summary)} chars)",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"generate_executive_summary returns valid summary ({len(summary)} chars)",
                details={
                    "length": len(summary),
                    "preview": summary[:200] + "..." if len(summary) > 200 else summary,
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_generate_vulnerability_triage_report(self) -> TestResult:
        """
        Test the generate_vulnerability_triage_report function.

        From lab_3_4_vulnerability_triage_report.md:
        - Function should use LLM to generate a complete markdown report
        - Returns a string with executive summary, risk distribution, findings, recommendations
        """
        test_name = "test_generate_vulnerability_triage_report"

        try:
            # Use the cached triage report's markdown to avoid a separate LLM call.
            # create_triage_report already calls generate_vulnerability_triage_report
            # internally, so we validate its output here instead of making a redundant
            # LLM round-trip that can time out.
            triage_report = self._get_triage_report()
            report = triage_report.report_markdown

            # Verify return type
            if not isinstance(report, str):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected str, got {type(report).__name__}",
                )

            # Verify report is not empty and has reasonable length
            if len(report.strip()) < 200:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Report too short ({len(report)} chars)",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"generate_vulnerability_triage_report returns valid report ({len(report)} chars)",
                details={
                    "length": len(report),
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Error: {e}",
            )

    def test_create_triage_report(self) -> TestResult:
        """
        Test the create_triage_report function.

        From lab_3_4_vulnerability_triage_report.md:
        - Function should orchestrate the full pipeline
        - Returns VulnerabilityTriageReport dataclass
        """
        test_name = "test_create_triage_report"

        try:
            # Use cached triage report to avoid redundant LLM calls
            report = self._get_triage_report()

            # Verify return type (use class name to handle reference implementation)
            if type(report).__name__ != "VulnerabilityTriageReport":
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected VulnerabilityTriageReport, got {type(report).__name__}",
                )

            # Verify required fields
            required_fields = [
                "binary_name",
                "sha256",
                "analysis_timestamp",
                "input_sources",
                "input_source_count",
                "source_to_sink_paths",
                "path_count",
                "ranked_paths",
                "risk_distribution",
                "executive_summary",
                "report_markdown",
            ]

            missing_fields = []
            for field_name in required_fields:
                if not hasattr(report, field_name):
                    missing_fields.append(field_name)

            if missing_fields:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing fields: {missing_fields}",
                )

            # Verify executive summary is not empty
            if not report.executive_summary or len(report.executive_summary.strip()) < 50:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Executive summary is empty or too short",
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="create_triage_report returns valid VulnerabilityTriageReport",
                details={
                    "binary_name": report.binary_name,
                    "input_source_count": report.input_source_count,
                    "path_count": report.path_count,
                    "risk_distribution": report.risk_distribution,
                    "summary_length": len(report.executive_summary),
                },
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

        From lab_3_4_vulnerability_triage_report.md:
        - CLI should provide help output
        """
        test_name = "test_cli_help"

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "student_labs.lab3.vulnerability_triage_report",
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
            expected_terms = ["--sha256", "--all", "--summary-only", "--output"]
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

    def test_report_has_risk_distribution(self) -> TestResult:
        """
        Test that the report includes proper risk distribution.

        From lab_3_4_vulnerability_triage_report.md:
        - Report should include risk distribution (critical/high/medium/low counts)
        """
        test_name = "test_report_has_risk_distribution"

        try:
            # Use cached triage report to avoid redundant LLM calls
            report = self._get_triage_report()

            # Verify risk distribution exists and has expected keys
            if not hasattr(report, "risk_distribution"):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Report missing risk_distribution field",
                )

            risk_dist = report.risk_distribution
            expected_keys = ["critical", "high", "medium", "low"]
            missing_keys = [k for k in expected_keys if k not in risk_dist]

            if missing_keys:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Risk distribution missing keys: {missing_keys}",
                )

            # Verify values are integers
            for key, value in risk_dist.items():
                if not isinstance(value, int):
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Risk distribution value for '{key}' is not int: {type(value).__name__}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message="Report has valid risk distribution",
                details={"risk_distribution": risk_dist},
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
            self.results.append(self.test_collect_lab3_findings())
            self.results.append(self.test_format_findings_for_llm())
            self.results.append(self.test_generate_executive_summary())
            self.results.append(self.test_generate_vulnerability_triage_report())
            self.results.append(self.test_create_triage_report())

            # CLI tests
            self.results.append(self.test_cli_help())

            # Integration tests
            self.results.append(self.test_report_has_risk_distribution())

        finally:
            self.teardown()

    def print_summary(self) -> None:
        """Print test results summary."""
        print("\n" + "=" * 70)
        print("LAB 3.4 TEST RESULTS: Vulnerability Triage Report")
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
            print("   2. Implemented all required functions in vulnerability_triage_report.py")
            print("   3. Filled in the ### YOUR CODE HERE ### sections")
        else:
            print("\n🎉 All tests passed! Lab 3.4 implementation is complete.")


def main() -> int:
    """Main entry point for the test suite."""
    parser = argparse.ArgumentParser(
        description="Lab 3.4 Test: Vulnerability Triage Report Functions"
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
    test_suite = Lab3_4_Test(verbose=args.verbose)
    test_suite.run_all_tests()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    module_name = Path(__file__).stem
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(module_name)
    sys.exit(main())
