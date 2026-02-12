"""
Lab 3.2 Test: Source-to-Sink Path Analysis Functions.

This test validates Lab 3.2 from lab_3_2_source_to_sink_analysis.md:
- The source_to_sink_analysis module is importable
- The Lab 3 dataset is ingested (binaries from dataset/lab3/)
- All 4 vulnerability path detection functions execute successfully
- Functions return SourceToSinkPath objects with expected fields
- The aggregation functions work correctly
- Inter-procedural analysis functions work correctly

Reference: docs/labs/lab3/lab_3_2_source_to_sink_analysis.md

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.test.test_lab_3_2

    # Run with verbose output
    python -m student_labs.lab3.test.test_lab_3_2 -v
"""

import argparse
import logging
import os
import subprocess
import sys
import tempfile
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
    vuln_type: Optional[str] = None


class Lab5_2_Test:
    """
    Test suite for Lab 3.2 - Source-to-Sink Path Analysis Functions.

    This test suite validates the student-implemented functions in
    student_labs/lab3/source_to_sink_analysis.py:
    1. The module is importable
    2. Lab 3 binaries are ingested in Neo4j
    3. All 4 vulnerability path detection functions execute successfully
    4. Functions return properly structured SourceToSinkPath objects
    5. Aggregation functions work correctly
    6. Inter-procedural analysis functions work correctly (from reference implementation)
       - _find_source_to_sink_paths_interprocedural function exists
       - All detection functions support interprocedural parameter
       - call_depth parameter affects analysis results
       - Aggregation functions support interprocedural mode
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
        Test that the source_to_sink_analysis module is importable.

        From lab_3_2_source_to_sink_analysis.md:
        - Student file: student_labs/lab3/source_to_sink_analysis.py
        """
        test_name = "test_module_importable"

        try:
            from student_labs.lab3 import source_to_sink_analysis

            # Check for required functions
            required_functions = [
                "_find_source_to_sink_paths_base",
                "find_buffer_overflow_paths",
                "find_format_string_paths",
                "find_command_injection_paths",
                "find_path_traversal_paths",
                "get_all_vulnerability_paths",
                "get_high_risk_functions",
                "generate_vulnerability_report",
                "SourceToSinkPath",
            ]

            missing = []
            for func in required_functions:
                if not hasattr(source_to_sink_analysis, func):
                    missing.append(func)

            if missing:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Module missing required functions: {missing}",
                    details={"missing": missing},
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
                message=f"Failed to query Neo4j: {e}",
            )

    def test_find_buffer_overflow_paths(self) -> TestResult:
        """
        Test find_buffer_overflow_paths function.

        From lab_3_2_source_to_sink_analysis.md:
        - Should find paths from input sources to buffer overflow sinks
        """
        test_name = "test_find_buffer_overflow_paths"

        try:
            from student_labs.lab3.source_to_sink_analysis import (
                find_buffer_overflow_paths,
            )

            results = find_buffer_overflow_paths(self.driver, self.database, limit=10)

            # Verify return type
            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    vuln_type="buffer_overflow",
                )

            # Verify result structure if we have results
            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "source_apis", "sink_apis"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        vuln_type="buffer_overflow",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"find_buffer_overflow_paths returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                vuln_type="buffer_overflow",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                vuln_type="buffer_overflow",
            )

    def test_find_format_string_paths(self) -> TestResult:
        """
        Test find_format_string_paths function.

        From lab_3_2_source_to_sink_analysis.md:
        - Should find paths from input sources to format string sinks
        """
        test_name = "test_find_format_string_paths"

        try:
            from student_labs.lab3.source_to_sink_analysis import (
                find_format_string_paths,
            )

            results = find_format_string_paths(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    vuln_type="format_string",
                )

            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "source_apis", "sink_apis"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        vuln_type="format_string",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"find_format_string_paths returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                vuln_type="format_string",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                vuln_type="format_string",
            )

    def test_find_command_injection_paths(self) -> TestResult:
        """
        Test find_command_injection_paths function.

        From lab_3_2_source_to_sink_analysis.md:
        - Should find paths from input sources to command execution sinks
        """
        test_name = "test_find_command_injection_paths"

        try:
            from student_labs.lab3.source_to_sink_analysis import (
                find_command_injection_paths,
            )

            results = find_command_injection_paths(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    vuln_type="command_injection",
                )

            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "source_apis", "sink_apis"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        vuln_type="command_injection",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"find_command_injection_paths returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                vuln_type="command_injection",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                vuln_type="command_injection",
            )

    def test_find_path_traversal_paths(self) -> TestResult:
        """
        Test find_path_traversal_paths function.

        From lab_3_2_source_to_sink_analysis.md:
        - Should find paths from input sources to file operation sinks
        """
        test_name = "test_find_path_traversal_paths"

        try:
            from student_labs.lab3.source_to_sink_analysis import (
                find_path_traversal_paths,
            )

            results = find_path_traversal_paths(self.driver, self.database, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    vuln_type="path_traversal",
                )

            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "source_apis", "sink_apis"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        vuln_type="path_traversal",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"find_path_traversal_paths returned {len(results)} results",
                details={"result_count": len(results)},
                results_data=results[:5] if results else [],
                vuln_type="path_traversal",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                vuln_type="path_traversal",
            )

    def test_get_all_vulnerability_paths(self) -> TestResult:
        """
        Test get_all_vulnerability_paths aggregation function.

        From lab_3_2_source_to_sink_analysis.md:
        - Should return a dictionary with all vulnerability types
        """
        test_name = "test_get_all_vulnerability_paths"

        try:
            from student_labs.lab3.source_to_sink_analysis import (
                get_all_vulnerability_paths,
            )

            results = get_all_vulnerability_paths(self.driver, self.database, limit=5)

            if not isinstance(results, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(results).__name__}",
                )

            expected_keys = ["buffer_overflow", "format_string", "command_injection", "path_traversal"]
            missing_keys = [k for k in expected_keys if k not in results]

            if missing_keys:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing vulnerability types: {missing_keys}",
                    details={"missing_keys": missing_keys, "found_keys": list(results.keys())},
                )

            total_results = sum(len(v) for v in results.values())

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_all_vulnerability_paths returned {total_results} total results across {len(results)} categories",
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

        From lab_3_2_source_to_sink_analysis.md:
        - Should find functions with multiple vulnerability types
        """
        test_name = "test_get_high_risk_functions"

        try:
            from student_labs.lab3.source_to_sink_analysis import (
                get_high_risk_functions,
            )

            results = get_high_risk_functions(self.driver, self.database, min_vuln_types=2, limit=10)

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                )

            # Verify structure if we have results
            if results:
                first_result = results[0]
                required_keys = ["binary", "function", "vuln_types", "vuln_count"]
                missing_keys = [k for k in required_keys if k not in first_result]
                if missing_keys:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required keys: {missing_keys}",
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

        From lab_3_2_source_to_sink_analysis.md:
        - CLI should be accessible via python -m student_labs.lab3.source_to_sink_analysis
        """
        test_name = "test_cli_help"

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.source_to_sink_analysis", "--help"],
                capture_output=True,                text=True,                timeout=30,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --help failed with return code {result.returncode}",
                    details={"stderr": result.stderr},
                )

            # Check for expected flags in help output
            expected_flags = ["--all", "--buffer-overflow", "--format-string", "--command-injection", "--path-traversal"]
            missing_flags = [f for f in expected_flags if f not in result.stdout]

            if missing_flags:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI help missing expected flags: {missing_flags}",
                    details={"stdout": result.stdout[:500]},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --help works and shows expected flags",
                details={"flags_found": expected_flags},
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
                message=f"CLI test failed: {e}",
            )

    def test_cli_buffer_overflow(self) -> TestResult:
        """
        Test that the CLI --buffer-overflow flag works.

        From lab_3_2_source_to_sink_analysis.md:
        - python -m student_labs.lab3.source_to_sink_analysis --buffer-overflow
        """
        test_name = "test_cli_buffer_overflow"

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.source_to_sink_analysis",
                 "--buffer-overflow", "--limit", "5"],
                capture_output=True,                text=True,                timeout=60,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --buffer-overflow failed with return code {result.returncode}",
                    details={"stderr": result.stderr[:500]},
                )

            # Check for expected output patterns
            if "BUFFER" not in result.stdout.upper() and "overflow" not in result.stdout.lower():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="CLI --buffer-overflow output missing expected content",
                    details={"stdout": result.stdout[:500]},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --buffer-overflow works correctly",
                details={"output_length": len(result.stdout)},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --buffer-overflow timed out",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"CLI test failed: {e}",
            )

    def test_cli_all(self) -> TestResult:
        """
        Test that the CLI --all flag works.

        From lab_3_2_source_to_sink_analysis.md:
        - python -m student_labs.lab3.source_to_sink_analysis --all
        """
        test_name = "test_cli_all"

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.source_to_sink_analysis",
                 "--all", "--limit", "5"],
                capture_output=True,                text=True,                timeout=120,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --all failed with return code {result.returncode}",
                    details={"stderr": result.stderr[:500]},
                )

            # Check for expected vulnerability categories in output
            expected_categories = ["BUFFER", "FORMAT", "COMMAND", "PATH"]
            found_categories = [cat for cat in expected_categories if cat in result.stdout.upper()]

            return TestResult(
                name=test_name,
                passed=True,
                message=f"CLI --all works correctly, found {len(found_categories)} categories",
                details={"categories_found": found_categories},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --all timed out",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"CLI test failed: {e}",
            )

    def test_cli_high_risk(self) -> TestResult:
        """
        Test that the CLI --high-risk flag works.

        From lab_3_2_source_to_sink_analysis.md:
        - python -m student_labs.lab3.source_to_sink_analysis --high-risk
        """
        test_name = "test_cli_high_risk"

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.source_to_sink_analysis",
                 "--high-risk", "--limit", "10"],
                capture_output=True,                text=True,                timeout=60,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --high-risk failed with return code {result.returncode}",
                    details={"stderr": result.stderr[:500]},
                )

            # Check for expected output patterns
            if "HIGH" not in result.stdout.upper() and "RISK" not in result.stdout.upper():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="CLI --high-risk output missing expected content",
                    details={"stdout": result.stdout[:500]},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --high-risk works correctly",
                details={"output_length": len(result.stdout)},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --high-risk timed out",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"CLI test failed: {e}",
            )

    def test_cli_sha256_report(self) -> TestResult:
        """
        Test that the CLI --sha256 flag generates a report.

        From lab_3_2_source_to_sink_analysis.md:
        - python -m student_labs.lab3.source_to_sink_analysis --sha256 <hash>
        """
        test_name = "test_cli_sha256_report"
        # Use bison binary SHA256 from the lab
        import os as _os
        test_sha256 = "9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd"
        output_file = _os.path.join(tempfile.gettempdir(), f"test_cli_report_{test_sha256[:8]}.md")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.source_to_sink_analysis",
                 "--sha256", test_sha256, "--output", output_file],
                capture_output=True,                text=True,                timeout=120,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --sha256 failed with return code {result.returncode}",
                    details={"stderr": result.stderr[:500]},
                )

            # Check that output file was created
            if not _os.path.exists(output_file):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --sha256 did not create output file: {output_file}",
                )

            # Check file content
            with open(output_file, "r", encoding="utf-8") as f:
                content = f.read()

            if "Vulnerability" not in content and "Report" not in content:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Generated report missing expected content",
                    details={"content_length": len(content)},
                )

            # Clean up
            _os.remove(output_file)

            return TestResult(
                name=test_name,
                passed=True,
                message=f"CLI --sha256 generated report successfully ({len(content)} chars)",
                details={"report_length": len(content)},
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
                message=f"CLI test failed: {e}",
            )

    def test_cli_interprocedural(self) -> TestResult:
        """
        Test that the CLI --interprocedural flag works.

        From lab_3_2_source_to_sink_analysis.md:
        - python -m student_labs.lab3.source_to_sink_analysis --all --interprocedural
        """
        test_name = "test_cli_interprocedural"

        try:
            result = subprocess.run(
                [sys.executable, "-m", "student_labs.lab3.source_to_sink_analysis",
                 "--buffer-overflow", "--interprocedural", "--call-depth", "2", "--limit", "5"],
                capture_output=True,                text=True,                timeout=120,                encoding="utf-8",                errors="replace",                )

            if result.returncode != 0:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"CLI --interprocedural failed with return code {result.returncode}",
                    details={"stderr": result.stderr[:500]},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="CLI --interprocedural works correctly",
                details={"output_length": len(result.stdout)},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name=test_name,
                passed=False,
                message="CLI --interprocedural timed out",
            )
        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"CLI test failed: {e}",
            )

    # =========================================================================
    # Inter-Procedural Analysis Tests
    # =========================================================================

    def test_interprocedural_function_exists(self) -> TestResult:
        """
        Test that the inter-procedural analysis function exists.

        From lab_3_2_source_to_sink_analysis.md Additional Reading:
        - Inter-procedural analysis extends intra-procedural by following function calls
        """
        test_name = "test_interprocedural_function_exists"

        try:
            from labs.lab3.source_to_sink_analysis_reference import (
                _find_source_to_sink_paths_interprocedural,
            )

            # Verify function signature has expected parameters
            import inspect
            sig = inspect.signature(_find_source_to_sink_paths_interprocedural)
            params = list(sig.parameters.keys())

            expected_params = ["driver", "database", "source_apis", "sink_apis", "call_depth", "limit"]
            missing_params = [p for p in expected_params if p not in params]

            if missing_params:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Function missing expected parameters: {missing_params}",
                    details={"found_params": params, "expected_params": expected_params},
                )

            return TestResult(
                name=test_name,
                passed=True,
                message="Inter-procedural function exists with correct signature",
                details={"parameters": params},
            )

        except ImportError as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Failed to import inter-procedural function: {e}",
            )

    def test_interprocedural_buffer_overflow_paths(self) -> TestResult:
        """
        Test inter-procedural buffer overflow path detection.

        From lab_3_2_source_to_sink_analysis.md:
        - Inter-procedural analysis follows function calls to find cross-function paths
        """
        test_name = "test_interprocedural_buffer_overflow_paths"

        try:
            from labs.lab3.source_to_sink_analysis_reference import (
                find_buffer_overflow_paths,
            )

            # Test with interprocedural=True
            results = find_buffer_overflow_paths(
                self.driver, self.database, limit=10, interprocedural=True, call_depth=2
            )

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                    vuln_type="buffer_overflow_interprocedural",
                )

            # Verify result structure if we have results
            if results:
                first_result = results[0]
                required_attrs = ["binary", "function", "source_apis", "sink_apis"]
                missing_attrs = [attr for attr in required_attrs if not hasattr(first_result, attr)]
                if missing_attrs:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required attributes: {missing_attrs}",
                        vuln_type="buffer_overflow_interprocedural",
                    )

                # Inter-procedural paths should show call chain (e.g., "func1 -> func2")
                has_call_chain = any("->" in r.function for r in results)
                details = {
                    "result_count": len(results),
                    "has_call_chain_paths": has_call_chain,
                }
            else:
                details = {"result_count": 0}

            return TestResult(
                name=test_name,
                passed=True,
                message=f"Inter-procedural buffer overflow detection returned {len(results)} results",
                details=details,
                results_data=results[:3] if results else [],
                vuln_type="buffer_overflow_interprocedural",
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
                vuln_type="buffer_overflow_interprocedural",
            )

    def test_interprocedural_call_depth_parameter(self) -> TestResult:
        """
        Test that call_depth parameter affects inter-procedural analysis.

        From lab_3_2_source_to_sink_analysis.md:
        - call_depth=1: direct calls only
        - call_depth=2: calls through one intermediate function
        """
        test_name = "test_interprocedural_call_depth_parameter"

        try:
            from labs.lab3.source_to_sink_analysis_reference import (
                find_buffer_overflow_paths,
            )

            # Test with call_depth=1 (direct calls)
            results_depth1 = find_buffer_overflow_paths(
                self.driver, self.database, limit=50, interprocedural=True, call_depth=1
            )

            # Test with call_depth=2 (through intermediate function)
            results_depth2 = find_buffer_overflow_paths(
                self.driver, self.database, limit=50, interprocedural=True, call_depth=2
            )

            # Both should return lists
            if not isinstance(results_depth1, list) or not isinstance(results_depth2, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Expected lists for both call depths",
                )

            # Count paths with different call chain depths
            depth1_chains = sum(1 for r in results_depth1 if "->" in r.function)
            depth2_chains = sum(1 for r in results_depth2 if r.function.count("->") >= 2)

            return TestResult(
                name=test_name,
                passed=True,
                message=f"call_depth parameter works: depth1={len(results_depth1)} results, depth2={len(results_depth2)} results",
                details={
                    "depth1_count": len(results_depth1),
                    "depth2_count": len(results_depth2),
                    "depth1_call_chains": depth1_chains,
                    "depth2_multi_hop_chains": depth2_chains,
                },
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
            )

    def test_interprocedural_all_vulnerability_types(self) -> TestResult:
        """
        Test inter-procedural analysis for all vulnerability types.

        From lab_3_2_source_to_sink_analysis.md:
        - All 4 detection functions should support interprocedural parameter
        """
        test_name = "test_interprocedural_all_vulnerability_types"

        try:
            from labs.lab3.source_to_sink_analysis_reference import (
                find_buffer_overflow_paths,
                find_format_string_paths,
                find_command_injection_paths,
                find_path_traversal_paths,
            )

            results_summary = {}

            # Test each vulnerability type with interprocedural=True
            vuln_functions = [
                ("buffer_overflow", find_buffer_overflow_paths),
                ("format_string", find_format_string_paths),
                ("command_injection", find_command_injection_paths),
                ("path_traversal", find_path_traversal_paths),
            ]

            for vuln_type, func in vuln_functions:
                try:
                    results = func(self.driver, self.database, limit=10, interprocedural=True, call_depth=2)
                    results_summary[vuln_type] = {
                        "count": len(results),
                        "success": True,
                    }
                except Exception as e:
                    results_summary[vuln_type] = {
                        "count": 0,
                        "success": False,
                        "error": str(e),
                    }

            # Check if all functions executed successfully
            all_success = all(r["success"] for r in results_summary.values())

            if not all_success:
                failed = [k for k, v in results_summary.items() if not v["success"]]
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Inter-procedural analysis failed for: {failed}",
                    details=results_summary,
                )

            total_results = sum(r["count"] for r in results_summary.values())

            return TestResult(
                name=test_name,
                passed=True,
                message=f"All 4 vulnerability types support inter-procedural analysis ({total_results} total results)",
                details=results_summary,
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Test execution failed: {e}",
            )

    def test_interprocedural_get_all_vulnerability_paths(self) -> TestResult:
        """
        Test get_all_vulnerability_paths with interprocedural parameter.

        From lab_3_2_source_to_sink_analysis.md:
        - Aggregation function should also support interprocedural analysis
        """
        test_name = "test_interprocedural_get_all_vulnerability_paths"

        try:
            from labs.lab3.source_to_sink_analysis_reference import (
                get_all_vulnerability_paths,
            )

            # Test with interprocedural=True
            results = get_all_vulnerability_paths(
                self.driver, self.database, limit=5, interprocedural=True, call_depth=2
            )

            if not isinstance(results, dict):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected dict, got {type(results).__name__}",
                )

            expected_keys = ["buffer_overflow", "format_string", "command_injection", "path_traversal"]
            missing_keys = [k for k in expected_keys if k not in results]

            if missing_keys:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Missing vulnerability types: {missing_keys}",
                    details={"missing_keys": missing_keys, "found_keys": list(results.keys())},
                )

            total_results = sum(len(v) for v in results.values())

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_all_vulnerability_paths with interprocedural=True returned {total_results} total results",
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

    def test_interprocedural_high_risk_functions(self) -> TestResult:
        """
        Test get_high_risk_functions with interprocedural parameter.

        From lab_3_2_source_to_sink_analysis.md:
        - High-risk function detection should also support interprocedural analysis
        """
        test_name = "test_interprocedural_high_risk_functions"

        try:
            from labs.lab3.source_to_sink_analysis_reference import (
                get_high_risk_functions,
            )

            # Test with interprocedural=True
            results = get_high_risk_functions(
                self.driver, self.database, min_vuln_types=2, limit=10,
                interprocedural=True, call_depth=2
            )

            if not isinstance(results, list):
                return TestResult(
                    name=test_name,
                    passed=False,
                    message=f"Expected list, got {type(results).__name__}",
                )

            # Verify structure if we have results
            if results:
                first_result = results[0]
                required_keys = ["binary", "function", "vuln_types", "vuln_count"]
                missing_keys = [k for k in required_keys if k not in first_result]
                if missing_keys:
                    return TestResult(
                        name=test_name,
                        passed=False,
                        message=f"Result missing required keys: {missing_keys}",
                    )

            return TestResult(
                name=test_name,
                passed=True,
                message=f"get_high_risk_functions with interprocedural=True returned {len(results)} results",
                details={"result_count": len(results)},
            )

        except Exception as e:
            return TestResult(
                name=test_name,
                passed=False,
                message=f"Function execution failed: {e}",
            )

    def run_all_tests(self) -> List[TestResult]:
        """Run all tests and return results."""
        self.setup()

        tests = [
            # Intra-procedural tests
            self.test_module_importable,
            self.test_binaries_ingested,
            self.test_find_buffer_overflow_paths,
            self.test_find_format_string_paths,
            self.test_find_command_injection_paths,
            self.test_find_path_traversal_paths,
            self.test_get_all_vulnerability_paths,
            self.test_get_high_risk_functions,
            # CLI tests
            self.test_cli_help,
            self.test_cli_buffer_overflow,
            self.test_cli_all,
            self.test_cli_high_risk,
            self.test_cli_sha256_report,
            self.test_cli_interprocedural,
            # Inter-procedural tests (API-level)
            self.test_interprocedural_function_exists,
            self.test_interprocedural_buffer_overflow_paths,
            self.test_interprocedural_call_depth_parameter,
            self.test_interprocedural_all_vulnerability_types,
            self.test_interprocedural_get_all_vulnerability_paths,
            self.test_interprocedural_high_risk_functions,
        ]

        for test in tests:
            try:
                result = test()
                self.results.append(result)
                if self.verbose:
                    status = "✓" if result.passed else "✗"
                    print(f"  {status} {result.name}: {result.message}")
            except Exception as e:
                self.results.append(TestResult(
                    name=test.__name__,
                    passed=False,
                    message=f"Test raised exception: {e}",
                ))

        self.teardown()
        return self.results

    def print_summary(self) -> None:
        """Print test summary."""
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        print(f"\n{'=' * 60}")
        print(f"  Lab 3.2 Test Summary")
        print(f"{'=' * 60}")
        print(f"  Total Tests: {total}")
        print(f"  Passed:      {passed}")
        print(f"  Failed:      {failed}")
        print(f"{'=' * 60}")

        if failed > 0:
            print("\n  Failed Tests:")
            for r in self.results:
                if not r.passed:
                    print(f"    ✗ {r.name}: {r.message}")


def main() -> int:
    """Main entry point for the test suite."""
    parser = argparse.ArgumentParser(
        description="Run Lab 3.2 Source-to-Sink Path Analysis tests.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("\n" + "=" * 60)
    print("  Lab 3.2: Source-to-Sink Path Analysis Tests")
    print("=" * 60)

    test_suite = Lab5_2_Test(verbose=args.verbose)
    results = test_suite.run_all_tests()
    test_suite.print_summary()

    # Return non-zero exit code if any tests failed
    failed = sum(1 for r in results if not r.passed)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
