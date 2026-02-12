"""
Test Module for Lab 2.3 - Prompt Builder.

This module tests the prompt building functions that combine schema metadata
with instructions to create effective LLM prompts for Cypher generation.

Usage:
    source venv/bin/activate
    python -m student_labs.lab2.test.test_lab_2_3

Reference: docs/labs/lab2/lab_2_3_prompt_builder.md
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str


class Lab2_3_Test:
    """Test suite for Lab 2.3 - Prompt Builder."""

    def __init__(self, verbose: bool = False) -> None:
        """
        Initialize the test suite.

        Args:
            verbose: Enable verbose logging output.
        """
        self.verbose = verbose
        self.results: List[TestResult] = []

    def test_format_relationships_for_llm(self) -> TestResult:
        """Test that format_relationships_for_llm produces readable relationship patterns."""
        test_name = "test_format_relationships_for_llm"
        try:
            from student_labs.lab2.prompt_builder import format_relationships_for_llm

            # Test with sample relationship data
            sample_relationships = [
                {
                    "relType": ":`HAS_FUNCTION`",
                    "sourceNodeLabels": ["Binary"],
                    "targetNodeLabels": ["Function"],
                },
                {
                    "relType": ":`CALLS_TO`",
                    "sourceNodeLabels": ["BasicBlock"],
                    "targetNodeLabels": ["Function", "ImportSymbol"],
                },
            ]

            result = format_relationships_for_llm(sample_relationships)

            # Verify result is not None or empty
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            if not result.strip():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned empty string",
                )

            # Check for expected content
            checks = [
                ("RELATIONSHIP TYPES" in result, "Missing 'RELATIONSHIP TYPES' header"),
                ("HAS_FUNCTION" in result, "Missing 'HAS_FUNCTION' relationship"),
                ("CALLS_TO" in result, "Missing 'CALLS_TO' relationship"),
                ("Binary" in result, "Missing 'Binary' node label"),
                ("Function" in result, "Missing 'Function' node label"),
                (")-[:" in result, "Missing relationship pattern syntax"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully formats relationship metadata",
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

    def test_format_nodes_for_llm(self) -> TestResult:
        """Test that format_nodes_for_llm includes property names, types, and sample values."""
        test_name = "test_format_nodes_for_llm"
        try:
            from student_labs.lab2.prompt_builder import format_nodes_for_llm

            # Test with sample node data
            sample_nodes = [
                {
                    "nodeType": ":`Binary`",
                    "propertyName": "sha256",
                    "propertyTypes": ["STRING"],
                    "mandatory": True,
                    "sampleValues": ["9409117ee68a2d75643bb0e0a15c71ab"],
                },
                {
                    "nodeType": ":`Binary`",
                    "propertyName": "name",
                    "propertyTypes": ["STRING"],
                    "mandatory": True,
                    "sampleValues": ["bison_arm", "benign_sample"],
                },
                {
                    "nodeType": ":`Binary`",
                    "propertyName": "classification",
                    "propertyTypes": ["STRING"],
                    "mandatory": False,
                    "sampleValues": ["benign", "unknown"],
                },
            ]

            result = format_nodes_for_llm(sample_nodes)

            # Verify result is not None or empty
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            if not result.strip():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned empty string",
                )

            # Check for expected content
            checks = [
                ("NODE LABELS" in result, "Missing 'NODE LABELS' header"),
                ("Binary" in result, "Missing 'Binary' node type"),
                ("sha256" in result, "Missing 'sha256' property"),
                ("STRING" in result, "Missing 'STRING' type"),
                ("required" in result, "Missing 'required' indicator"),
                ("optional" in result, "Missing 'optional' indicator"),
                ("Samples:" in result, "Missing sample values"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully formats node metadata with properties and samples",
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

    def test_build_cypher_generation_prompt(self) -> TestResult:
        """Test that build_cypher_generation_prompt includes schema and instructions."""
        test_name = "test_build_cypher_generation_prompt"
        try:
            from student_labs.lab2.prompt_builder import build_cypher_generation_prompt

            # Test with sample schema text
            sample_schema = """
============================================================
RELATIONSHIP TYPES (Graph Topology)
============================================================

Relationship: HAS_FUNCTION
  (Binary)-[:HAS_FUNCTION]->(Function)

============================================================
NODE LABELS AND PROPERTIES
============================================================

Node: Binary
  - sha256 (STRING, required)
"""

            result = build_cypher_generation_prompt(sample_schema)

            # Verify result is not None or empty
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            if not result.strip():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned empty string",
                )

            # Check for expected content
            checks = [
                ("Cypher" in result, "Missing 'Cypher' in prompt"),
                ("DATABASE SCHEMA" in result or sample_schema.strip() in result, "Missing schema in prompt"),
                ("INSTRUCTIONS" in result, "Missing 'INSTRUCTIONS' section"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Successfully builds system prompt with schema and instructions",
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

    def test_prompt_contains_required_elements(self) -> TestResult:
        """Test that generated prompt contains required elements (INSTRUCTIONS, EXAMPLE, code blocks)."""
        test_name = "test_prompt_contains_required_elements"
        try:
            from student_labs.lab2.prompt_builder import build_cypher_generation_prompt

            # Test with minimal schema
            sample_schema = "Node: Binary\n  - sha256 (STRING, required)"

            result = build_cypher_generation_prompt(sample_schema)

            # Verify result is not None or empty
            if result is None:
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned None - not implemented",
                )

            if not result.strip():
                return TestResult(
                    name=test_name,
                    passed=False,
                    message="Function returned empty string",
                )

            # Check for required elements
            checks = [
                ("INSTRUCTIONS" in result, "Missing 'INSTRUCTIONS' section"),
                ("EXAMPLE" in result, "Missing 'EXAMPLE' section"),
                ("```cypher" in result, "Missing ```cypher code block marker"),
                ("```" in result, "Missing code block closing marker"),
                ("MATCH" in result, "Missing MATCH example in prompt"),
                ("RETURN" in result, "Missing RETURN example in prompt"),
            ]

            for check, error_msg in checks:
                if not check:
                    return TestResult(name=test_name, passed=False, message=error_msg)

            return TestResult(
                name=test_name,
                passed=True,
                message="Prompt contains all required elements",
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
            self.test_format_relationships_for_llm,
            self.test_format_nodes_for_llm,
            self.test_build_cypher_generation_prompt,
            self.test_prompt_contains_required_elements,
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
        description="Run tests for Lab 2.3 - Prompt Builder"
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
    print("Lab 2.3 - Prompt Builder Tests")
    print("=" * 40)
    print()

    # Run tests
    test_suite = Lab2_3_Test(verbose=args.verbose)
    test_suite.run_all()
    test_suite.print_summary()

    # Exit with appropriate code
    failed = sum(1 for r in test_suite.results if not r.passed)
    exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
