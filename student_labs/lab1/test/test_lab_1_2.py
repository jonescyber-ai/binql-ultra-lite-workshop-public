"""
Lab 1.2 Student Test: Graph Queries.

Tests your implementation of graph query functions in student_labs/lab1/graph_queries.py.

Usage:
    source venv/bin/activate
    python -m student_labs.lab1.test.test_lab_1_2
"""

import logging
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

_DEFAULT_CREDENTIALS = get_neo4j_credentials()


@dataclass
class TestResult:
    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


def run_tests() -> List[TestResult]:
    results = []
    creds = _DEFAULT_CREDENTIALS
    driver = GraphDatabase.driver(creds["uri"], auth=(creds["user"], creds["password"]))
    database = creds["database"]

    try:
        from student_labs.lab1.graph_queries import (
            count_entity_types,
            check_duplicates,
            get_relationship_counts,
            get_binary_metadata,
            find_dangerous_import_calls,
            get_call_graph,
        )

        # Test 1: count_entity_types
        counts = count_entity_types(driver, database)
        if isinstance(counts, list) and len(counts) > 0:
            binary_count = next((c for c in counts if c.get("label") == "Binary"), None)
            if binary_count and binary_count["count"] > 0:
                results.append(TestResult("count_entity_types", True, f"{len(counts)} types, Binary={binary_count['count']}"))
            else:
                results.append(TestResult("count_entity_types", False, "Binary count is 0 or missing"))
        else:
            results.append(TestResult("count_entity_types", False, f"Expected non-empty list, got {type(counts)}"))

        # Test 2: check_duplicates
        duplicates = check_duplicates(driver, database)
        if isinstance(duplicates, list) and len(duplicates) == 0:
            results.append(TestResult("check_duplicates", True, "No duplicates (expected)"))
        elif isinstance(duplicates, list):
            results.append(TestResult("check_duplicates", False, f"Found {len(duplicates)} duplicates"))
        else:
            results.append(TestResult("check_duplicates", False, f"Expected list, got {type(duplicates)}"))

        # Test 3: get_relationship_counts
        rel_counts = get_relationship_counts(driver, database)
        if isinstance(rel_counts, list) and len(rel_counts) > 0:
            required = {"name", "functions", "blocks", "strings", "imports"}
            missing = required - set(rel_counts[0].keys())
            if not missing:
                results.append(TestResult("get_relationship_counts", True, f"Counts for {len(rel_counts)} binaries"))
            else:
                results.append(TestResult("get_relationship_counts", False, f"Missing keys: {missing}"))
        else:
            results.append(TestResult("get_relationship_counts", False, "Expected non-empty list"))

        # Test 4: get_binary_metadata
        metadata = get_binary_metadata(driver, database)
        if isinstance(metadata, list) and len(metadata) > 0:
            required = {"name", "classification", "tags"}
            missing = required - set(metadata[0].keys())
            if not missing:
                results.append(TestResult("get_binary_metadata", True, f"Metadata for {len(metadata)} binaries"))
            else:
                results.append(TestResult("get_binary_metadata", False, f"Missing keys: {missing}"))
        else:
            results.append(TestResult("get_binary_metadata", False, "Expected non-empty list"))

        # Test 5: find_dangerous_import_calls
        dangerous = find_dangerous_import_calls(driver, database)
        if isinstance(dangerous, list):
            results.append(TestResult("find_dangerous_import_calls", True, f"Found {len(dangerous)} results"))
        else:
            results.append(TestResult("find_dangerous_import_calls", False, f"Expected list, got {type(dangerous)}"))

        # Test 6: get_call_graph
        edges = get_call_graph(driver, database)
        if isinstance(edges, list):
            results.append(TestResult("get_call_graph", True, f"Found {len(edges)} edges"))
        else:
            results.append(TestResult("get_call_graph", False, f"Expected list, got {type(edges)}"))

    except ImportError as e:
        results.append(TestResult("import", False, f"Import failed: {e}"))
    except Exception as e:
        results.append(TestResult("unexpected", False, f"Error: {e}"))
    finally:
        driver.close()

    return results


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    results = run_tests()

    print("\n" + "=" * 60)
    print("LAB 1.2 STUDENT TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    for r in results:
        status = "✓ PASS" if r.passed else "✗ FAIL"
        print(f"  {status}: {r.name} — {r.message}")

    print("-" * 60)
    print(f"Total: {len(results)} | Passed: {passed} | Failed: {failed}")
    print("=" * 60)

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
