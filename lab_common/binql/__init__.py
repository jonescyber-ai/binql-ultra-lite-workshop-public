"""
BinQL - Binary Query Language utilities for Neo4j program graph ingestion.

This package provides the core ingestion pipeline for converting binaries into
a Neo4j-backed knowledge graph, plus natural language to Cypher query conversion.

Key components:
- binql_ul: Main ingestion module with CLI and API
- nl2gql: Natural Language to Graph Query Language conversion
- binql_config.yaml: Configuration for Neo4j connection and ingestion settings

Usage:
    # CLI usage - Binary ingestion
    source venv/bin/activate
    python -m lab_common.binql.binql_ul --help

    # CLI usage - Natural language to Cypher
    source venv/bin/activate
    python -m lab_common.binql.nl2gql --query "Find all binaries with more than 100 functions"

    # API usage (preferred - explicit imports from submodules)
    from lab_common.binql.binql_ul import get_neo4j_credentials, ingest_binary
    from lab_common.binql.nl2gql import natural_language_to_cypher, export_schema

    # API usage (convenience - re-exported from package)
    from lab_common.binql import get_neo4j_credentials

Reference: docs/labs/lab1/lab_1_0_overview.md, docs/labs/lab2/lab_2_0_overview.md

Note on RuntimeWarning:
    Running `python -m lab_common.binql.binql_ul` may produce a RuntimeWarning about
    the module being found in sys.modules. This is harmless and occurs because Python
    imports the package before executing the submodule. The warning does not affect
    functionality. To avoid it, run the module directly without package import:
        python lab_common/binql/binql_ul.py --help
    Or simply ignore the warning - it has no impact on execution.
"""

# =============================================================================
# Re-exports for convenience
# =============================================================================
# These re-exports allow `from lab_common.binql import get_neo4j_credentials`
# as a convenience. The preferred pattern is explicit imports from submodules:
#     from lab_common.binql.binql_ul import get_neo4j_credentials

from lab_common.binql.binql_ul import get_neo4j_credentials

from lab_common.binql.nl2gql import (
    export_node_metadata,
    export_relationship_metadata,
    export_schema,
    natural_language_to_cypher,
    natural_language_to_cypher_with_retry,
)

__all__ = [
    "get_neo4j_credentials",
    "natural_language_to_cypher",
    "natural_language_to_cypher_with_retry",
    "export_schema",
    "export_node_metadata",
    "export_relationship_metadata",
]
