"""
NL2GQL: Natural Language to Graph Query Language.

This module exports Neo4j database schema information (labels, relationships, properties,
constraints, and indexes) in a text format optimized for use with Large Language Models (LLMs).
The exported schema helps LLMs generate accurate Cypher queries by providing comprehensive
context about the database structure.

Uses APOC procedures to extract metadata:
- apoc.meta.relTypeProperties(): Relationship topology and properties
- apoc.meta.nodeTypeProperties(): Node labels and properties
- apoc.export.cypher.schema(): Constraints and indexes as Cypher DDL

Additionally provides natural language to Cypher query conversion using LLM.

Default Behavior:
- LLM-generated descriptions are ENABLED by default (use --no-describe to disable)
- Schema enrichment with sample values is disabled by default (use --enrich to enable)

Automatic Query Refinement: If a generated query fails execution, the tool automatically
retries up to 3 times by default, feeding error messages back to the LLM for correction.

Usage:
    Run this script from the project root directory using the -m flag:

        cd /path/to/AutoRE_ML_NLP_LLM_Course
        python -m lab_common.binql.nl2gql --query "Find all malware binaries"

    Examples:
        # Export schema with LLM descriptions (default)
        python -m lab_common.binql.nl2gql

        # Export schema without LLM descriptions (faster, no LLM call)
        python -m lab_common.binql.nl2gql --no-describe

        # Export with sample values instead of descriptions
        python -m lab_common.binql.nl2gql --no-describe --no-enrich

        # Convert natural language to Cypher and execute (default behavior with auto-retry)
        python -m lab_common.binql.nl2gql --query "Find all malware binaries"

        # Query without LLM descriptions (faster)
        python -m lab_common.binql.nl2gql --query "Find malware" --no-describe

        # Adjust retry attempts
        python -m lab_common.binql.nl2gql --query "Complex query" --max-retries 5

        # Disable retries (fail on first error)
        python -m lab_common.binql.nl2gql --query "Simple query" --max-retries 0

        # Generate Cypher without executing
        python -m lab_common.binql.nl2gql --query "Show me all libraries" --no-execute

        # Execute with custom result limit
        python -m lab_common.binql.nl2gql --query "List all functions" --limit 10
"""

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import Driver, GraphDatabase

from lab_common.llm.client import llm_completion

logger = logging.getLogger(__name__)

# Default connection parameters
DEFAULT_URI = "neo4j://127.0.0.1:7687"
DEFAULT_USER = "neo4j"
DEFAULT_PASSWORD = "12345678"
DEFAULT_DATABASE = "neo4j"

# =============================================================================
# Predefined Schema Descriptions for BinQL Ontology
# =============================================================================

# Node descriptions explain what each node type represents in the binary analysis domain
NODE_DESCRIPTIONS: Dict[str, str] = {
    "Binary": "Represents a binary executable file (ELF, PE, Mach-O) that has been analyzed.",
    "Function": "A function or subroutine within a binary, identified by its entry point address.",
    "BasicBlock": "A sequence of instructions with a single entry and exit point within a function.",
    "ImportSymbol": "An external symbol imported by a binary from a shared library.",
    "ExportSymbol": "A symbol exported by a binary for use by other binaries.",
    "Library": "A shared library (DLL, .so) that provides imported symbols.",
    "StringLiteral": "A string constant embedded in a binary's data section.",
    "MalwareFamily": "A classification grouping related malware samples by family name.",
    "Vendor": "The vendor or manufacturer of a product containing the binary.",
    "Product": "A software product that contains one or more binaries.",
    "DefinedData": "A defined data item (global variable, constant) in the binary.",
}

# Property descriptions explain the meaning and purpose of each property
# Format: {"NodeLabel": {"property_name": "description"}}
PROPERTY_DESCRIPTIONS: Dict[str, Dict[str, str]] = {
    "Binary": {
        "sha256": "SHA-256 cryptographic hash uniquely identifying this binary.",
        "name": "Original filename or identifier of the binary.",
        "architecture": "CPU architecture the binary targets (e.g., x86_64, ARM, MIPS).",
        "file_type": "Binary format type (e.g., ELF, PE, Mach-O).",
        "word_size": "Processor word size (32-bit or 64-bit).",
        "endness": "Byte order (little-endian or big-endian).",
        "classification": "Security classification (malware, benign, suspicious, unknown).",
        "total_functions": "Total number of functions identified in this binary.",
        "file_size": "Size of the binary file in bytes.",
        "language_id": "Programming language or compiler identified for this binary.",
        "disassembler_type": "Disassembler used to analyze this binary (e.g., Ghidra, IDA).",
        "disassembler_version": "Version of the disassembler used for analysis.",
        "bcc_version": "Version of the Binary Context Container format.",
    },
    "Function": {
        "name": "Function name (from symbols or auto-generated like FUN_xxxxx).",
        "start_address": "Entry point address of the function in the binary.",
        "end_address": "End address of the function (last instruction).",
        "binary_sha256": "SHA-256 of the binary containing this function.",
        "is_thunk": "Whether this function is a thunk (simple jump to another function).",
        "is_external": "Whether this function is external (imported, not defined in binary).",
        "calling_convention": "Calling convention used by this function.",
        "decompiled_code": "Decompiled source code representation of the function.",
        "decompiled_code_sha256": "SHA-256 hash of the decompiled code.",
        "total_basic_blocks": "Number of basic blocks in this function.",
        "total_instructions": "Total instruction count in this function.",
        "cyclomatic_complexity": "McCabe cyclomatic complexity metric for this function.",
    },
    "BasicBlock": {
        "start_address": "Starting address of the basic block.",
        "end_address": "Ending address of the basic block.",
        "binary_sha256": "SHA-256 of the binary containing this basic block.",
        "exit_type": "How control flow exits this block (call, jump, return, etc.).",
        "instruction_count": "Number of instructions in this basic block.",
    },
    "ImportSymbol": {
        "name": "Name of the imported symbol/function.",
        "qualified_name": "Fully qualified name including library (e.g., libc!malloc).",
        "library_name": "Name of the library providing this symbol.",
        "ordinal": "Ordinal number for PE imports (if applicable).",
    },
    "ExportSymbol": {
        "name": "Name of the exported symbol.",
        "address": "Address where this symbol is defined in the binary.",
        "binary_sha256": "SHA-256 of the binary exporting this symbol.",
        "ordinal": "Export ordinal number (for PE binaries).",
    },
    "Library": {
        "name": "Name of the shared library (e.g., libc.so.6, kernel32.dll).",
    },
    "StringLiteral": {
        "value": "The actual string content.",
        "name": "Truncated display name for the string.",
        "sha256": "SHA-256 hash of the string value for deduplication.",
        "address": "Address where this string is located in the binary.",
    },
    "MalwareFamily": {
        "name": "Name of the malware family (e.g., zeus, emotet, wannacry).",
    },
    "Vendor": {
        "name": "Name of the vendor or manufacturer.",
    },
    "Product": {
        "name": "Name of the software product.",
        "vendor_name": "Name of the vendor producing this product.",
        "version": "Version string of the product.",
    },
    "DefinedData": {
        "address": "Memory address of the defined data item.",
        "binary_sha256": "SHA-256 of the binary containing this data.",
        "name": "Name or label for this data item.",
        "size": "Size of the data item in bytes.",
        "data_type": "Type of the data (int, pointer, array, etc.).",
    },
}

# Relationship descriptions explain the meaning of each relationship type
RELATIONSHIP_DESCRIPTIONS: Dict[str, str] = {
    "HAS_FUNCTION": "Binary contains this function.",
    "CALLS_FUNCTION": "Function calls another function.",
    "ENTRY_BLOCK": "Function's entry point basic block.",
    "ORPHAN_BLOCK": "Basic block not reachable from function entry.",
    "BRANCHES_TO": "Control flow from one basic block to another.",
    "CALLS_TO": "Basic block contains a call to a function or import.",
    "IMPORTS_SYMBOL": "Binary imports this external symbol.",
    "EXPORTS_SYMBOL": "Binary exports this symbol for external use.",
    "USES_LIBRARY": "Binary depends on this shared library.",
    "FROM_LIBRARY": "Import symbol comes from this library.",
    "USES_STRING": "Binary or basic block references this string literal.",
    "BELONGS_TO_FAMILY": "Binary is classified as belonging to this malware family.",
    "SIMILAR_TO": "Binary or function is similar to another (with similarity score).",
    "PRODUCED_BY": "Product is produced by this vendor.",
    "CONTAINS_BINARY": "Product contains this binary.",
}


def get_schema_descriptions() -> Dict[str, Dict[str, str]]:
    """
    Get predefined schema descriptions for the BinQL ontology.

    Returns a dictionary suitable for use with format_nodes_for_llm(),
    containing node descriptions and property descriptions.

    Returns:
        Dictionary mapping node labels to their descriptions:
        {
            "Binary": {
                "node_description": "Represents a binary executable file...",
                "sha256": "SHA-256 cryptographic hash uniquely identifying...",
                ...
            }
        }
    """
    descriptions: Dict[str, Dict[str, str]] = {}

    for label, node_desc in NODE_DESCRIPTIONS.items():
        descriptions[label] = {"node_description": node_desc}

        # Add property descriptions if available
        if label in PROPERTY_DESCRIPTIONS:
            descriptions[label].update(PROPERTY_DESCRIPTIONS[label])

    return descriptions


def enrich_node_properties_with_descriptions(
    node_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Enrich node property metadata with predefined descriptions.

    This adds human-readable descriptions to help LLMs understand the semantic
    meaning of properties without requiring sample values from the database.

    Unlike enrich_node_properties_with_samples(), this function does not require
    a database connection and uses predefined descriptions from the BinQL ontology.

    Args:
        node_records: Node metadata records from export_node_metadata().

    Returns:
        Enriched node records with 'description' field added to each property.
    """
    logger.info("Enriching node properties with predefined descriptions...")

    enriched_records = []

    for record in node_records:
        node_type = record["nodeType"]
        label = node_type.strip(":`")
        prop_name = record.get("propertyName")

        enriched_record = record.copy()

        # Add property description if available
        if prop_name and label in PROPERTY_DESCRIPTIONS:
            prop_desc = PROPERTY_DESCRIPTIONS[label].get(prop_name)
            if prop_desc:
                enriched_record["description"] = prop_desc

        enriched_records.append(enriched_record)

    logger.info(f"Enriched {len(enriched_records)} node property records with descriptions")
    return enriched_records


def export_relationship_metadata(driver: Driver, database: str) -> List[Dict[str, Any]]:
    """
    Export relationship types with source/target labels and properties.

    Uses APOC's apoc.meta.relTypeProperties() to get comprehensive relationship metadata.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        List of dictionaries containing relationship metadata.
    """
    query = """
        CALL apoc.meta.relTypeProperties()
        YIELD relType, sourceNodeLabels, targetNodeLabels, propertyName, propertyTypes, mandatory
        RETURN relType, sourceNodeLabels, targetNodeLabels, propertyName, propertyTypes, mandatory
        ORDER BY relType, sourceNodeLabels, targetNodeLabels, propertyName
    """

    with driver.session(database=database) as session:
        result = session.run(query)
        records = [dict(record) for record in result]

    logger.info(f"Exported {len(records)} relationship property records")
    return records


def export_node_metadata(driver: Driver, database: str) -> List[Dict[str, Any]]:
    """
    Export node labels and their properties with types.

    Uses APOC's apoc.meta.nodeTypeProperties() to get node metadata.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        List of dictionaries containing node label metadata.
    """
    query = """
        CALL apoc.meta.nodeTypeProperties()
        YIELD nodeType, nodeLabels, propertyName, propertyTypes, mandatory
        RETURN nodeType, nodeLabels, propertyName, propertyTypes, mandatory
        ORDER BY nodeType, propertyName
    """

    with driver.session(database=database) as session:
        result = session.run(query)
        records = [dict(record) for record in result]

    logger.info(f"Exported {len(records)} node property records")
    return records


def enrich_node_properties_with_samples(
    driver: Driver,
    database: str,
    node_records: List[Dict[str, Any]],
    max_samples: int = 5,
) -> List[Dict[str, Any]]:
    """
    Enrich node property metadata with sample values from the database.

    This adds concrete examples of property values to help LLMs understand
    the data better (e.g., classification: ["malware", "benign", "suspicious"]).

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        node_records: Node metadata records from export_node_metadata().
        max_samples: Maximum number of unique sample values to collect per property.

    Returns:
        Enriched node records with 'sample_values' field added.
    """
    logger.info("Enriching node properties with sample values...")

    # Group records by node type
    node_types = {}
    for record in node_records:
        node_type = record["nodeType"]
        if node_type not in node_types:
            node_types[node_type] = []
        node_types[node_type].append(record)

    enriched_records = []

    with driver.session(database=database) as session:
        for node_type, properties in node_types.items():
            # Extract label from nodeType (e.g., ":`Binary`" -> "Binary")
            label = node_type.strip(":`")

            for prop_record in properties:
                prop_name = prop_record["propertyName"]

                if not prop_name:
                    enriched_records.append(prop_record)
                    continue

                # Query to get distinct sample values for this property
                sample_query = f"""
                    MATCH (n:{label})
                    WHERE n.{prop_name} IS NOT NULL
                    RETURN DISTINCT n.{prop_name} AS value
                    LIMIT {max_samples}
                """

                try:
                    result = session.run(sample_query)
                    samples = [record["value"] for record in result]

                    # Add samples to the record
                    enriched_record = prop_record.copy()
                    enriched_record["sample_values"] = samples
                    enriched_records.append(enriched_record)

                    logger.debug(
                        f"Collected {len(samples)} samples for {label}.{prop_name}: {samples}"
                    )
                except Exception as e:
                    logger.warning(f"Could not get samples for {label}.{prop_name}: {e}")
                    enriched_records.append(prop_record)

    logger.info(f"Enriched {len(enriched_records)} node property records with sample values")
    return enriched_records


def generate_schema_descriptions_with_llm(
    node_records: List[Dict[str, Any]],
    relationship_records: List[Dict[str, Any]],
) -> Dict[str, Dict[str, str]]:
    """
    Use LLM to generate human-readable descriptions for nodes and properties.

    Analyzes property names, types, and sample values to infer semantic meaning.

    Args:
        node_records: Node metadata records (should be enriched with sample_values).
        relationship_records: Relationship metadata records.

    Returns:
        Dictionary mapping node labels and properties to descriptions:
        {
            "Binary": {
                "node_description": "Represents a binary executable file...",
                "sha256": "Cryptographic hash uniquely identifying the binary...",
                "classification": "Security classification of the binary..."
            }
        }
    """
    logger.info("Generating schema descriptions using LLM...")

    # Build context for LLM
    context_lines = ["Database Schema Analysis Request:", ""]

    # Group by node type
    node_groups = {}
    for record in node_records:
        node_type = record["nodeType"]
        label = node_type.strip(":`")
        if label not in node_groups:
            node_groups[label] = []
        node_groups[label].append(record)

    # Format for LLM
    context_lines.append("NODE TYPES:")
    for label, properties in node_groups.items():
        context_lines.append(f"\n{label}:")
        for prop in properties:
            prop_name = prop.get("propertyName")
            if not prop_name:
                continue
            prop_type = ", ".join(prop.get("propertyTypes", []))
            mandatory = "REQUIRED" if prop.get("mandatory") else "OPTIONAL"
            samples = prop.get("sample_values", [])

            context_lines.append(f"  - {prop_name} ({prop_type}, {mandatory})")
            if samples:
                sample_str = str(samples[:3])  # Show first 3 samples
                context_lines.append(f"    Sample values: {sample_str}")

    context_lines.append("\nRELATIONSHIPS:")
    rel_types = set()
    for record in relationship_records:
        rel_type = record["relType"]
        source = ", ".join(record["sourceNodeLabels"])
        target = ", ".join(record["targetNodeLabels"])
        rel_types.add(f"  ({source})-[:{rel_type}]->({target})")

    context_lines.extend(sorted(rel_types))

    context = "\n".join(context_lines)

    # Create LLM prompt
    system_prompt = """You are a database schema documentation expert. Generate concise, technical descriptions for node types and their properties based on the schema information provided.

For each node type, provide:
1. A brief description of what the node represents (1-2 sentences)
2. A description for each property explaining its purpose and meaning

Return your response in this exact JSON format:
{
  "NodeLabel": {
    "node_description": "Description of the node type",
    "property_name": "Description of the property"
  }
}

Keep descriptions:
- Technical and precise
- 1-2 sentences per item
- Focused on semantic meaning, not just restating the name
- Informed by sample values when available
"""

    user_prompt = f"""Analyze this database schema and generate descriptions:

{context}

Generate comprehensive descriptions for all node types and their properties."""

    try:
        llm_response = llm_completion(user_prompt, system_prompt=system_prompt)
        logger.info(f"LLM description generation completed (tokens: {llm_response.total_tokens})")

        # Parse JSON response
        response_text = llm_response.response.strip()

        # Try to extract JSON from code blocks
        json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL | re.IGNORECASE)
        if json_match:
            response_text = json_match.group(1)
        else:
            # Try generic code block
            json_match = re.search(r"```\s*(.*?)\s*```", response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1)

        descriptions = json.loads(response_text)
        logger.info(f"Successfully parsed descriptions for {len(descriptions)} node types")
        return descriptions

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response as JSON: {e}")
        logger.debug(f"Response text: {llm_response.response}")
        return {}
    except Exception as e:
        logger.error(f"LLM description generation failed: {e}")
        return {}


def export_schema_ddl_manual(driver: Driver, database: str) -> str:
    """
    Manually export constraints and indexes when APOC is not available.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        String containing Cypher DDL statements for constraints and indexes.
    """
    ddl_lines = []

    with driver.session(database=database) as session:
        # Get constraints
        constraints_result = session.run("SHOW CONSTRAINTS")
        constraints = list(constraints_result)

        if constraints:
            ddl_lines.append("// Constraints")
            for constraint in constraints:
                constraint_name = constraint.get("name", "unnamed")
                constraint_type = constraint.get("type", "UNKNOWN")
                ddl_lines.append(f"// Constraint: {constraint_name} ({constraint_type})")

        # Get indexes
        indexes_result = session.run("SHOW INDEXES")
        indexes = list(indexes_result)

        if indexes:
            ddl_lines.append("")
            ddl_lines.append("// Indexes")
            for index in indexes:
                index_name = index.get("name", "unnamed")
                index_type = index.get("type", "UNKNOWN")
                ddl_lines.append(f"// Index: {index_name} ({index_type})")

    return "\n".join(ddl_lines)


def export_schema_ddl(driver: Driver, database: str) -> str:
    """
    Export constraints and indexes as Cypher DDL statements.

    Uses APOC's apoc.export.cypher.schema() with streaming to generate DDL.
    Falls back to manual constraint/index extraction if APOC is not available.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        String containing Cypher DDL statements for constraints and indexes.
    """
    # Try APOC first with streaming enabled
    query = """
        CALL apoc.export.cypher.schema(null, {stream: true})
        YIELD cypherStatements
        RETURN cypherStatements
    """

    try:
        with driver.session(database=database) as session:
            result = session.run(query)
            record = result.single()
            ddl = record["cypherStatements"] if record else ""

        logger.info(f"Exported schema DDL using APOC ({len(ddl)} characters)")
        return ddl
    except Exception as e:
        logger.warning(f"APOC schema export failed, using manual extraction: {e}")
        return export_schema_ddl_manual(driver, database)


def export_schema_json(driver: Driver, database: str) -> Dict[str, Any]:
    """
    Export full schema as a JSON object.

    Uses APOC's apoc.meta.schema() for complete schema representation.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.

    Returns:
        Dictionary containing the complete schema structure.
    """
    query = """
        CALL apoc.meta.schema()
        YIELD value
        RETURN value
    """

    with driver.session(database=database) as session:
        result = session.run(query)
        record = result.single()
        schema = dict(record["value"]) if record else {}

    logger.info("Exported complete schema as JSON")
    return schema


def format_relationships_for_llm(records: List[Dict[str, Any]]) -> str:
    """
    Format relationship metadata in LLM-friendly tabular text.

    Args:
        records: List of relationship property records.

    Returns:
        Formatted string representation of relationship metadata.
    """
    if not records:
        return "No relationships found in database.\n"

    lines = [
        "=" * 100,
        "RELATIONSHIP TYPES AND PROPERTIES",
        "=" * 100,
        "",
    ]

    current_rel_type = None
    current_endpoints = None

    for record in records:
        rel_type = record["relType"]
        source = ", ".join(record["sourceNodeLabels"])
        target = ", ".join(record["targetNodeLabels"])
        prop_name = record["propertyName"]
        prop_types = ", ".join(record["propertyTypes"]) if record["propertyTypes"] else "N/A"
        mandatory = "REQUIRED" if record["mandatory"] else "OPTIONAL"

        endpoints = f"({source})-[:{rel_type}]->({target})"

        # Print relationship header when it changes
        if rel_type != current_rel_type or endpoints != current_endpoints:
            lines.append("")
            lines.append(f"Relationship: {endpoints}")
            lines.append("-" * 100)
            current_rel_type = rel_type
            current_endpoints = endpoints

        # Print property
        if prop_name:
            lines.append(f"  Property: {prop_name}")
            lines.append(f"    Type: {prop_types}")
            lines.append(f"    Required: {mandatory}")

    lines.append("")
    return "\n".join(lines)


def format_nodes_for_llm(
    records: List[Dict[str, Any]],
    descriptions: Optional[Dict[str, Dict[str, str]]] = None,
    include_samples: bool = True,
) -> str:
    """
    Format node metadata in LLM-friendly tabular text.

    Args:
        records: List of node property records (optionally enriched with sample_values).
        descriptions: Optional LLM-generated descriptions for nodes and properties.
        include_samples: Whether to include sample values in output. When descriptions
            are provided, samples may have been used to generate them but shouldn't
            appear in the final output.

    Returns:
        Formatted string representation of node metadata.
    """
    if not records:
        return "No node labels found in database.\n"

    lines = [
        "=" * 100,
        "NODE LABELS AND PROPERTIES",
        "=" * 100,
        "",
    ]

    current_node_type = None
    current_label = None

    for record in records:
        node_type = record["nodeType"]
        node_labels = ", ".join(record["nodeLabels"])
        prop_name = record["propertyName"]
        prop_types = ", ".join(record["propertyTypes"]) if record["propertyTypes"] else "N/A"
        mandatory = "REQUIRED" if record["mandatory"] else "OPTIONAL"

        # Print node label header when it changes
        if node_type != current_node_type:
            current_label = node_type.strip(":`")
            lines.append("")
            lines.append(f"Node Label: {node_labels}")
            lines.append("-" * 100)

            # Add node description if available
            if descriptions and current_label in descriptions:
                node_desc = descriptions[current_label].get("node_description")
                if node_desc:
                    lines.append(f"Description: {node_desc}")
                    lines.append("")

            current_node_type = node_type

        # Print property
        if prop_name:
            lines.append(f"  Property: {prop_name}")
            lines.append(f"    Type: {prop_types}")
            lines.append(f"    Required: {mandatory}")

            # Add property description if available
            if descriptions and current_label in descriptions:
                prop_desc = descriptions[current_label].get(prop_name)
                if prop_desc:
                    lines.append(f"    Description: {prop_desc}")

            # Add sample values if available (from enrichment) and requested
            if include_samples and "sample_values" in record and record["sample_values"]:
                samples = record["sample_values"]
                # Format samples nicely based on type
                if isinstance(samples[0], str):
                    formatted_samples = '", "'.join(str(s) for s in samples)
                    lines.append(f'    Sample Values: ["{formatted_samples}"]')
                else:
                    formatted_samples = ", ".join(str(s) for s in samples)
                    lines.append(f"    Sample Values: [{formatted_samples}]")

    lines.append("")
    return "\n".join(lines)


def format_ddl_for_llm(ddl: str) -> str:
    """
    Format schema DDL for LLM consumption.

    Args:
        ddl: Cypher DDL statements.

    Returns:
        Formatted DDL with header.
    """
    lines = [
        "=" * 100,
        "CONSTRAINTS AND INDEXES (Cypher DDL)",
        "=" * 100,
        "",
        ddl,
        "",
    ]
    return "\n".join(lines)


def generate_llm_prompt_template(schema_text: str) -> str:
    """
    Generate an example LLM prompt template with the schema embedded.

    Args:
        schema_text: Complete formatted schema text.

    Returns:
        LLM prompt template with schema context.
    """
    prompt = f"""
===== NEO4J DATABASE SCHEMA =====

{schema_text}

===== INSTRUCTIONS =====

You are a Cypher query expert. Using the schema above, generate accurate Cypher queries.

When generating queries:
1. Respect node labels and relationship types exactly as defined
2. Use only properties that exist in the schema
3. Pay attention to property types (STRING, INTEGER, etc.)
4. Honor required vs. optional properties
5. Follow relationship direction: (Source)-[:TYPE]->(Target)

===== EXAMPLE USAGE =====

User Query: "Find all functions in a binary with SHA256 starting with 'abc123'"

Your Cypher:
MATCH (b:Binary {{sha256: 'abc123...'}})-[:HAS_FUNCTION]->(f:Function)
RETURN f.name, f.start_address

===== YOUR TURN =====

User Query: [PASTE YOUR NATURAL LANGUAGE QUERY HERE]

Your Cypher:
"""
    return prompt


def export_schema(
    driver: Driver,
    database: str,
    output_file: Optional[Path] = None,
    format_type: str = "text",
    include_prompt_template: bool = False,
    include_samples: bool = False,
    max_samples: int = 5,
    describe_with_llm: bool = True,
) -> str:
    """
    Export complete Neo4j schema in specified format.

    When describe_with_llm=True (default), sample values are automatically collected
    from the database to help the LLM generate meaningful descriptions. The samples
    are used internally but only the descriptions appear in the output.

    Use include_samples=True to also include sample values in the exported schema
    (in addition to descriptions if describe_with_llm=True).

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        output_file: Optional output file path. If None, prints to stdout.
        format_type: Export format - "text" (LLM-friendly), "json", or "both".
        include_prompt_template: Whether to include LLM prompt template.
        include_samples: Whether to include sample values in the exported schema.
            Samples are always collected when describe_with_llm=True (to generate
            descriptions), but this controls whether they appear in the output.
        max_samples: Maximum number of sample values per property.
        describe_with_llm: Whether to generate descriptions using LLM (default: True).
            When True, sample values are collected and used to generate descriptions.

    Returns:
        Formatted schema text.
    """
    logger.info(f"Exporting schema from database: {database}")

    # Gather all metadata
    relationships = export_relationship_metadata(driver, database)
    nodes = export_node_metadata(driver, database)

    # Collect sample values if needed for LLM descriptions OR if user wants them in output
    # Samples are always collected when describe_with_llm=True to help generate descriptions
    need_samples = include_samples or describe_with_llm
    if need_samples:
        nodes = enrich_node_properties_with_samples(driver, database, nodes, max_samples)

    # Generate descriptions with LLM if requested
    descriptions = None
    if describe_with_llm:
        descriptions = generate_schema_descriptions_with_llm(nodes, relationships)

    ddl = export_schema_ddl(driver, database)

    # Format for text output
    text_output = ""
    if format_type in ("text", "both"):
        rel_text = format_relationships_for_llm(relationships)
        node_text = format_nodes_for_llm(nodes, descriptions, include_samples=include_samples)
        ddl_text = format_ddl_for_llm(ddl)

        text_output = f"{rel_text}\n{node_text}\n{ddl_text}"

        if include_prompt_template:
            text_output = generate_llm_prompt_template(text_output)

    # Format for JSON output
    json_output = {}
    if format_type in ("json", "both"):
        schema_json = export_schema_json(driver, database)
        json_output = {
            "relationships": relationships,
            "nodes": nodes,
            "ddl": ddl,
            "full_schema": schema_json,
        }

    # Write output
    if output_file:
        if format_type == "text":
            output_file.write_text(text_output, encoding="utf-8")
            logger.info(f"Schema exported to: {output_file}")
        elif format_type == "json":
            output_file.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
            logger.info(f"Schema JSON exported to: {output_file}")
        elif format_type == "both":
            text_file = output_file.with_suffix(".txt")
            json_file = output_file.with_suffix(".json")
            text_file.write_text(text_output, encoding="utf-8")
            json_file.write_text(json.dumps(json_output, indent=2), encoding="utf-8")
            logger.info(f"Schema exported to: {text_file} and {json_file}")
    else:
        # Print to stdout
        if format_type in ("text", "both"):
            print(text_output)
        if format_type in ("json", "both"):
            print(json.dumps(json_output, indent=2))

    return text_output


def build_cypher_generation_system_prompt(schema_text: str) -> str:
    """
    Build a system prompt for Cypher query generation.

    Args:
        schema_text: Formatted schema text containing relationships, nodes, and constraints.

    Returns:
        System prompt optimized for Cypher query generation.
    """
    system_prompt = f"""You are an expert Neo4j Cypher query generator. Given a natural language question, generate an accurate Cypher query.

DATABASE SCHEMA:
{schema_text}

INSTRUCTIONS:
1. Generate ONLY valid Cypher syntax
2. Use exact node labels and relationship types from the schema
3. Use only properties that exist in the schema
4. Respect property types (STRING, INTEGER, etc.)
5. Follow relationship direction: (Source)-[:TYPE]->(Target)
6. Use MATCH for queries, not CREATE/MERGE unless explicitly asked
7. Return your Cypher query inside ```cypher and ``` code blocks
8. Add a brief explanation after the query

EXAMPLE:
User: "Find all malware binaries"
Assistant:
```cypher
MATCH (b:Binary)-[:BELONGS_TO_FAMILY]->(mf:MalwareFamily)
RETURN b.name, b.sha256, mf.name AS family
LIMIT 25
```

This query finds binaries that belong to a malware family and returns their name, SHA256 hash, and family name, limited to 25 results.
"""
    return system_prompt


def extract_cypher_from_response(response_text: str) -> Optional[str]:
    """
    Extract Cypher query from LLM response.

    Looks for Cypher code blocks marked with ```cypher or ```

    Args:
        response_text: Raw LLM response text.

    Returns:
        Extracted Cypher query or None if not found.
    """
    # Try to find code blocks with cypher language marker
    cypher_pattern = r"```cypher\s*(.*?)\s*```"
    match = re.search(cypher_pattern, response_text, re.DOTALL | re.IGNORECASE)

    if match:
        return match.group(1).strip()

    # Try to find any code block
    code_pattern = r"```\s*(.*?)\s*```"
    match = re.search(code_pattern, response_text, re.DOTALL)

    if match:
        return match.group(1).strip()

    # If no code block found, return the entire response (might be just the query)
    return response_text.strip()


def build_cypher_refinement_prompt(
    schema_text: str, question: str, previous_query: str, error_message: str
) -> str:
    """
    Build a system prompt for refining a Cypher query that failed execution.

    Args:
        schema_text: Formatted schema text containing relationships, nodes, and constraints.
        question: Original natural language question.
        previous_query: The Cypher query that failed.
        error_message: The error message from Neo4j.

    Returns:
        System prompt for query refinement.
    """
    system_prompt = f"""You are an expert Neo4j Cypher query debugger. A Cypher query was generated but failed execution. Your task is to analyze the error and generate a corrected query.

DATABASE SCHEMA:
{schema_text}

ORIGINAL QUESTION:
{question}

PREVIOUS QUERY THAT FAILED:
```cypher
{previous_query}
```

EXECUTION ERROR:
{error_message}

INSTRUCTIONS:
1. Analyze the error message carefully
2. Identify the specific issue (syntax error, undefined variable, type mismatch, etc.)
3. Generate a CORRECTED Cypher query that fixes the error
4. Ensure all variables are properly defined before use
5. Maintain WITH clause variable scope - include all needed variables
6. Use exact node labels and relationship types from the schema
7. Return your corrected Cypher query inside ```cypher and ``` code blocks
8. Add a brief explanation of what was wrong and how you fixed it

COMMON ISSUES TO CHECK:
- Variables used in WITH clauses must be defined in MATCH or carried through
- COUNT(DISTINCT var) requires var to be in scope
- WITH clauses create new scopes - carry forward needed variables
- Relationship patterns must match schema direction
- Property names must exist in schema

Generate the corrected query now:
"""
    return system_prompt


def natural_language_to_cypher_with_retry(
    driver: Driver,
    database: str,
    question: str,
    execute: bool = False,
    limit: int = 25,
    include_samples: bool = False,
    max_samples: int = 5,
    describe_with_llm: bool = True,
    max_retries: int = 3,
) -> Dict[str, Any]:
    """
    Convert natural language to Cypher with automatic retry on execution errors.

    This function attempts to generate and execute a Cypher query. If execution fails,
    it feeds the error back to the LLM to generate a corrected query, up to max_retries times.

    When describe_with_llm=True (default), sample values are automatically collected
    to help generate descriptions. Use include_samples=True to also show samples in output.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        question: Natural language question about the data.
        execute: Whether to execute the generated query against the database.
        limit: Maximum number of results to return if executing query.
        include_samples: Whether to include sample values in schema context.
        max_samples: Maximum number of sample values per property.
        describe_with_llm: Whether to generate descriptions using LLM (default: True).
        max_retries: Maximum number of retry attempts on execution errors (default: 3).

    Returns:
        Dictionary containing question, generated Cypher, explanation, optional results,
        and retry history if retries occurred.
    """
    logger.info(f"Converting natural language to Cypher with up to {max_retries} retries: {question}")

    # Get schema once
    relationships = export_relationship_metadata(driver, database)
    nodes = export_node_metadata(driver, database)

    # Collect sample values if needed for LLM descriptions OR if user wants them in context
    need_samples = include_samples or describe_with_llm
    if need_samples:
        nodes = enrich_node_properties_with_samples(driver, database, nodes, max_samples)

    # Generate descriptions with LLM if requested
    descriptions = None
    if describe_with_llm:
        descriptions = generate_schema_descriptions_with_llm(nodes, relationships)

    # Build compact schema text for LLM
    rel_text = format_relationships_for_llm(relationships)
    node_text = format_nodes_for_llm(nodes, descriptions, include_samples=include_samples)
    schema_text = f"{rel_text}\n{node_text}"

    # Track retry history
    retry_history = []
    total_tokens = 0

    # Initial attempt
    attempt = 0
    result = None

    while attempt <= max_retries:
        attempt_num = attempt + 1
        logger.info(f"Attempt {attempt_num}/{max_retries + 1}")

        if attempt == 0:
            # First attempt - use normal prompt
            system_prompt = build_cypher_generation_system_prompt(schema_text)
            user_message = question
        else:
            # Retry attempt - use refinement prompt with error feedback
            previous_result = retry_history[-1]
            system_prompt = build_cypher_refinement_prompt(
                schema_text,
                question,
                previous_result["cypher"],
                previous_result["execution_error"],
            )
            user_message = "Please provide the corrected Cypher query."

        # Generate Cypher query using LLM
        logger.info("Sending request to LLM...")
        try:
            llm_response = llm_completion(user_message, system_prompt=system_prompt)
            full_response = llm_response.response
            tokens_used = llm_response.total_tokens
            total_tokens += tokens_used
            logger.info(f"LLM response received (tokens: {tokens_used})")
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            raise

        # Extract Cypher query from response
        cypher_query = extract_cypher_from_response(full_response)

        if not cypher_query:
            logger.warning("Could not extract Cypher query from LLM response")
            cypher_query = full_response

        result = {
            "question": question,
            "cypher": cypher_query,
            "full_response": full_response,
            "tokens_used": tokens_used,
            "attempt": attempt_num,
        }

        # Execute query if requested
        if execute:
            logger.info("Executing generated Cypher query...")
            try:
                with driver.session(database=database) as session:
                    query_result = session.run(cypher_query)
                    records = [dict(record) for record in query_result.fetch(limit)]
                    result["results"] = records
                    result["result_count"] = len(records)
                    logger.info(f"✅ Query executed successfully, returned {len(records)} records")

                # Success! Break out of retry loop
                break

            except Exception as e:
                error_msg = str(e)
                logger.error(f"❌ Query execution failed (attempt {attempt_num}): {error_msg}")
                result["execution_error"] = error_msg

                # Add to retry history
                retry_history.append(result.copy())

                # Check if we should retry
                if attempt < max_retries:
                    logger.info(f"Retrying with error feedback... ({max_retries - attempt} attempts remaining)")
                else:
                    logger.error(f"Max retries ({max_retries}) reached. Giving up.")
                    break

                attempt += 1
        else:
            # Not executing, so we're done
            break

    # Add retry history to final result if there were retries
    if retry_history:
        result["retry_history"] = retry_history
        result["total_attempts"] = len(retry_history) + 1
        result["total_tokens_used"] = total_tokens
        # Update tokens_used to show cumulative
        result["tokens_used"] = total_tokens

    return result


def natural_language_to_cypher(
    driver: Driver,
    database: str,
    question: str,
    execute: bool = False,
    limit: int = 25,
    include_samples: bool = False,
    max_samples: int = 5,
    describe_with_llm: bool = True,
) -> Dict[str, Any]:
    """
    Convert natural language question to Cypher query using LLM.

    When describe_with_llm=True (default), sample values are automatically collected
    to help generate descriptions. Use include_samples=True to also show samples in output.

    Args:
        driver: Neo4j driver instance.
        database: Target database name.
        question: Natural language question about the data.
        execute: Whether to execute the generated query against the database.
        limit: Maximum number of results to return if executing query.
        include_samples: Whether to include sample values in schema context.
        max_samples: Maximum number of sample values per property.
        describe_with_llm: Whether to generate descriptions using LLM (default: True).

    Returns:
        Dictionary containing question, generated Cypher, explanation, and optional results.
    """
    logger.info(f"Converting natural language to Cypher: {question}")

    # Get schema
    relationships = export_relationship_metadata(driver, database)
    nodes = export_node_metadata(driver, database)

    # Collect sample values if needed for LLM descriptions OR if user wants them in context
    need_samples = include_samples or describe_with_llm
    if need_samples:
        nodes = enrich_node_properties_with_samples(driver, database, nodes, max_samples)

    # Generate descriptions with LLM if requested
    descriptions = None
    if describe_with_llm:
        descriptions = generate_schema_descriptions_with_llm(nodes, relationships)

    # Build compact schema text for LLM
    rel_text = format_relationships_for_llm(relationships)
    node_text = format_nodes_for_llm(nodes, descriptions, include_samples=include_samples)
    schema_text = f"{rel_text}\n{node_text}"

    # Build system prompt
    system_prompt = build_cypher_generation_system_prompt(schema_text)

    # Generate Cypher query using LLM
    logger.info("Sending request to LLM...")
    try:
        llm_response = llm_completion(question, system_prompt=system_prompt)
        full_response = llm_response.response
        logger.info(f"LLM response received (tokens: {llm_response.total_tokens})")
    except Exception as e:
        logger.error(f"LLM request failed: {e}")
        raise

    # Extract Cypher query from response
    cypher_query = extract_cypher_from_response(full_response)

    if not cypher_query:
        logger.warning("Could not extract Cypher query from LLM response")
        cypher_query = full_response

    result = {
        "question": question,
        "cypher": cypher_query,
        "full_response": full_response,
        "tokens_used": llm_response.total_tokens,
    }

    # Execute query if requested
    if execute:
        logger.info("Executing generated Cypher query...")
        try:
            with driver.session(database=database) as session:
                query_result = session.run(cypher_query)
                records = [dict(record) for record in query_result.fetch(limit)]
                result["results"] = records
                result["result_count"] = len(records)
                logger.info(f"Query executed successfully, returned {len(records)} records")
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            result["execution_error"] = str(e)

    return result


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Export Neo4j schema and convert natural language to Cypher queries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export schema to stdout (text format)
  python -m lab_common.binql.nl2gql

  # Export to file with prompt template
  python -m lab_common.binql.nl2gql --output schema.txt --prompt-template

  # Convert natural language to Cypher and execute (default)
  python -m lab_common.binql.nl2gql --query "Find all malware binaries"

  # Generate Cypher without executing
  python -m lab_common.binql.nl2gql --query "Show me functions that call printf" --no-execute

  # Limit results when executing
  python -m lab_common.binql.nl2gql --query "List all binaries" --limit 10

  # Use custom database connection
  python -m lab_common.binql.nl2gql --uri bolt://localhost:7687 --user neo4j --password mypass --db mydb
        """,
    )

    parser.add_argument(
        "--uri",
        default=DEFAULT_URI,
        help=f"Neo4j connection URI (default: {DEFAULT_URI})",
    )
    parser.add_argument(
        "--user",
        default=DEFAULT_USER,
        help=f"Neo4j username (default: {DEFAULT_USER})",
    )
    parser.add_argument(
        "--password",
        default=DEFAULT_PASSWORD,
        help=f"Neo4j password (default: {DEFAULT_PASSWORD})",
    )
    parser.add_argument(
        "--db",
        "--database",
        dest="database",
        default=DEFAULT_DATABASE,
        help=f"Target database name (default: {DEFAULT_DATABASE})",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path (default: print to stdout)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "both"],
        default="text",
        help="Output format: text (LLM-friendly), json, or both (default: text)",
    )
    parser.add_argument(
        "--prompt-template",
        action="store_true",
        help="Include LLM prompt template in text output",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Disable schema enrichment with sample values",
    )
    parser.add_argument(
        "--no-describe",
        action="store_true",
        help="Disable LLM-generated descriptions (LLM descriptions are enabled by default)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=5,
        help="Maximum number of sample values to collect per property (default: 5)",
    )
    parser.add_argument(
        "--query",
        "-q",
        type=str,
        help="Natural language question to convert to Cypher query (executes by default)",
    )
    parser.add_argument(
        "--no-execute",
        action="store_true",
        help="Do not execute the generated Cypher query (only generate and display it)",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=25,
        help="Maximum number of results to return when executing query (default: 25)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum number of retry attempts when query execution fails (default: 3)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point for nl2gql schema exporter."""
    args = parse_arguments()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Connect to Neo4j
    logger.info(f"Connecting to Neo4j at {args.uri}")
    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))

    try:
        # Handle natural language to Cypher conversion
        if args.query:
            # Default to execute unless --no-execute is specified
            should_execute = not args.no_execute
            # Default to enrich unless --no-enrich is specified
            should_enrich = not args.no_enrich

            logger.info("Natural language to Cypher mode")
            # Default to describe unless --no-describe is specified
            should_describe = not args.no_describe

            result = natural_language_to_cypher_with_retry(
                driver=driver,
                database=args.database,
                question=args.query,
                execute=should_execute,
                limit=args.limit,
                enrich_with_samples=should_enrich,
                max_samples=args.max_samples,
                describe_with_llm=should_describe,
                max_retries=args.max_retries,
            )

            # Display results
            print("\n" + "=" * 100)
            print("NATURAL LANGUAGE TO CYPHER")
            print("=" * 100)
            print(f"\nQuestion: {result['question']}")

            # Show retry history if there were retries
            if "retry_history" in result:
                print(f"\n⚠️  Query required {result['total_attempts']} attempts")
                print("\n" + "=" * 100)
                print("RETRY HISTORY")
                print("=" * 100)
                for i, retry in enumerate(result['retry_history'], 1):
                    print(f"\n--- Attempt {i} ---")
                    print(f"Generated Cypher:")
                    print("-" * 100)
                    print(retry['cypher'])
                    print("-" * 100)
                    print(f"❌ Error: {retry['execution_error']}")
                    print(f"Tokens: {retry['tokens_used']}")

                print("\n" + "=" * 100)
                print(f"FINAL ATTEMPT (Attempt {result['total_attempts']})")
                print("=" * 100)

            print("\nGenerated Cypher:")
            print("-" * 100)
            print(result['cypher'])
            print("-" * 100)

            if should_execute:
                if "execution_error" in result:
                    print(f"\n❌ Execution Error: {result['execution_error']}")
                    if "retry_history" in result:
                        print(f"\n⚠️  Failed after {result['total_attempts']} attempts")
                else:
                    print(f"\n✅ Query executed successfully!")
                    if "retry_history" in result:
                        print(f"✨ Success on attempt {result['total_attempts']}")
                    print(f"Results ({result['result_count']} records):")
                    print("-" * 100)
                    for i, record in enumerate(result['results'], 1):
                        print(f"{i}. {json.dumps(record, indent=2, default=str)}")

            print(f"\nTokens used: {result['tokens_used']}")
            print("=" * 100)

        # Handle schema export
        else:
            # Default to enrich unless --no-enrich is specified
            should_enrich = not args.no_enrich
            # Default to describe unless --no-describe is specified
            should_describe = not args.no_describe

            export_schema(
                driver=driver,
                database=args.database,
                output_file=args.output,
                format_type=args.format,
                include_prompt_template=args.prompt_template,
                enrich_with_samples=should_enrich,
                max_samples=args.max_samples,
                describe_with_llm=should_describe,
            )

            logger.info("Schema export completed successfully")

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        raise
    finally:
        driver.close()
        logger.debug("Neo4j connection closed")


if __name__ == "__main__":
    module_name = Path(__file__).stem

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Override the logger to use the file name
    logger = logging.getLogger(module_name)

    main()
