"""
Lab 3.1: User-Controlled Input Detection Module.

This module provides functions to detect user-controlled input sources in binaries
using graph-based queries. Each function queries Neo4j for specific input source
categories (network, file, stdin, environment, IPC, command-line) that are
reachable from function entry points.

The module uses a **base query pattern** to avoid repetition:
1. `_detect_input_source_base()` - Contains the CFG reachability query (students implement once)
2. `detect_*()` functions - Call the base function with their specific API list (students implement)

Students implement the base query once, then implement each specialized function
as a one-liner that calls the base with the appropriate API list.

Usage (Students):
    source venv/bin/activate
    python -m student_labs.lab3.user_input_detection --help

    # Run all input source detection queries
    python -m student_labs.lab3.user_input_detection --all

    # Run specific input source query
    python -m student_labs.lab3.user_input_detection --network
    python -m student_labs.lab3.user_input_detection --file

Usage (Instructors Only):
    # Run with reference implementation using USE_REFERENCE=1
    source venv/bin/activate
    USE_REFERENCE=1 python -m student_labs.lab3.user_input_detection --all

NOTE: The USE_REFERENCE=1 environment variable is for INSTRUCTORS ONLY.
      It requires access to the `labs/` folder which contains the reference
      implementations. Students do not have access to this folder, so using
      USE_REFERENCE=1 will result in an ImportError. Students should fill in
      the query placeholders marked with "### YOUR CODE HERE ###" instead.

Reference: docs/labs/lab3/lab_3_1_user_input_detection.md
"""

import argparse
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from neo4j import Driver, GraphDatabase

from lab_common.binql import get_neo4j_credentials

logger = logging.getLogger(__name__)

# Check if we should use reference implementation
_USE_REFERENCE = os.environ.get("USE_REFERENCE", "").lower() in ("1", "true", "yes")

if _USE_REFERENCE:
    # Import reference implementations to use as fallback
    from labs.lab3 import user_input_detection_reference as _ref
    logger.info("Using reference implementation for user_input_detection")


@dataclass
class InputSourceResult:
    """Result from an input source detection query."""

    binary: str
    function: str
    address: Optional[str] = None
    apis: List[str] = field(default_factory=list)
    count: int = 0


@dataclass
class UserInputSourceDetail:
    """
    Detailed information about a user-controlled input API call.

    This dataclass provides granular information about each API call site,
    including the basic block address where the call occurs. This is useful
    for Lab 3.2 source-to-sink analysis where you need to know exactly
    where input enters the program.
    """

    binary: str
    sha256: str
    function: str
    function_address: str
    api_name: str
    basic_block_address: str
    input_category: str  # network, file, stdin, environment, ipc, cmdline


def run_query(driver: Driver, database: str, query: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Execute a Cypher query and return results as a list of dictionaries.

    This is a helper function that students can use to execute their queries
    and get structured results back for further processing.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        query: Cypher query string to execute.
        limit: Maximum number of results (0 = no limit).

    Returns:
        List of dictionaries, where each dictionary represents a row with
        column names as keys.

    Example:
        >>> results = run_query(driver, "neo4j", "MATCH (b:Binary) RETURN b.name AS name")
        >>> for row in results:
        ...     print(row["name"])
    """
    if _USE_REFERENCE:
        return _ref.run_query(driver, database, query, limit)

    # Add LIMIT clause if not already present and limit > 0
    query_upper = query.upper().strip()
    if limit > 0 and "LIMIT" not in query_upper:
        query = f"{query.rstrip().rstrip(';')} LIMIT {limit}"

    with driver.session(database=database) as session:
        result = session.run(query)
        records = list(result)
        keys = result.keys() if records else []

        # Convert Neo4j records to plain dictionaries
        output = []
        for record in records:
            row = {}
            for key in keys:
                value = record.get(key)
                # Convert Neo4j types to Python types
                if hasattr(value, "__iter__") and not isinstance(value, (str, dict)):
                    value = list(value)
                row[key] = value
            output.append(row)

        return output


# =============================================================================
# API Lists for User-Controlled Input Detection
# =============================================================================
# These lists define the APIs to search for in each input source category.
# Students can customize these lists or add new categories.

NETWORK_INPUT_APIS = [
    # BSD sockets
    "recv", "recvfrom", "recvmsg", "read", "readv",
    # Windows sockets
    "WSARecv", "WSARecvFrom", "WSARecvMsg",
    # Windows HTTP (WinINet)
    "InternetReadFile", "InternetReadFileEx",
    # Windows HTTP Server
    "HttpReceiveHttpRequest", "HttpReceiveRequestEntityBody",
    # Windows HTTP (WinHTTP)
    "WinHttpReadData", "WinHttpReceiveResponse",
    # SSL/TLS libraries
    "PR_Read", "PR_Recv", "SSL_read", "BIO_read",
]

FILE_INPUT_APIS = [
    # C standard library
    "fread", "fgets", "fgetc", "fgetws", "fgetwc",
    # POSIX I/O
    "read", "pread", "pread64", "readv", "preadv",
    # Windows file I/O
    "ReadFile", "ReadFileEx", "ReadFileScatter",
    # NT native
    "NtReadFile", "ZwReadFile",
    # Memory mapping
    "mmap", "MapViewOfFile", "MapViewOfFileEx",
]

STDIN_INPUT_APIS = [
    # Formatted input
    "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
    # Line input
    "gets", "fgets", "getchar", "getc", "ungetc",
    # Wide character input
    "getwchar", "fgetws", "fgetwc",
    # Windows console
    "ReadConsoleA", "ReadConsoleW", "ReadConsoleInputA", "ReadConsoleInputW",
    "GetStdHandle", "_getch", "_getche", "_getwch", "_getwche",
]

ENVIRONMENT_INPUT_APIS = [
    # POSIX
    "getenv", "getenv_s", "_wgetenv", "_wgetenv_s",
    "secure_getenv", "__secure_getenv",
    # Windows
    "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "GetEnvironmentStringsA", "GetEnvironmentStringsW",
    "ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW",
]

IPC_INPUT_APIS = [
    # POSIX message queues
    "msgrcv", "mq_receive", "mq_timedreceive",
    # Shared memory
    "shmat", "shmget", "shmctl",
    # Named pipes (Windows)
    "ReadFile", "PeekNamedPipe", "TransactNamedPipe",
    # File mapping
    "CreateFileMappingA", "CreateFileMappingW", "OpenFileMappingA", "OpenFileMappingW",
    "MapViewOfFile", "MapViewOfFileEx",
    # RPC
    "RpcServerListen", "RpcBindingFromStringBindingA", "NdrServerCall2",
    # DDE
    "DdeConnect", "DdeClientTransaction",
    # COM
    "CoCreateInstance", "CoGetClassObject",
]

CMDLINE_INPUT_APIS = [
    # POSIX option parsing
    "getopt", "getopt_long", "getopt_long_only",
    # GNU argp
    "argp_parse",
    # popt library
    "poptGetContext", "poptGetNextOpt",
    # Windows
    "CommandLineToArgvW", "GetCommandLineA", "GetCommandLineW",
    # CRT initialization
    "__getmainargs", "__wgetmainargs",
    # Path utilities
    "PathGetArgsA", "PathGetArgsW",
]


# =============================================================================
# Helper Function for Converting Query Results to InputSourceResult
# =============================================================================

def _convert_to_input_source_results(
    rows: List[Dict[str, Any]],
    api_field: str = "input_apis",
) -> List[InputSourceResult]:
    """
    Convert query result rows to InputSourceResult objects.

    This helper handles the common conversion pattern used by all input
    detection functions. Students don't need to modify this.

    Args:
        rows: List of dictionaries from run_query().
        api_field: Name of the field containing API list (default: "input_apis").

    Returns:
        List of InputSourceResult objects.
    """
    results = []
    for row in rows:
        results.append(InputSourceResult(
            binary=row.get("binary", ""),
            function=row.get("function", ""),
            address=hex(row["address"]) if row.get("address") else None,
            apis=row.get(api_field, []) if api_field in row else [],
            count=row.get("api_count", 0),
        ))
    return results


# =============================================================================
# Base Query Function - Students Implement the Query Here (ONCE)
# =============================================================================


def _detect_input_source_base(
    driver: Driver,
    database: str,
    api_list: List[str],
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Base function for detecting input sources using CFG reachability.

    This function contains the core Cypher query that finds functions with
    reachable input-related imports. All specialized detection functions
    (detect_network_input, detect_file_input, etc.) call this base function
    with their specific API list.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        api_list: List of API names to search for.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects containing:
        - binary: Binary name/hash
        - function: Function name
        - address: Function start address (hex)
        - apis: List of input APIs found
        - count: Number of distinct APIs

    Example:
        >>> results = _detect_input_source_base(driver, "neo4j", ["recv", "read"])
        >>> for r in results:
        ...     print(f"{r.binary}: {r.function} uses {r.apis}")
    """
    if _USE_REFERENCE:
        return _ref._detect_input_source_base(driver, database, api_list, limit)

    # Build the API list string for the query
    api_list_str = ", ".join(f"'{api}'" for api in api_list)

    # =========================================================================
    # STUDENTS: Paste your Cypher query below (between the triple quotes)
    # This is the CFG reachability query that finds functions with reachable
    # input-related imports. You only need to implement this ONCE - all the
    # specialized detection functions will call this base function.
    #
    # Use {api_list_str} where you need the list of APIs.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Write a Cypher query that finds functions with reachable input-related imports.
    # Use {api_list_str} where you need the list of APIs.
    query = ""
    ### END YOUR CODE HERE ###

    # Execute query and convert results
    rows = run_query(driver, database, query, limit)
    return _convert_to_input_source_results(rows, api_field="input_apis")


# =============================================================================
# Specialized Detection Functions - Students Call Base Function Here
# =============================================================================


def detect_network_input(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Detect network input sources in binaries.

    Find functions that receive data from network connections (sockets, HTTP).
    These are entry points for remote attacker-controlled data.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects with network input APIs.
    """
    if _USE_REFERENCE:
        return _ref.detect_network_input(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the API list and call _detect_input_source_base()
    # Copy this entire block including the api_list definition.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define api_list with network input APIs and call _detect_input_source_base.
    pass
    ### END YOUR CODE HERE ###


def detect_file_input(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Detect file input sources in binaries.

    Find functions that read data from files. File input is a major attack
    vector for document parsers, configuration handlers, and archive processors.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects with file input APIs.
    """
    if _USE_REFERENCE:
        return _ref.detect_file_input(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the API list and call _detect_input_source_base()
    # Copy this entire block including the api_list definition.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define api_list with file input APIs and call _detect_input_source_base.
    pass
    ### END YOUR CODE HERE ###


def detect_stdin_input(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Detect standard input sources in binaries.

    Find functions that read from stdin or console. These are entry points
    for user-controlled data in interactive applications and piped input.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects with stdin input APIs.
    """
    if _USE_REFERENCE:
        return _ref.detect_stdin_input(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the API list and call _detect_input_source_base()
    # Copy this entire block including the api_list definition.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define api_list with stdin input APIs and call _detect_input_source_base.
    pass
    ### END YOUR CODE HERE ###


def detect_environment_input(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Detect environment variable input sources in binaries.

    Find functions that read environment variables. Environment input is
    attacker-controlled in many contexts (web servers, SUID binaries).

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects with environment input APIs.
    """
    if _USE_REFERENCE:
        return _ref.detect_environment_input(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the API list and call _detect_input_source_base()
    # Copy this entire block including the api_list definition.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define api_list with environment variable APIs and call _detect_input_source_base.
    pass
    ### END YOUR CODE HERE ###


def detect_ipc_input(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Detect IPC (Inter-Process Communication) input sources in binaries.

    Find functions that receive data via IPC mechanisms (message queues,
    shared memory, pipes, RPC, COM). IPC input can be attacker-controlled
    in multi-process applications and service architectures.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects with IPC input APIs.
    """
    if _USE_REFERENCE:
        return _ref.detect_ipc_input(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the API list and call _detect_input_source_base()
    # Copy this entire block including the api_list definition.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define api_list with IPC input APIs and call _detect_input_source_base.
    pass
    ### END YOUR CODE HERE ###


def detect_cmdline_input(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> List[InputSourceResult]:
    """
    Detect command-line argument input sources in binaries.

    Find functions that process command-line arguments. Command-line input
    is fully attacker-controlled in SUID binaries and subprocess invocations.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum number of results.

    Returns:
        List of InputSourceResult objects with command-line input APIs.
    """
    if _USE_REFERENCE:
        return _ref.detect_cmdline_input(driver, database, limit)

    # =========================================================================
    # STUDENTS: Define the API list and call _detect_input_source_base()
    # Copy this entire block including the api_list definition.
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Define api_list with command-line argument APIs and call _detect_input_source_base.
    pass
    ### END YOUR CODE HERE ###


# =============================================================================
# Binary-Specific User Input Source Detection
# =============================================================================


def get_user_input_sources_for_binary(
    driver: Driver,
    database: str,
    sha256: str,
    include_llm_classification: bool = True,
    limit: int = 500,
) -> List[UserInputSourceDetail]:
    """
    Get detailed user-controlled input source information for a specific binary.

    This function combines the results from the 6 detection functions (network,
    file, stdin, environment, IPC, command-line) and optionally uses LLM
    classification to discover additional user-input APIs not in the hardcoded lists.

    The function returns granular information about each API call site where
    user-controlled input enters the program, including the basic block address
    where the call occurs. This is designed for use by Lab 3.2 source-to-sink
    analysis.

    NOTE: This function is PROVIDED - students do not need to implement it.
    It leverages the detection functions you implemented above.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to analyze.
        include_llm_classification: If True, use LLM to classify unknown APIs
            and include any additional user-input sources discovered.
        limit: Maximum number of results (default: 500).

    Returns:
        List of UserInputSourceDetail objects, each containing:
        - binary: Binary name
        - sha256: Binary SHA256 hash
        - function: Function name containing the API call
        - function_address: Function start address (hex)
        - api_name: Name of the user-input API
        - basic_block_address: Address of the basic block where the call occurs (hex)
        - input_category: Category of input (network, file, stdin, environment, ipc, cmdline)

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.

    Example:
        >>> sources = get_user_input_sources_for_binary(driver, "neo4j", "abc123...")
        >>> for src in sources:
        ...     print(f"{src.function} calls {src.api_name} at BB {src.basic_block_address}")
    """
    if _USE_REFERENCE:
        return _ref.get_user_input_sources_for_binary(driver, database, sha256, include_llm_classification, limit)

    # Check if binary exists first
    check_query = "MATCH (b:Binary) WHERE b.sha256 = $sha256 RETURN b.name AS name"
    with driver.session(database=database) as session:
        check_result = session.run(check_query, {"sha256": sha256})
        record = check_result.single()
        if record is None:
            raise ValueError(f"No binary found with SHA256: {sha256}")

    # Step 1: Build API-to-category mapping from the hardcoded lists
    # These are the same lists used by the detection functions
    known_api_categories = {
        "network": NETWORK_INPUT_APIS,
        "file": FILE_INPUT_APIS,
        "stdin": STDIN_INPUT_APIS,
        "environment": ENVIRONMENT_INPUT_APIS,
        "ipc": IPC_INPUT_APIS,
        "cmdline": CMDLINE_INPUT_APIS,
    }

    api_to_category = {}
    for category, apis in known_api_categories.items():
        for api in apis:
            if api not in api_to_category:
                api_to_category[api] = category

    # Step 2: If LLM classification is enabled, get all APIs from the binary
    # and classify unknown ones to discover additional user-input sources
    if include_llm_classification:
        try:
            all_binary_apis = get_binary_apis(driver, database, sha256)
            unknown_apis = [api for api in all_binary_apis if api not in api_to_category]

            if unknown_apis:
                logger.info(f"Classifying {len(unknown_apis)} unknown APIs with LLM...")
                llm_results = classify_apis_batch_with_llm(unknown_apis, batch_size=20)

                # Add LLM-classified user-input APIs to our mapping
                for result in llm_results:
                    if result.get("is_user_input", False):
                        api_name = result.get("api", "")
                        category = result.get("input_category", "other")
                        if api_name and api_name not in api_to_category:
                            api_to_category[api_name] = category
                            logger.info(f"LLM discovered user-input API: {api_name} ({category})")
        except Exception as e:
            logger.warning(f"LLM classification failed, using only hardcoded APIs: {e}")

    # Step 3: Query for detailed per-call-site information with basic block addresses
    all_apis = list(api_to_category.keys())
    api_list_str = ", ".join(f"'{api}'" for api in all_apis)

    query = f"""
    MATCH (b:Binary)-[:HAS_FUNCTION]->(f:Function)-[:ENTRY_BLOCK]->(entry:BasicBlock)
    WHERE b.sha256 = $sha256
    MATCH (entry)-[:BRANCHES_TO*0..20]->(bb:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE imp.name IN [{api_list_str}]
    RETURN DISTINCT
        b.name AS binary,
        b.sha256 AS sha256,
        f.name AS function,
        f.start_address AS function_address,
        imp.name AS api_name,
        bb.start_address AS basic_block_address
    ORDER BY function, basic_block_address
    """

    # Execute the main query
    with driver.session(database=database) as session:
        result = session.run(query, {"sha256": sha256})
        records = list(result)

    # Step 4: Convert to UserInputSourceDetail objects
    results = []
    for record in records[:limit]:
        api_name = record["api_name"]
        category = api_to_category.get(api_name, "unknown")

        func_addr = record["function_address"]
        bb_addr = record["basic_block_address"]

        results.append(UserInputSourceDetail(
            binary=record["binary"],
            sha256=record["sha256"],
            function=record["function"],
            function_address=hex(func_addr) if func_addr else "0x0",
            api_name=api_name,
            basic_block_address=hex(bb_addr) if bb_addr else "0x0",
            input_category=category,
        ))

    return results


# =============================================================================
# Aggregation Functions
# =============================================================================


def get_all_input_sources(
    driver: Driver,
    database: str,
    limit: int = 100,
) -> Dict[str, List[InputSourceResult]]:
    """
    Run all input source detection queries and return combined results.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        limit: Maximum results per category.

    Returns:
        Dictionary mapping category names to lists of InputSourceResult objects.
    """
    return {
        "network": detect_network_input(driver, database, limit),
        "file": detect_file_input(driver, database, limit),
        "stdin": detect_stdin_input(driver, database, limit),
        "environment": detect_environment_input(driver, database, limit),
        "ipc": detect_ipc_input(driver, database, limit),
        "cmdline": detect_cmdline_input(driver, database, limit),
    }


def get_high_risk_functions(
    driver: Driver,
    database: str,
    min_categories: int = 2,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Find functions that accept input from multiple source categories.

    Functions that receive input from multiple sources (e.g., both network
    and file) are higher-risk targets because they have more attack surface.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        min_categories: Minimum number of input categories to be considered high-risk.
        limit: Maximum number of results.

    Returns:
        List of dictionaries with function info and their input categories.
    """
    all_results = get_all_input_sources(driver, database, limit=0)

    # Build a map of (binary, function) -> set of categories
    function_categories: Dict[tuple, Dict[str, Any]] = {}

    for category, results in all_results.items():
        for result in results:
            key = (result.binary, result.function)
            if key not in function_categories:
                function_categories[key] = {
                    "binary": result.binary,
                    "function": result.function,
                    "address": result.address,
                    "categories": set(),
                    "all_apis": [],
                }
            function_categories[key]["categories"].add(category)
            function_categories[key]["all_apis"].extend(result.apis)

    # Filter to functions with multiple categories
    high_risk = []
    for func_info in function_categories.values():
        if len(func_info["categories"]) >= min_categories:
            high_risk.append({
                "binary": func_info["binary"],
                "function": func_info["function"],
                "address": func_info["address"],
                "categories": sorted(func_info["categories"]),
                "category_count": len(func_info["categories"]),
                "apis": list(set(func_info["all_apis"])),
            })

    # Sort by category count descending
    high_risk.sort(key=lambda x: (-x["category_count"], x["binary"], x["function"]))

    return high_risk[:limit] if limit > 0 else high_risk


# =============================================================================
# LLM-Based API Classification
# =============================================================================


def get_binary_apis(driver: Driver, database: str, sha256: str) -> List[str]:
    """
    Extract all unique API names (ImportSymbols) from a binary in the database.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to scan.

    Returns:
        List of unique API names found in the binary.

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.
    """
    query = """
    MATCH (b:Binary)-[:HAS_FUNCTION]->(:Function)-[:ENTRY_BLOCK]->(:BasicBlock)
          -[:BRANCHES_TO*0..20]->(:BasicBlock)-[:CALLS_TO]->(imp:ImportSymbol)
    WHERE b.sha256 = $sha256
    RETURN DISTINCT imp.name AS api
    ORDER BY api
    """
    params = {"sha256": sha256}

    with driver.session(database=database) as session:
        result = session.run(query, params)
        apis = [record["api"] for record in result]

    if not apis:
        # Check if the binary exists at all
        check_query = "MATCH (b:Binary) WHERE b.sha256 = $sha256 RETURN b.name AS name"
        with driver.session(database=database) as session:
            check_result = session.run(check_query, params)
            record = check_result.single()
            if record is None:
                raise ValueError(f"No binary found with SHA256: {sha256}")

    return apis


def classify_api_with_llm(api_name: str) -> Dict[str, Any]:
    """
    Use LLM to classify an API and determine if it's a user-controlled input source.

    This function sends the API name to an LLM with a system prompt that instructs
    it to return a JSON classification. Students implement the system prompt and
    LLM call logic.

    Args:
        api_name: The name of the API to classify.

    Returns:
        Dictionary with classification results:
        - api: The API name
        - is_user_input: Boolean indicating if this API accepts user-controlled input
        - input_category: Category if user input (network, file, stdin, environment, ipc, cmdline, other)
        - confidence: Confidence level (high, medium, low)
        - description: Brief description of what this API does
        - security_notes: Security considerations for this API

    Example:
        >>> result = classify_api_with_llm("recv")
        >>> print(result["is_user_input"])  # True
        >>> print(result["input_category"])  # "network"
    """
    if _USE_REFERENCE:
        return _ref.classify_api_with_llm(api_name)

    from lab_common.llm.client import llm_completion
    import json

    # =========================================================================
    # STUDENTS: Implement the LLM-based API classification.
    #
    # 1. Define a system_prompt that instructs the LLM to:
    #    - Analyze the API name and determine if it accepts user-controlled input
    #    - Return ONLY valid JSON (no markdown, no extra text)
    #    - Use this schema:
    #      {
    #        "api": "<api name>",
    #        "is_user_input": <true/false>,
    #        "input_category": "<network|file|stdin|environment|ipc|cmdline|other|none>",
    #        "confidence": "<high|medium|low>",
    #        "description": "<brief description>",
    #        "security_notes": "<security considerations>"
    #      }
    #
    # 2. Create a prompt that asks the LLM to classify the given api_name
    #
    # 3. Call llm_completion(prompt, system_prompt=system_prompt)
    #
    # 4. Parse the JSON response and return it
    #
    # 5. Handle errors gracefully (JSONDecodeError, other exceptions)
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Use LLM to classify the API as a user-controlled input source.
    # Return a dictionary with classification results.
    pass
    ### END YOUR CODE HERE ###


def classify_apis_batch_with_llm(
    api_names: List[str],
    batch_size: int = 20,
) -> List[Dict[str, Any]]:
    """
    Classify multiple APIs in batches to reduce LLM calls.

    This function processes APIs in batches to improve efficiency when classifying
    many APIs. Each batch is sent to the LLM in a single call, reducing latency
    and token overhead from repeated system prompts.

    Args:
        api_names: List of API names to classify.
        batch_size: Maximum APIs per LLM call (default: 20). Smaller batches are
                    more reliable but slower. Larger batches risk truncation.

    Returns:
        List of classification results for each API. Each result contains:
        - api: The API name
        - is_user_input: Boolean indicating if this API accepts user-controlled input
        - input_category: Category (network, file, stdin, environment, ipc, cmdline, other, none)
        - confidence: Confidence level (high, medium, low)
        - description: Brief description of what the API does
        - security_notes: Security considerations for this API

    Example:
        >>> results = classify_apis_batch_with_llm(["recv", "fread", "getenv"])
        >>> for r in results:
        ...     print(f"{r['api']}: {r['input_category']} ({r['confidence']})")
    """
    if _USE_REFERENCE:
        return _ref.classify_apis_batch_with_llm(api_names, batch_size)

    from lab_common.llm.client import llm_completion
    import json

    if not api_names:
        return []

    all_results = []

    # =========================================================================
    # STUDENTS: Implement batch API classification.
    #
    # Process APIs in batches of `batch_size` to reduce LLM calls.
    # For each batch:
    #
    # 1. Define a system_prompt that instructs the LLM to:
    #    - Analyze multiple API names and classify each one
    #    - Return ONLY a valid JSON array (no markdown, no extra text)
    #    - Each element should follow this schema:
    #      {
    #        "api": "<api name>",
    #        "is_user_input": <true/false>,
    #        "input_category": "<network|file|stdin|environment|ipc|cmdline|other|none>",
    #        "confidence": "<high|medium|low>",
    #        "description": "<brief description>",
    #        "security_notes": "<security considerations>"
    #      }
    #
    # 2. Create a prompt listing the APIs in the current batch
    #
    # 3. Call llm_completion(prompt, system_prompt=system_prompt)
    #
    # 4. Parse the JSON array response and extend all_results
    #
    # 5. Handle errors gracefully - on failure, fall back to classifying
    #    each API individually using classify_api_with_llm()
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Process APIs in batches and classify each using LLM.
    # Return a list of classification results.
    pass
    ### END YOUR CODE HERE ###


def classify_binary_apis_with_llm(
    driver: Driver,
    database: str,
    sha256: str,
    filter_user_input: bool = True,
    batch_size: int = 20,
) -> List[Dict[str, Any]]:
    """
    Extract all APIs from a binary and classify them using LLM.

    This function scans a binary (identified by SHA256) for all its API calls,
    then uses an LLM to classify each API and determine if it's a potential
    user-controlled input source. APIs are processed in batches for efficiency.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to scan (must be ingested in database).
        filter_user_input: If True, only return APIs classified as user input sources.
        batch_size: Maximum APIs per LLM call (default: 20).

    Returns:
        List of classification results for each API.

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.
    """
    if _USE_REFERENCE:
        return _ref.classify_binary_apis_with_llm(driver, database, sha256, filter_user_input, batch_size)

    apis = get_binary_apis(driver, database, sha256)
    logger.info(f"Found {len(apis)} unique APIs to classify for binary {sha256[:16]}...")

    # Use batch classification for efficiency
    all_results = classify_apis_batch_with_llm(apis, batch_size=batch_size)

    # Filter to user input sources if requested
    if filter_user_input:
        return [r for r in all_results if r.get("is_user_input", False)]

    return all_results


def get_binary_info(driver: Driver, database: str, sha256: str) -> Dict[str, Any]:
    """
    Get binary metadata from the database.

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary.

    Returns:
        Dictionary with binary metadata (name, sha256, function_count).
    """
    if _USE_REFERENCE:
        return _ref.get_binary_info(driver, database, sha256)

    query = """
    MATCH (b:Binary)
    WHERE b.sha256 = $sha256
    OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(f:Function)
    RETURN b.name AS name, b.sha256 AS sha256, count(f) AS function_count
    """
    with driver.session(database=database) as session:
        result = session.run(query, {"sha256": sha256})
        record = result.single()
        if record:
            return {
                "name": record["name"],
                "sha256": record["sha256"],
                "function_count": record["function_count"],
            }
        return {"name": "Unknown", "sha256": sha256, "function_count": 0}


def generate_scan_report(
    driver: Driver,
    database: str,
    sha256: str,
    output_path: Optional[str] = None,
    include_llm_classification: bool = True,
) -> str:
    """
    Generate a markdown report for a binary's user-controlled input sources.

    This function uses get_user_input_sources_for_binary() to find all user-input
    API call sites, then generates a comprehensive markdown report with:
    - Binary metadata
    - User-input sources grouped by category with call-site details
    - LLM-generated executive summary and security analysis
    - Recommendations for further analysis

    Args:
        driver: Neo4j driver instance.
        database: Database name.
        sha256: SHA256 hash of the binary to scan.
        output_path: Optional path to write the markdown report. If None, returns the report string.
        include_llm_classification: If True, use LLM to discover additional input sources.

    Returns:
        The markdown report as a string.

    Raises:
        ValueError: If no binary with the given SHA256 is found in the database.

    Example:
        >>> report = generate_scan_report(driver, "neo4j", "abc123...", "report.md")
        >>> print(f"Report saved to report.md")
    """
    if _USE_REFERENCE:
        return _ref.generate_scan_report(driver, database, sha256, output_path, include_llm_classification)

    from lab_common.llm.client import llm_completion
    from datetime import datetime
    import json

    # =========================================================================
    # STUDENTS: Implement the report generation logic.
    #
    # This function should:
    # 1. Get binary info using get_binary_info()
    # 2. Call get_user_input_sources_for_binary() to get user-input sources
    # 3. Group sources by category
    # 4. Use LLM to generate executive summary and security analysis
    # 5. Build markdown report with all sections
    # 6. Write to file if output_path is specified
    # 7. Return the report string
    # =========================================================================
    ### YOUR CODE HERE ###
    # TODO: Implement this function
    # Generate a markdown report for the binary's user-input sources.
    # See the comments above for the required steps.
    pass
    ### END YOUR CODE HERE ###


def print_llm_classification_results(results: List[Dict[str, Any]]) -> None:
    """Print LLM classification results in a formatted table."""
    print(f"\n{'=' * 80}")
    print(f"  LLM API CLASSIFICATION RESULTS ({len(results)} APIs)")
    print(f"{'=' * 80}")

    if not results:
        print("  No user-input APIs found.")
        return

    # Group by category
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        cat = r.get("input_category", "unknown")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(r)

    for category in sorted(by_category.keys()):
        apis = by_category[category]
        print(f"\n  [{category.upper()}] ({len(apis)} APIs)")
        print(f"  {'-' * 40}")
        for api in apis:
            confidence = api.get("confidence", "?")
            desc = api.get("description", "")[:50]
            print(f"    {api['api']:<30} [{confidence}] {desc}")


# =============================================================================
# CLI and Output Functions
# =============================================================================


def print_results(category: str, results: List[InputSourceResult]) -> None:
    """Print results for a single category."""
    print(f"\n{'=' * 60}")
    print(f"  {category.upper()} INPUT SOURCES ({len(results)} results)")
    print(f"{'=' * 60}")

    if not results:
        print("  No results found.")
        return

    for r in results:
        print(f"\n  Binary: {r.binary}")
        print(f"  Function: {r.function}")
        if r.address:
            print(f"  Address: {r.address}")
        print(f"  APIs ({r.count}): {', '.join(r.apis)}")


def main() -> None:
    """CLI entry point for user-controlled input detection."""
    parser = argparse.ArgumentParser(
        description="Detect user-controlled input sources in binaries using graph queries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all input source detection queries
  python -m student_labs.lab3.user_input_detection --all

  # Run specific input source query
  python -m student_labs.lab3.user_input_detection --network
  python -m student_labs.lab3.user_input_detection --file

  # Find high-risk functions with multiple input sources
  python -m student_labs.lab3.user_input_detection --high-risk

  # LLM-based API classification (single API)
  python -m student_labs.lab3.user_input_detection --classify-api recv

  # Scan binary and generate markdown report (default output: output/lab3/user_input_report_<sha256>.md)
  python -m student_labs.lab3.user_input_detection --scan-apis --sha256 abc123...

  # Scan binary with custom output file
  python -m student_labs.lab3.user_input_detection --scan-apis --sha256 abc123... --output my_report.md

  # Include all APIs in report (not just user-input sources)
  python -m student_labs.lab3.user_input_detection --scan-apis --sha256 abc123... --show-all
        """,
    )

    # Query selection arguments
    parser.add_argument("--all", action="store_true", help="Run all input source queries")
    parser.add_argument("--network", action="store_true", help="Detect network input sources")
    parser.add_argument("--file", action="store_true", help="Detect file input sources")
    parser.add_argument("--stdin", action="store_true", help="Detect stdin input sources")
    parser.add_argument("--env", action="store_true", help="Detect environment variable input")
    parser.add_argument("--ipc", action="store_true", help="Detect IPC input sources")
    parser.add_argument("--cmdline", action="store_true", help="Detect command-line input")
    parser.add_argument("--high-risk", action="store_true", help="Find functions with multiple input sources")

    # LLM-based API classification arguments
    parser.add_argument("--classify-api", type=str, metavar="API_NAME",
                        help="Use LLM to classify a single API and determine if it's user-controlled input")
    parser.add_argument("--scan-apis", action="store_true",
                        help="Scan binary for all APIs, classify with LLM, and generate markdown report (requires --sha256)")
    parser.add_argument("--sha256", type=str, metavar="HASH",
                        help="SHA256 hash of the binary to scan (required with --scan-apis)")
    parser.add_argument("--show-all", action="store_true",
                        help="Include all APIs in report, not just user-input sources (used with --scan-apis)")
    parser.add_argument("--output", "-o", type=str, metavar="FILE",
                        help="Output file for markdown report (default: output/lab3/user_input_report_<sha256>.md)")

    # Common arguments
    parser.add_argument("--limit", type=int, default=100, help="Maximum results per query (default: 100)")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Handle single API classification (doesn't need Neo4j)
    if args.classify_api:
        import json
        print(f"\nClassifying API: {args.classify_api}")
        print("-" * 40)
        result = classify_api_with_llm(args.classify_api)
        print(json.dumps(result, indent=2))
        return

    # Connect to Neo4j
    creds = get_neo4j_credentials()
    driver = GraphDatabase.driver(
        creds["uri"],
        auth=(creds["user"], creds["password"]),
    )
    database = creds.get("database", "neo4j")

    try:
        # Handle LLM-based binary API scanning
        if args.scan_apis:
            if not args.sha256:
                parser.error("--scan-apis requires --sha256 to specify the binary to scan")

            # Generate markdown report (default behavior)
            # Use specified output path or auto-generate in output/lab3/ folder
            if args.output:
                output_path = args.output
            else:
                # Default to output/lab3/ folder with SHA256-based filename
                output_dir = Path("output/lab3")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = str(output_dir / f"user_input_report_{args.sha256[:16]}.md")

            print(f"\nGenerating markdown report for binary...")
            print(f"Binary SHA256: {args.sha256}")
            print(f"Output file: {output_path}")
            try:
                report = generate_scan_report(
                    driver, database,
                    sha256=args.sha256,
                    output_path=output_path,
                )
                print(f"\n✅ Report generated successfully: {output_path}")
                print(f"   Report length: {len(report)} characters")
            except ValueError as e:
                print(f"\nError: {e}")
                print("Make sure the binary has been ingested into the database.")
                return
            return

        # Determine which queries to run
        run_all = args.all or not any([
            args.network, args.file, args.stdin, args.env,
            args.ipc, args.cmdline, args.high_risk
        ])

        if run_all or args.network:
            results = detect_network_input(driver, database, args.limit)
            print_results("Network", results)

        if run_all or args.file:
            results = detect_file_input(driver, database, args.limit)
            print_results("File", results)

        if run_all or args.stdin:
            results = detect_stdin_input(driver, database, args.limit)
            print_results("Stdin", results)

        if run_all or args.env:
            results = detect_environment_input(driver, database, args.limit)
            print_results("Environment", results)

        if run_all or args.ipc:
            results = detect_ipc_input(driver, database, args.limit)
            print_results("IPC", results)

        if run_all or args.cmdline:
            results = detect_cmdline_input(driver, database, args.limit)
            print_results("Command-Line", results)

        if args.high_risk:
            print(f"\n{'=' * 60}")
            print("  HIGH-RISK FUNCTIONS (Multiple Input Sources)")
            print(f"{'=' * 60}")

            high_risk = get_high_risk_functions(driver, database, min_categories=2, limit=args.limit)

            if not high_risk:
                print("  No high-risk functions found.")
            else:
                for func in high_risk:
                    print(f"\n  Binary: {func['binary']}")
                    print(f"  Function: {func['function']}")
                    if func['address']:
                        print(f"  Address: {func['address']}")
                    print(f"  Categories ({func['category_count']}): {', '.join(func['categories'])}")
                    print(f"  APIs: {', '.join(func['apis'][:10])}")
                    if len(func['apis']) > 10:
                        print(f"        ... and {len(func['apis']) - 10} more")

    finally:
        driver.close()


if __name__ == "__main__":
    module_name = Path(__file__).stem

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Override the logger to use the file name
    logger = logging.getLogger(module_name)

    main()
