import argparse
from pathlib import Path
import hashlib
import logging
import json
import yaml
import tempfile
import shutil
import sys
import os
import traceback
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
import warnings

# Suppress the RuntimeWarning about module found in sys.modules when running with -m flag.
# This warning is harmless - it occurs because Python imports the package (which imports this
# module) before executing this module as __main__. See lab_common/binql/__init__.py docstring.
warnings.filterwarnings(
    'ignore',
    message=r"'lab_common\.binql\.binql_ul' found in sys\.modules",
    category=RuntimeWarning,
)

# Suppress PyVEX warnings before importing blackfyre/pyvex
warnings.filterwarnings('ignore', category=UserWarning, module='pyvex')
# Suppress logging from pyvex
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('pyvex.lifting').setLevel(logging.ERROR)
logging.getLogger('pyvex.lifting.gym').setLevel(logging.ERROR)

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError, Neo4jError
from tqdm import tqdm
import blackfyre
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.vex.vexbinarycontext import VexBinaryContext
from blackfyre.common import BasicBlockExitType

# Module-level logger
logger = logging.getLogger(__name__)


class BinaryClassification(str, Enum):
    """Valid binary classification types."""
    BENIGN = "benign"
    MALWARE = "malware"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"

# Default Neo4j credentials (loaded from binql_config.yaml + env vars in main())
# These are used as argparse defaults only
URI = "neo4j://127.0.0.1:7687"
USER = "neo4j"
PASSWORD = "12345678"
TARGET_DB = "neo4j"
RESET_DB = True              # <-- Set this to True to blow away the DB

# All your constraint statements
CONSTRAINTS = [
    # -------------------------
    # Binary
    # -------------------------
    # Unique identity by sha256
    """
    CREATE CONSTRAINT binary_sha256 IF NOT EXISTS
    FOR (b:Binary)
    REQUIRE b.sha256 IS UNIQUE
    """,

    # Required properties for Binary (one per constraint)
    """
    CREATE CONSTRAINT binary_sha256_exists IF NOT EXISTS
    FOR (b:Binary)
    REQUIRE b.sha256 IS NOT NULL
    """,

    """
    CREATE CONSTRAINT binary_name_exists IF NOT EXISTS
    FOR (b:Binary)
    REQUIRE b.name IS NOT NULL
    """,

    # Type constraint for sha256
    """
    CREATE CONSTRAINT binary_sha256_type IF NOT EXISTS
    FOR (b:Binary)
    REQUIRE b.sha256 IS :: STRING
    """,

    # -------------------------
    # Function
    # -------------------------
    # Unique identity: (binary_sha256, start_address)
    """
    CREATE CONSTRAINT function_identity IF NOT EXISTS
    FOR (f:Function)
    REQUIRE (f.binary_sha256, f.start_address) IS UNIQUE
    """,

    # Required properties for Function (one per constraint)
    """
    CREATE CONSTRAINT function_binary_sha_exists IF NOT EXISTS
    FOR (f:Function)
    REQUIRE f.binary_sha256 IS NOT NULL
    """,

    """
    CREATE CONSTRAINT function_start_addr_exists IF NOT EXISTS
    FOR (f:Function)
    REQUIRE f.start_address IS NOT NULL
    """,

    """
    CREATE CONSTRAINT function_name_exists IF NOT EXISTS
    FOR (f:Function)
    REQUIRE f.name IS NOT NULL
    """,

    # Type constraint for function start_address
    """
    CREATE CONSTRAINT function_addr_type IF NOT EXISTS
    FOR (f:Function)
    REQUIRE f.start_address IS :: INTEGER
    """,

    # -------------------------
    # BasicBlock
    # -------------------------
    # Unique identity: (binary_sha256, start_address)
    """
    CREATE CONSTRAINT bb_identity IF NOT EXISTS
    FOR (bb:BasicBlock)
    REQUIRE (bb.binary_sha256, bb.start_address) IS UNIQUE
    """,

    # Required properties for BasicBlock (single-property constraints)
    """
    CREATE CONSTRAINT bb_binary_sha_exists IF NOT EXISTS
    FOR (bb:BasicBlock)
    REQUIRE bb.binary_sha256 IS NOT NULL
    """,

    """
    CREATE CONSTRAINT bb_start_addr_exists IF NOT EXISTS
    FOR (bb:BasicBlock)
    REQUIRE bb.start_address IS NOT NULL
    """,

    # Type constraint for basic block start_address
    """
    CREATE CONSTRAINT bb_addr_type IF NOT EXISTS
    FOR (bb:BasicBlock)
    REQUIRE bb.start_address IS :: INTEGER
    """,

    # Type constraint for basic block exit_type
    """
    CREATE CONSTRAINT bb_exit_type_type IF NOT EXISTS
    FOR (bb:BasicBlock)
    REQUIRE bb.exit_type IS :: STRING
    """,

    # -------------------------
    # ImportSymbol
    # -------------------------
    # Unique identity: qualified_name only (format: "library!symbol", e.g., "libc.so.6!printf")
    # The qualified_name is a denormalized field combining library_name and symbol name
    # This allows the same import to be shared across multiple binaries
    """
    CREATE CONSTRAINT import_qualified_name_unique IF NOT EXISTS
    FOR (imp:ImportSymbol)
    REQUIRE imp.qualified_name IS UNIQUE
    """,

    # Required properties for ImportSymbol
    """
    CREATE CONSTRAINT import_qualified_name_exists IF NOT EXISTS
    FOR (imp:ImportSymbol)
    REQUIRE imp.qualified_name IS NOT NULL
    """,

    """
    CREATE CONSTRAINT import_name_exists IF NOT EXISTS
    FOR (imp:ImportSymbol)
    REQUIRE imp.name IS NOT NULL
    """,

    # Type constraints for ImportSymbol
    """
    CREATE CONSTRAINT import_qualified_name_type IF NOT EXISTS
    FOR (imp:ImportSymbol)
    REQUIRE imp.qualified_name IS :: STRING
    """,

    # -------------------------
    # ExportSymbol
    # -------------------------
    # Unique identity: (binary_sha256, address, name)
    # Note: Multiple export symbols can exist at the same address (e.g., __DT_INIT and _init)
    """
    CREATE CONSTRAINT export_identity IF NOT EXISTS
    FOR (exp:ExportSymbol)
    REQUIRE (exp.binary_sha256, exp.address, exp.name) IS UNIQUE
    """,

    # Required properties for ExportSymbol
    """
    CREATE CONSTRAINT export_binary_sha_exists IF NOT EXISTS
    FOR (exp:ExportSymbol)
    REQUIRE exp.binary_sha256 IS NOT NULL
    """,

    """
    CREATE CONSTRAINT export_addr_exists IF NOT EXISTS
    FOR (exp:ExportSymbol)
    REQUIRE exp.address IS NOT NULL
    """,

    """
    CREATE CONSTRAINT export_name_exists IF NOT EXISTS
    FOR (exp:ExportSymbol)
    REQUIRE exp.name IS NOT NULL
    """,

    # Type constraint for export address
    """
    CREATE CONSTRAINT export_addr_type IF NOT EXISTS
    FOR (exp:ExportSymbol)
    REQUIRE exp.address IS :: INTEGER
    """,

    # -------------------------
    # StringLiteral
    # -------------------------
    # Unique identity: sha256 (implies NOT NULL)
    """
    CREATE CONSTRAINT string_sha256_unique IF NOT EXISTS
    FOR (s:StringLiteral)
    REQUIRE s.sha256 IS UNIQUE
    """,

    # Type constraint for StringLiteral.sha256
    """
    CREATE CONSTRAINT string_sha256_type IF NOT EXISTS
    FOR (s:StringLiteral)
    REQUIRE s.sha256 IS :: STRING
    """,

    # Required + type for StringLiteral.value
    """
    CREATE CONSTRAINT string_value_exists IF NOT EXISTS
    FOR (s:StringLiteral)
    REQUIRE s.value IS NOT NULL
    """,

    """
    CREATE CONSTRAINT string_value_type IF NOT EXISTS
    FOR (s:StringLiteral)
    REQUIRE s.value IS :: STRING
    """,

    # -------------------------
    # DefinedData
    # -------------------------
    # Unique identity: (binary_sha256, address)
    """
    CREATE CONSTRAINT data_identity IF NOT EXISTS
    FOR (d:DefinedData)
    REQUIRE (d.binary_sha256, d.address) IS UNIQUE
    """,

    # Required properties for DefinedData
    """
    CREATE CONSTRAINT data_binary_sha_exists IF NOT EXISTS
    FOR (d:DefinedData)
    REQUIRE d.binary_sha256 IS NOT NULL
    """,

    """
    CREATE CONSTRAINT data_addr_exists IF NOT EXISTS
    FOR (d:DefinedData)
    REQUIRE d.address IS NOT NULL
    """,

    # Type constraint for data address
    """
    CREATE CONSTRAINT data_addr_type IF NOT EXISTS
    FOR (d:DefinedData)
    REQUIRE d.address IS :: INTEGER
    """,

    # -------------------------
    # Library
    # -------------------------
    # Libraries by unique name
    """
    CREATE CONSTRAINT library_name IF NOT EXISTS
    FOR (l:Library)
    REQUIRE l.name IS UNIQUE
    """,

    # Required + type for Library.name
    """
    CREATE CONSTRAINT library_name_exists IF NOT EXISTS
    FOR (l:Library)
    REQUIRE l.name IS NOT NULL
    """,

    """
    CREATE CONSTRAINT library_name_type IF NOT EXISTS
    FOR (l:Library)
    REQUIRE l.name IS :: STRING
    """,

    # -------------------------
    # MalwareFamily
    # -------------------------
    # Malware families by unique name
    """
    CREATE CONSTRAINT malware_family_name IF NOT EXISTS
    FOR (mf:MalwareFamily)
    REQUIRE mf.name IS UNIQUE
    """,

    # Required + type for MalwareFamily.name
    """
    CREATE CONSTRAINT malware_family_name_exists IF NOT EXISTS
    FOR (mf:MalwareFamily)
    REQUIRE mf.name IS NOT NULL
    """,

    """
    CREATE CONSTRAINT malware_family_name_type IF NOT EXISTS
    FOR (mf:MalwareFamily)
    REQUIRE mf.name IS :: STRING
    """,

    # -------------------------
    # Vendor
    # -------------------------
    # Vendors by unique name
    """
    CREATE CONSTRAINT vendor_name IF NOT EXISTS
    FOR (v:Vendor)
    REQUIRE v.name IS UNIQUE
    """,

    # Required + type for Vendor.name
    """
    CREATE CONSTRAINT vendor_name_exists IF NOT EXISTS
    FOR (v:Vendor)
    REQUIRE v.name IS NOT NULL
    """,

    """
    CREATE CONSTRAINT vendor_name_type IF NOT EXISTS
    FOR (v:Vendor)
    REQUIRE v.name IS :: STRING
    """,

    # -------------------------
    # Product
    # -------------------------
    # Products by unique (vendor_name, product_name)
    """
    CREATE CONSTRAINT product_identity IF NOT EXISTS
    FOR (p:Product)
    REQUIRE (p.vendor_name, p.name) IS UNIQUE
    """,

    # Required properties for Product
    """
    CREATE CONSTRAINT product_vendor_name_exists IF NOT EXISTS
    FOR (p:Product)
    REQUIRE p.vendor_name IS NOT NULL
    """,

    """
    CREATE CONSTRAINT product_name_exists IF NOT EXISTS
    FOR (p:Product)
    REQUIRE p.name IS NOT NULL
    """,

    # Type constraints for Product
    """
    CREATE CONSTRAINT product_vendor_name_type IF NOT EXISTS
    FOR (p:Product)
    REQUIRE p.vendor_name IS :: STRING
    """,

    """
    CREATE CONSTRAINT product_name_type IF NOT EXISTS
    FOR (p:Product)
    REQUIRE p.name IS :: STRING
    """,

    # -------------------------
    # SIMILAR_TO Relationships
    # -------------------------
    # Applies to all SIMILAR_TO relationships (Function→Function, Binary→Binary, etc.)

    # Type constraint for SIMILAR_TO score
    """
    CREATE CONSTRAINT similar_to_score_type IF NOT EXISTS
    FOR ()-[r:SIMILAR_TO]-()
    REQUIRE r.score IS :: FLOAT
    """,

    # Type constraint for SIMILAR_TO method
    """
    CREATE CONSTRAINT similar_to_method_type IF NOT EXISTS
    FOR ()-[r:SIMILAR_TO]-()
    REQUIRE r.method IS :: STRING
    """,

    # Required properties for SIMILAR_TO relationships
    """
    CREATE CONSTRAINT similar_to_score_exists IF NOT EXISTS
    FOR ()-[r:SIMILAR_TO]-()
    REQUIRE r.score IS NOT NULL
    """,

    """
    CREATE CONSTRAINT similar_to_method_exists IF NOT EXISTS
    FOR ()-[r:SIMILAR_TO]-()
    REQUIRE r.method IS NOT NULL
    """
]


def setup_logging(verbosity: int) -> None:
    """
    Configure logging based on verbosity level.

    Args:
        verbosity: 0 (quiet/CRITICAL), 1 (normal/INFO), 2 (verbose/DEBUG)
    """
    # Root logger levels
    root_level_map = {
        0: logging.CRITICAL,  # Quiet: only critical errors
        1: logging.INFO,      # Normal: info and above
        2: logging.DEBUG,     # Verbose: everything
    }
    root_level = root_level_map.get(verbosity, logging.INFO)

    # Format based on verbosity
    # Normal mode: timestamp + level + module + message
    # Verbose mode: timestamp + level + module:line + message
    format_map = {
        0: "%(message)s",  # Quiet: just the message
        1: "%(asctime)s - %(levelname)s - %(name)s - %(message)s",  # Normal: standard logging
        2: "%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(message)s",  # Verbose: with line numbers
    }
    log_format = format_map.get(verbosity, format_map[1])

    # Configure root logger
    logging.basicConfig(
        level=root_level,
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )

    # Configure binarycontext logger with different levels
    # 0 = CRITICAL, 1 = WARNING (suppress INFO), 2 = INFO (show details)
    binarycontext_level_map = {
        0: logging.CRITICAL,  # Quiet: only critical errors
        1: logging.WARNING,   # Normal: warnings and errors only (suppress INFO)
        2: logging.INFO,      # Verbose: show INFO messages
    }
    binarycontext_level = binarycontext_level_map.get(verbosity, logging.WARNING)

    binarycontext_logger = logging.getLogger("binarycontext")
    binarycontext_logger.setLevel(binarycontext_level)


def reset_database(driver: Driver, dbname: str, create_indexes: bool = True, timeout_seconds: int = 30) -> None:
    """
    Drops and recreates the specified Neo4j database.

    By default, constraints and indexes are automatically created after recreation
    to ensure optimal query performance during ingestion.

    Args:
        driver: Neo4j driver instance
        dbname: Name of the database to reset
        create_indexes: If True (default), create constraints/indexes after reset.
            This is critical for ingestion performance (can be 100x+ faster).
        timeout_seconds: Maximum time to wait for database to come online (default: 30).

    Raises:
        ServiceUnavailable: If Neo4j connection fails
        TimeoutError: If database does not come online within timeout
    """
    import time

    try:
        with driver.session(database="system") as session:
            logger.info(f"Dropping database `{dbname}` if it exists...")
            session.run(f"DROP DATABASE `{dbname}` IF EXISTS")

            logger.info(f"Recreating database `{dbname}`...")
            # Don't use WAIT clause - it can hang indefinitely if Neo4j has issues
            session.run(f"CREATE DATABASE `{dbname}`")

        # Poll for database availability instead of relying on WAIT
        logger.info(f"Waiting for database `{dbname}` to come online (timeout: {timeout_seconds}s)...")
        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            try:
                with driver.session(database="system") as session:
                    result = session.run(
                        "SHOW DATABASE $dbname YIELD currentStatus",
                        dbname=dbname
                    )
                    record = result.single()
                    if record and record["currentStatus"] == "online":
                        logger.info(f"Database `{dbname}` is online.")
                        break
            except Exception:
                pass  # Database may not exist yet or query failed
            time.sleep(0.5)
        else:
            logger.error("=" * 80)
            logger.error("ERROR: Database did not come online within timeout")
            logger.error("=" * 80)
            logger.error("")
            logger.error(f"Database `{dbname}` did not become available within {timeout_seconds} seconds.")
            logger.error("")
            logger.error("Possible causes:")
            logger.error("  1. Neo4j server is unhealthy or misconfigured")
            logger.error("  2. Insufficient system resources (memory, disk)")
            logger.error("  3. Neo4j cluster/replication issues")
            logger.error("")
            logger.error("Solutions:")
            logger.error("  • Check Neo4j logs: journalctl -u neo4j or /var/log/neo4j/")
            logger.error("  • Restart Neo4j: sudo systemctl restart neo4j")
            logger.error("  • Verify Neo4j has enough memory and disk space")
            logger.error("=" * 80)
            raise TimeoutError(
                f"Database `{dbname}` did not come online within {timeout_seconds} seconds."
            )

        # Create constraints/indexes by default for optimal ingestion performance
        if create_indexes:
            logger.info("Creating constraints and indexes for optimal performance...")
            create_constraints(driver, dbname)

    except ServiceUnavailable as e:
        logger.error("=" * 80)
        logger.error("ERROR: Lost connection to Neo4j during database reset")
        logger.error("=" * 80)
        logger.error("")
        logger.error("Possible causes:")
        logger.error("  1. Neo4j stopped running")
        logger.error("  2. Network connection lost")
        logger.error("  3. Database is locked or busy")
        logger.error("")
        logger.error("Technical details: %s", str(e))
        logger.error("=" * 80)
        raise


def check_constraints_exist(driver: Driver, database: str) -> bool:
    """
    Check if database has constraints (indicating it's been initialized).

    Args:
        driver: Neo4j driver instance
        database: Database name to check

    Returns:
        True if constraints exist, False otherwise

    Raises:
        ServiceUnavailable: If Neo4j connection fails
    """
    try:
        with driver.session(database=database) as session:
            result = session.run("SHOW CONSTRAINTS")
            constraints = list(result)
            return len(constraints) > 0
    except ServiceUnavailable as e:
        logger.error("=" * 80)
        logger.error("ERROR: Cannot check database constraints - Neo4j connection lost")
        logger.error("=" * 80)
        logger.error("")
        logger.error("Please ensure Neo4j is running and accessible.")
        logger.error("Technical details: %s", str(e))
        logger.error("=" * 80)
        raise


def create_constraints(driver: Driver, database: str) -> None:
    """
    Create all schema constraints for the binary analysis database.

    Args:
        driver: Neo4j driver instance
        database: Database name where constraints will be created

    Raises:
        ServiceUnavailable: If Neo4j connection fails
    """
    try:
        with driver.session(database=database) as session:
            for constraint in CONSTRAINTS:
                constraint_name = constraint.strip().split("\n")[0]
                logger.debug(f"Running constraint: {constraint_name}...")
                session.run(constraint)

        logger.info(f"All constraints created (or already existed) in database '{database}'.")
    except ServiceUnavailable as e:
        logger.error("=" * 80)
        logger.error("ERROR: Cannot create constraints - Neo4j connection lost")
        logger.error("=" * 80)
        logger.error("")
        logger.error("Please ensure Neo4j is running and accessible.")
        logger.error("Technical details: %s", str(e))
        logger.error("=" * 80)
        raise




def load_metadata_file(dir_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load metadata.json from directory if it exists.

    Args:
        dir_path: Directory containing .bcc files

    Returns:
        Metadata dictionary or None if file doesn't exist

    Example metadata.json:
    {
        "classification": "benign",
        "tags": ["lab1", "benign-corpus"],
        "binary_file_path": "/path/to/actual/binary.exe",
        "overrides": {
            "specific.bcc": {
                "classification": "suspicious",
                "binary_file_path": "/path/to/specific/binary.exe"
            }
        }
    }
    """
    metadata_path = dir_path / "metadata.json"
    if not metadata_path.exists():
        logger.debug(f"No metadata.json found in {dir_path}")
        return None

    try:
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        logger.info(f"Loaded metadata from {metadata_path}")
        return metadata
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {metadata_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error loading {metadata_path}: {e}")
        return None


def get_binary_metadata(filename: str, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get metadata for a specific binary file.

    Args:
        filename: Name of the .bcc file
        metadata: Loaded metadata dictionary (or None)

    Returns:
        Dictionary with classification, malware_family, tags, vendor, product, firmware_version, binary_file_path,
        and ingest_decompiled_code
    """
    # Default values
    result = {
        "classification": BinaryClassification.UNKNOWN.value,
        "malware_family": None,
        "tags": [],
        "vendor": None,
        "product": None,
        "firmware_version": None,
        "binary_file_path": None,
        "ingest_decompiled_code": False,  # Default to False for performance
    }

    if metadata is None:
        return result

    # Apply directory-level defaults
    result["classification"] = metadata.get("classification", result["classification"])
    result["malware_family"] = metadata.get("malware_family", result["malware_family"])
    result["tags"] = metadata.get("tags", result["tags"])
    result["vendor"] = metadata.get("vendor", result["vendor"])
    result["product"] = metadata.get("product", result["product"])
    result["firmware_version"] = metadata.get("firmware_version", result["firmware_version"])
    result["binary_file_path"] = metadata.get("binary_file_path", result["binary_file_path"])
    result["ingest_decompiled_code"] = metadata.get("ingest_decompiled_code", result["ingest_decompiled_code"])

    # Apply file-specific overrides
    overrides = metadata.get("overrides", {})
    if filename in overrides:
        file_meta = overrides[filename]
        result["classification"] = file_meta.get("classification", result["classification"])
        result["malware_family"] = file_meta.get("malware_family", result["malware_family"])
        result["tags"] = file_meta.get("tags", result["tags"])
        result["vendor"] = file_meta.get("vendor", result["vendor"])
        result["product"] = file_meta.get("product", result["product"])
        result["firmware_version"] = file_meta.get("firmware_version", result["firmware_version"])
        result["binary_file_path"] = file_meta.get("binary_file_path", result["binary_file_path"])
        result["ingest_decompiled_code"] = file_meta.get("ingest_decompiled_code", result["ingest_decompiled_code"])

    # Validate classification
    try:
        BinaryClassification(result["classification"])
    except ValueError:
        logger.warning(
            f"Invalid classification '{result['classification']}' for {filename}, using 'unknown'"
        )
        result["classification"] = BinaryClassification.UNKNOWN.value

    return result


def load_vex_binary_context(file_path: str) -> VexBinaryContext:
    """Load a VexBinaryContext from a .bcc file path."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary context file not found: {file_path}")

    logger.debug(f"Loading VexBinaryContext from: {file_path}")
    return VexBinaryContext.load_from_file(str(path), cache_path=None)


def collect_strings_from_context(vex_binary_context):
    """
    Collect strings from the binary context into a dict keyed by address:

        {
          address: {
            "value": full_string,
            "name":  truncated_string,
            "sha256": sha256_of_full_string,
            "address": address,
          },
          ...
        }
    """
    strings_by_address = {}

    for address, string in vex_binary_context.string_refs.items():
        if not isinstance(string, str):
            string = str(string)

        sha_256 = hashlib.sha256(string.encode("utf-8")).hexdigest()
        truncated = string[:20]

        strings_by_address[address] = {
            "value": string,       # full string
            "name": truncated,     # truncated label
            "sha256": sha_256,
            "address": address,
        }

    return strings_by_address


def collect_structure_from_context(vex_binary_context, strings_by_address, ingest_decompiled_code=False):
    """
    From the VexBinaryContext and pre-collected strings, build:

      - function_entries     : [{start_address, end_address, name, decompiled_code_sha, [decompiled_code]}]
      - block_entries        : [{func_start_address, start_address, end_address, hex_name, exit_type}]
      - bb_string_uses       : [{bb_start_address, address, value, name, sha256}]
      - entry_blocks         : [{func_start_address, bb_start_address}]
      - block_edges          : [{src_start_address, dst_start_address}]
      - orphan_blocks        : [{func_start_address, bb_start_address}]
      - call_function_edges  : [{bb_start_address, callee_start_address}]
      - call_import_edges    : [{bb_start_address, import_address}]
      - import_entries       : [{address, name, library_name}]
      - export_entries       : [{address, name, library_name}]

    Args:
        vex_binary_context: VexBinaryContext instance
        strings_by_address: Dict mapping addresses to string literals
        ingest_decompiled_code: If True, include full decompiled_code in function_entries (default: False)
    """
    function_entries = []
    block_entries = []
    bb_string_uses = []
    entry_blocks = []
    block_edges = []
    orphan_blocks = []
    call_function_edges = []
    call_import_edges = []
    import_entries = []  # for creating ImportSymbol + Library nodes
    export_entries = []  # for creating ExportSymbol nodes

    # For quick dedup of import_entries by address
    seen_import_addrs = set()

    for vex_function_context in vex_binary_context.function_contexts:
        func_start = vex_function_context.start_address
        func_end = vex_function_context.end_address
        func_name = vex_function_context.name
        is_thunk = vex_function_context.is_thunk
        total_instructions = vex_function_context.total_instructions
        decompiled_code = vex_function_context.decompiled_code

        # Compute SHA256 of decompiled code (None if decompiled code is None, empty, or whitespace-only)
        if decompiled_code and decompiled_code.strip():
            decompiled_code_sha = hashlib.sha256(decompiled_code.encode("utf-8")).hexdigest()
        else:
            decompiled_code_sha = None

        function_entry = {
            "start_address": func_start,
            "end_address": func_end,
            "name": func_name,
            "is_thunk": is_thunk,
            "total_instructions": total_instructions,
            "decompiled_code_sha": decompiled_code_sha,
        }

        # Optionally include full decompiled code (for CVE triage, vulnerability analysis, etc.)
        # Only included if ingest_decompiled_code=True
        if ingest_decompiled_code and decompiled_code and decompiled_code.strip():
            function_entry["decompiled_code"] = decompiled_code

        function_entries.append(function_entry)

        # All BB addresses in this function
        bb_addrs = list(vex_function_context.basic_block_context_dict.keys())

        incoming_counts = {addr: 0 for addr in bb_addrs}

        # Entry basic block has the same address as the function
        entry_bb_addr = func_start
        if entry_bb_addr in incoming_counts:
            entry_blocks.append({
                "func_start_address": func_start,
                "bb_start_address": entry_bb_addr,
            })

        # Basic blocks within this function
        for bb_start, vex_bb_context in vex_function_context.basic_block_context_dict.items():
            bb_end = vex_bb_context.end_address

            # Get the exit type from the basic block context
            exit_type = vex_bb_context.exit_type
            exit_type_str = exit_type.value if exit_type else BasicBlockExitType.UNKNOWN.value

            block_entries.append({
                "func_start_address": func_start,
                "start_address": bb_start,
                "end_address": bb_end,
                "hex_name": hex(bb_start),  # <-- real hex conversion
                "exit_type": exit_type_str
            })

            # CFG edges using helper; BRANCHES_TO edges src -> dst
            targets = vex_binary_context.branch_targets_from_vex_bb_context(vex_bb_context) or []
            for tgt_addr in targets:


                block_edges.append({
                    "src_start_address": bb_start,
                    "dst_start_address": tgt_addr,
                })

                # If a BB is a dst of BRANCHES_TO, it is not an orphan
                if tgt_addr in incoming_counts:

                    incoming_counts[tgt_addr] += 1

            # Call edge (at most one call per BB in VEX IR)
            call_target = vex_binary_context.call_target_from_vex_bb_context(vex_bb_context)
            if call_target is not None:
                # Check if this call target matches an import symbol
                imp = vex_binary_context.import_symbol_dict.get(call_target)
                if imp is not None:
                    # Call to an import
                    qualified_name = f"{imp.library_name}!{imp.import_name}"
                    call_import_edges.append({
                        "bb_start_address": bb_start,
                        "import_qualified_name": qualified_name,
                    })
                    if imp.address not in seen_import_addrs:
                        seen_import_addrs.add(imp.address)
                        import_entries.append({
                            "address": imp.address,
                            "name": imp.import_name,
                            "library_name": imp.library_name,
                        })
                else:
                    # Call to an internal function
                    call_function_edges.append({
                        "bb_start_address": bb_start,
                        "callee_start_address": call_target,
                    })

            # Strings whose address lies in [bb_start, bb_end)
            for addr, s_entry in strings_by_address.items():
                if bb_start <= addr < bb_end:
                    logger.debug(
                        f"BasicBlock {hex(bb_start)} references "
                        f"string at {hex(addr)}: '{s_entry['value']}'"
                    )
                    bb_string_uses.append({
                        "bb_start_address": bb_start,
                        "address": addr,
                        "value": s_entry["value"],
                        "name": s_entry["name"],
                        "sha256": s_entry["sha256"],
                    })

        # Orphan blocks:
        #   - no incoming BRANCHES_TO (incoming_counts == 0)
        #   - not the entry block
        for bb_addr, inc in incoming_counts.items():
            if inc == 0 and bb_addr != entry_bb_addr:

                orphan_blocks.append({
                    "func_start_address": func_start,
                    "bb_start_address": bb_addr,
                })

    # Collect export symbols from the binary context
    for exp_symbol in vex_binary_context.export_symbols:
        export_entries.append({
            "address": exp_symbol.address,
            "name": exp_symbol.export_name,
            "library_name": exp_symbol.library_name,
        })

    return (
        function_entries,
        block_entries,
        bb_string_uses,
        entry_blocks,
        block_edges,
        orphan_blocks,
        call_function_edges,
        call_import_edges,
        import_entries,
        export_entries,
    )




def write_binary_context_tx(
    tx,
    sha256_binary: str,
    binary_name: str,
    bcc_file_path: str,
    binary_file_path: Optional[str],
    classification: str,
    malware_family: Optional[str],
    tags: List[str],
    vendor: Optional[str],
    product: Optional[str],
    firmware_version: Optional[str],
    function_entries,
    block_entries,
    bb_string_uses,
    entry_blocks,
    block_edges,
    orphan_blocks,
    call_function_edges,
    call_import_edges,
    import_entries,
    export_entries,
):
    """
    Transaction body: write Binary, Functions, BasicBlocks, StringLiteral usage,
    plus Function entry blocks, CFG edges, orphan-block relationships, calls to
    internal functions, calls to import symbols (with Library nodes), and export symbols.
    """

    # 1) Binary
    cypher_binary = """
        MERGE (b:Binary { sha256: $sha256_binary })
        SET b.name = $binary_name,
            b.bcc_file_path = $bcc_file_path,
            b.binary_file_path = $binary_file_path,
            b.classification = $classification,
            b.tags = $tags,
            b.firmware_version = $firmware_version
    """
    tx.run(
        cypher_binary,
        sha256_binary=sha256_binary,
        binary_name=binary_name,
        bcc_file_path=bcc_file_path,
        binary_file_path=binary_file_path,
        classification=classification,
        tags=tags,
        firmware_version=firmware_version,
    )

    # 1b) MalwareFamily relationship if malware_family is provided
    if malware_family is not None:
        cypher_malware_family = """
            MATCH (b:Binary { sha256: $sha256_binary })
            MERGE (mf:MalwareFamily { name: $malware_family })
            MERGE (b)-[:BELONGS_TO_FAMILY]->(mf)
        """
        tx.run(
            cypher_malware_family,
            sha256_binary=sha256_binary,
            malware_family=malware_family,
        )

    # 1c) Vendor and Product relationships if provided
    if vendor is not None and product is not None:
        cypher_vendor_product = """
            MATCH (b:Binary { sha256: $sha256_binary })
            MERGE (v:Vendor { name: $vendor })
            MERGE (p:Product { vendor_name: $vendor, name: $product })
            MERGE (p)-[:FROM_VENDOR]->(v)
            MERGE (b)-[:IMPLEMENTS_PRODUCT]->(p)
        """
        tx.run(
            cypher_vendor_product,
            sha256_binary=sha256_binary,
            vendor=vendor,
            product=product,
        )
    elif vendor is not None:
        # Vendor only (no product specified)
        cypher_vendor_only = """
            MATCH (b:Binary { sha256: $sha256_binary })
            MERGE (v:Vendor { name: $vendor })
            MERGE (b)-[:FROM_VENDOR]->(v)
        """
        tx.run(
            cypher_vendor_only,
            sha256_binary=sha256_binary,
            vendor=vendor,
        )

    # 2) Functions attached to Binary
    # Check if any function has decompiled_code (to determine the flag value)
    has_decompiled = any("decompiled_code" in f for f in function_entries) if function_entries else False

    if function_entries:
        cypher_functions = """
            UNWIND $functions AS f
            MATCH (b:Binary { sha256: $sha256_binary })
            MERGE (func:Function {
                binary_sha256: $sha256_binary,
                start_address: f.start_address
            })
            SET func.name                 = f.name,
                func.end_address          = f.end_address,
                func.is_thunk             = f.is_thunk,
                func.total_instructions   = f.total_instructions,
                func.decompiled_code_sha  = f.decompiled_code_sha,
                func.decompiled_code      = CASE WHEN f.decompiled_code IS NOT NULL
                                                 THEN f.decompiled_code
                                                 ELSE func.decompiled_code
                                            END
            MERGE (b)-[:HAS_FUNCTION]->(func)
        """
        tx.run(
            cypher_functions,
            sha256_binary=sha256_binary,
            functions=function_entries,
        )

    # Always set Binary flag explicitly (true if decompiled code was ingested, false otherwise)
    # This ensures the property is always defined, never NULL
    cypher_set_flag = """
        MATCH (b:Binary { sha256: $sha256_binary })
        SET b.decompiled_code_ingested = $has_decompiled
    """
    tx.run(cypher_set_flag, sha256_binary=sha256_binary, has_decompiled=has_decompiled)

    # 3) Basic blocks (nodes only, no HAS_BLOCK edge)
    if block_entries:
        cypher_blocks = """
            UNWIND $blocks AS bb
            MERGE (block:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: bb.start_address
            })
            SET block.end_address = bb.end_address,
                block.name = bb.hex_name,
                block.exit_type = bb.exit_type,
                block.func_start_address = bb.func_start_address
        """
        tx.run(
            cypher_blocks,
            sha256_binary=sha256_binary,
            blocks=block_entries,
        )

    # 3a) Function -> entry basic block
    if entry_blocks:
        cypher_entry_blocks = """
            UNWIND $entries AS e
            MATCH (func:Function {
                binary_sha256: $sha256_binary,
                start_address: e.func_start_address
            })
            MATCH (bb:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: e.bb_start_address
            })
            MERGE (func)-[:ENTRY_BLOCK]->(bb)
        """
        tx.run(
            cypher_entry_blocks,
            sha256_binary=sha256_binary,
            entries=entry_blocks,
        )

    # 3b) BasicBlock -> successor BasicBlock edges (branches)
    if block_edges:
        cypher_block_edges = """
            UNWIND $edges AS e
            MATCH (src:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: e.src_start_address
            })
            MATCH (dst:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: e.dst_start_address
            })
            MERGE (src)-[:BRANCHES_TO]->(dst)
        """
        tx.run(
            cypher_block_edges,
            sha256_binary=sha256_binary,
            edges=block_edges,
        )

    # 3c) Function -> orphan basic blocks
    # Orphan = BB with no incoming BRANCHES_TO and not the entry block
    if orphan_blocks:
        cypher_orphans = """
            UNWIND $orphans AS o
            MATCH (func:Function {
                binary_sha256: $sha256_binary,
                start_address: o.func_start_address
            })
            MATCH (bb:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: o.bb_start_address
            })
            MERGE (func)-[:ORPHAN_BLOCK]->(bb)
        """
        tx.run(
            cypher_orphans,
            sha256_binary=sha256_binary,
            orphans=orphan_blocks,
        )

    # 3d) BasicBlock -> Function (CALLS_TO for internal functions)
    if call_function_edges:
        cypher_calls_internal = """
            UNWIND $calls AS c
            MATCH (bb:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: c.bb_start_address
            })
            MATCH (callee:Function {
                binary_sha256: $sha256_binary,
                start_address: c.callee_start_address
            })
            MERGE (bb)-[:CALLS_TO]->(callee)
        """
        tx.run(
            cypher_calls_internal,
            sha256_binary=sha256_binary,
            calls=call_function_edges,
        )

    # 3e) ImportSymbol + Library nodes
    # ImportSymbol is unique by qualified_name only (shared across binaries)
    if import_entries:
        cypher_imports = """
            UNWIND $imports AS imp
            MERGE (lib:Library { name: imp.library_name })
            MERGE (is:ImportSymbol {
                qualified_name: imp.library_name + "!" + imp.name
            })
            SET is.name = imp.name,
                is.library_name = imp.library_name
            MERGE (is)-[:FROM_LIBRARY]->(lib)
        """
        tx.run(
            cypher_imports,
            imports=import_entries,
        )

    # 3e2) ExportSymbol nodes with Binary relationship
    # ExportSymbol is identified by (binary_sha256, address, name) to support multiple exports at same address
    if export_entries:
        cypher_exports = """
            UNWIND $exports AS exp
            MATCH (b:Binary { sha256: $sha256_binary })
            MERGE (es:ExportSymbol {
                binary_sha256: $sha256_binary,
                address: exp.address,
                name: exp.name
            })
            SET es.library_name = exp.library_name
            MERGE (b)-[:EXPORTS_SYMBOL]->(es)
        """
        tx.run(
            cypher_exports,
            sha256_binary=sha256_binary,
            exports=export_entries,
        )

    # 3f) BasicBlock -> ImportSymbol (CALLS_TO for imports)
    # Match ImportSymbol by qualified_name only (no binary_sha256)
    if call_import_edges:
        cypher_calls_imports = """
            UNWIND $calls AS c
            MATCH (bb:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: c.bb_start_address
            })
            MATCH (callee:ImportSymbol {
                qualified_name: c.import_qualified_name
            })
            MERGE (bb)-[:CALLS_TO]->(callee)
        """
        tx.run(
            cypher_calls_imports,
            sha256_binary=sha256_binary,
            calls=call_import_edges,
        )

    # 3g) Function -> Function (CALLS_FUNCTION relationship)
    # Aggregates BasicBlock CALLS_TO relationships to create direct function-to-function edges
    if call_function_edges:
        cypher_calls_function = """
            UNWIND $calls AS c
            MATCH (bb:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: c.bb_start_address
            })
            MATCH (caller:Function {
                binary_sha256: $sha256_binary,
                start_address: bb.func_start_address
            })
            MATCH (callee:Function {
                binary_sha256: $sha256_binary,
                start_address: c.callee_start_address
            })
            MERGE (caller)-[:CALLS_FUNCTION]->(callee)
        """
        tx.run(
            cypher_calls_function,
            sha256_binary=sha256_binary,
            calls=call_function_edges,
        )

    # 4) String literals and BasicBlock → String uses
    if bb_string_uses:
        cypher_strings = """
            UNWIND $uses AS use
            MATCH (block:BasicBlock {
                binary_sha256: $sha256_binary,
                start_address: use.bb_start_address
            })
            MERGE (str:StringLiteral { sha256: use.sha256 })
            SET str.value = use.value,
                str.name  = use.name
            MERGE (block)-[:USES_STRING { address: use.address }]->(str)
        """
        tx.run(
            cypher_strings,
            sha256_binary=sha256_binary,
            uses=bb_string_uses,
        )

    # 5) Binary -> Library usage edges (aggregated from BasicBlock calls to ImportSymbols)
    cypher_binary_libraries = """
        MATCH (b:Binary {sha256: $sha256_binary})-[:HAS_FUNCTION]->(f:Function)
        MATCH (bb:BasicBlock {binary_sha256: $sha256_binary, func_start_address: f.start_address})
        MATCH (bb)-[:CALLS_TO]->(imp:ImportSymbol)-[:FROM_LIBRARY]->(lib:Library)
        MERGE (b)-[:USES_LIBRARY]->(lib)
    """
    tx.run(cypher_binary_libraries, sha256_binary=sha256_binary)

    # 6) Binary -> StringLiteral usage edges (aggregated from BasicBlock uses)
    cypher_binary_strings = """
        MATCH (b:Binary {sha256: $sha256_binary})
        MATCH (bb:BasicBlock {binary_sha256: $sha256_binary})-[:USES_STRING]->(str:StringLiteral)
        MERGE (b)-[:USES_STRING]->(str)
    """
    tx.run(cypher_binary_strings, sha256_binary=sha256_binary)

    # 7) Binary -> ImportSymbol direct relationship (aggregated from BasicBlock calls)
    # ImportSymbol is globally unique by qualified_name (no binary_sha256)
    cypher_binary_imports = """
        MATCH (b:Binary {sha256: $sha256_binary})
        MATCH (bb:BasicBlock {binary_sha256: $sha256_binary})-[:CALLS_TO]->(imp:ImportSymbol)
        MERGE (b)-[:IMPORTS_SYMBOL]->(imp)
    """
    tx.run(cypher_binary_imports, sha256_binary=sha256_binary)


def update_binary_decompiled_code(
    driver: Driver,
    database: str,
    sha256: Optional[str] = None,
    update_all: bool = False,
    force: bool = False,
) -> Dict[str, int]:
    """
    Update existing binaries in Neo4j with decompiled code from their stored BCC files.

    Args:
        driver: Neo4j driver instance
        database: Database name
        sha256: SHA256 of specific binary to update (mutually exclusive with update_all)
        update_all: Update all binaries without decompiled code (mutually exclusive with sha256)
        force: Force re-ingestion even if already ingested

    Returns:
        Dictionary with statistics: {binaries_updated, functions_updated, binaries_failed}

    Raises:
        ValueError: If neither or both sha256 and update_all are specified
    """
    if not sha256 and not update_all:
        raise ValueError("Must specify either --sha256 or --update-all")
    if sha256 and update_all:
        raise ValueError("Cannot specify both --sha256 and --update-all")

    stats = {
        "binaries_updated": 0,
        "functions_updated": 0,
        "binaries_failed": 0,
    }

    # Find binaries to update
    with driver.session(database=database) as session:
        if update_all:
            # Find all binaries without decompiled code
            # Note: Checks for NULL for backward compatibility with old binaries
            result = session.run("""
                MATCH (b:Binary)
                WHERE (b.decompiled_code_ingested IS NULL OR b.decompiled_code_ingested = false)
                  AND b.bcc_file_path IS NOT NULL
                RETURN b.sha256 as sha256,
                       b.name as name,
                       b.bcc_file_path as bcc_path
                ORDER BY b.name
            """)
            binaries = [{"sha256": r["sha256"], "name": r["name"], "bcc_path": r["bcc_path"]}
                       for r in result]
            logger.info(f"Found {len(binaries)} binaries to update")
        else:
            # Get specific binary
            result = session.run("""
                MATCH (b:Binary {sha256: $sha256})
                RETURN b.sha256 as sha256,
                       b.name as name,
                       b.bcc_file_path as bcc_path,
                       b.decompiled_code_ingested as ingested
            """, sha256=sha256)
            record = result.single()

            if not record:
                raise ValueError(f"Binary not found: {sha256}")
            if not record["bcc_path"]:
                raise ValueError(f"No BCC path stored for binary: {sha256}")
            if not force and record.get("ingested"):
                logger.warning(f"Binary already has decompiled code (use --force to update)")
                return stats

            binaries = [{"sha256": record["sha256"], "name": record["name"], "bcc_path": record["bcc_path"]}]

    # Update each binary
    for i, binary_info in enumerate(binaries, 1):
        bin_sha256 = binary_info["sha256"]
        name = binary_info["name"]
        bcc_path = Path(binary_info["bcc_path"])

        if update_all:
            logger.info(f"[{i}/{len(binaries)}] Updating {name} ({bin_sha256[:16]}...)")
        else:
            logger.info(f"Updating {name} ({bin_sha256[:16]}...)")

        try:
            # Check if BCC file exists
            if not bcc_path.exists():
                logger.error(f"BCC file not found: {bcc_path}")
                stats["binaries_failed"] += 1
                continue

            # Load BCC and re-ingest with decompiled code
            # This reuses the existing add_binary_context infrastructure
            result = add_binary_context(
                driver=driver,
                database=database,
                file_path=str(bcc_path),
                metadata=None,  # Keep existing metadata
                ingest_decompiled_code=True,
            )

            stats["binaries_updated"] += 1
            stats["functions_updated"] += result.get("num_functions", 0)
            logger.info(f"✓ Updated {result.get('num_functions', 0)} functions")

        except Exception as e:
            logger.error(f"Failed to update {name}: {e}")
            stats["binaries_failed"] += 1

    return stats


def _find_nearest_metadata(bcc_file: Path, root_dir: Path, metadata_cache: Dict[Path, Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """
    Find the nearest metadata.json for a .bcc file by walking up the directory tree.

    Searches from the .bcc file's parent directory up to (and including) the root directory,
    returning the first metadata.json found. Results are cached for efficiency.

    Args:
        bcc_file: Path to the .bcc file
        root_dir: Root directory of the search (stop searching at this level)
        metadata_cache: Cache of directory -> metadata mappings

    Returns:
        Metadata dictionary if found, None otherwise
    """
    current_dir = bcc_file.parent

    # Walk up the directory tree until we reach or pass the root
    while current_dir >= root_dir:
        if current_dir in metadata_cache:
            return metadata_cache[current_dir]

        metadata = load_metadata_file(current_dir)
        metadata_cache[current_dir] = metadata

        if metadata is not None:
            return metadata

        # Move up one level
        if current_dir == root_dir:
            break
        current_dir = current_dir.parent

    return None


def process_directory(
    driver: Driver,
    database: str,
    dir_path: str,
    verbosity: int = 1,
    max_files: int = 20,
    cli_ingest_decompiled: bool = True,
) -> None:
    """
    Process all .bcc files in a directory and its subdirectories (recursively).

    Supports hierarchical folder structures at any depth where:
    - Root directory may contain .bcc files and/or subdirectories
    - Each subdirectory at any level can have its own metadata.json
    - .bcc files inherit metadata from the nearest parent directory with metadata.json
    - If no metadata.json is found, defaults are used

    Example structure:
        dataset/lab9/
        ├── benign/
        │   ├── metadata.json          # {"classification": "benign"}
        │   └── bison_arm.bcc          # Uses benign/metadata.json
        └── firmware/
            ├── metadata.json          # {"classification": "unknown", "vendor": "acme"}
            ├── sample1.bcc            # Uses firmware/metadata.json
            └── sample2.bcc

    Args:
        driver: Neo4j driver instance
        database: Database name
        dir_path: Path to directory containing .bcc files and/or subdirectories
        verbosity: 0 (quiet with tqdm), 1 (normal), 2 (verbose)
        max_files: Maximum number of .bcc files to process (0 = no limit, default: 20)
        cli_ingest_decompiled: CLI override for ingesting decompiled code (default: True)
    """
    dir_path_obj = Path(dir_path)
    if not dir_path_obj.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")
    if not dir_path_obj.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {dir_path}")

    # Find all .bcc files recursively
    all_bcc_files = sorted(dir_path_obj.rglob("*.bcc"))

    if not all_bcc_files:
        logger.warning(f"No .bcc files found in directory or subdirectories: {dir_path}")
        return

    # Cache for metadata lookups (directory -> metadata)
    metadata_cache: Dict[Path, Optional[Dict[str, Any]]] = {}

    # Collect all .bcc files with their associated metadata
    # Each entry is (bcc_path, metadata_dict)
    bcc_files_with_metadata: List[Tuple[Path, Optional[Dict[str, Any]]]] = []

    for bcc_file in all_bcc_files:
        metadata = _find_nearest_metadata(bcc_file, dir_path_obj, metadata_cache)
        bcc_files_with_metadata.append((bcc_file, metadata))

    # Log subdirectory breakdown
    subdirs_with_files: Dict[Path, int] = {}
    for bcc_file, _ in bcc_files_with_metadata:
        parent = bcc_file.parent
        subdirs_with_files[parent] = subdirs_with_files.get(parent, 0) + 1

    for subdir, count in sorted(subdirs_with_files.items()):
        rel_path = subdir.relative_to(dir_path_obj) if subdir != dir_path_obj else Path(".")
        logger.info(f"Found {count} .bcc file(s) in: {rel_path}")

    # Apply max_files limit
    total_found = len(bcc_files_with_metadata)
    if max_files > 0 and total_found > max_files:
        bcc_files_with_metadata = bcc_files_with_metadata[:max_files]
        logger.info(f"Limiting to first {max_files} of {total_found} .bcc files")

    if not bcc_files_with_metadata:
        logger.warning(f"No .bcc files found in directory or subdirectories: {dir_path}")
        return

    logger.info(f"Found {len(bcc_files_with_metadata)} .bcc file(s) total in {dir_path}")

    success_count = 0
    error_count = 0

    # Use tqdm for quiet mode, disable for normal/verbose
    use_tqdm = (verbosity == 0)
    iterator = tqdm(bcc_files_with_metadata, desc="Processing .bcc files", unit="file", disable=not use_tqdm)

    for i, (bcc_file, dir_metadata) in enumerate(iterator if use_tqdm else bcc_files_with_metadata, 1):
        if not use_tqdm:
            logger.info(f"\n[{i}/{len(bcc_files_with_metadata)}] Processing: {bcc_file.name}")
            logger.info("-" * 80)

        try:
            # Get metadata for this specific file (uses directory's metadata.json)
            file_metadata = get_binary_metadata(bcc_file.name, dir_metadata)
            # CLI flag overrides metadata setting
            ingest_decompiled = cli_ingest_decompiled or file_metadata.get("ingest_decompiled_code", False)
            add_binary_context(driver, database, str(bcc_file), file_metadata, ingest_decompiled)
            success_count += 1
        except Exception as e:
            logger.error(f"ERROR processing {bcc_file.name}: {e}")
            error_count += 1
            # Continue with next file instead of stopping

    logger.info(f"\nDirectory processing complete: {success_count}/{len(bcc_files_with_metadata)} successful")


def add_binary_context(
    driver: Driver,
    database: str,
    file_path: str,
    metadata: Optional[Dict[str, Any]] = None,
    ingest_decompiled_code: bool = True,
) -> Dict[str, int]:
    """
    Orchestrator: load the context, collect data, and write everything atomically.

    Args:
        driver: Neo4j driver instance
        database: Database name
        file_path: Path to .bcc file
        metadata: Optional metadata dict with classification, tags, and other fields
        ingest_decompiled_code: If True, ingest full decompiled C code for functions (default: True)

    Returns:
        Dictionary with import statistics
    """

    vex_binary_context = load_vex_binary_context(file_path)

    sha256_binary = vex_binary_context.sha256_hash
    binary_name = vex_binary_context.name

    # Convert to absolute path for storage in bcc_file_path attribute
    # This stores the full path to the Binary Context Container (.bcc) file
    absolute_bcc_file_path = str(Path(file_path).resolve())

    # Use provided metadata or default to "unknown"
    if metadata is None:
        metadata = {
            "classification": BinaryClassification.UNKNOWN.value,
            "malware_family": None,
            "tags": [],
            "vendor": None,
            "product": None,
            "firmware_version": None,
            "binary_file_path": None,
        }

    classification = metadata["classification"]
    malware_family = metadata["malware_family"]
    tags = metadata["tags"]
    vendor = metadata["vendor"]
    product = metadata["product"]
    firmware_version = metadata["firmware_version"]
    binary_file_path = metadata["binary_file_path"]

    strings_by_address = collect_strings_from_context(vex_binary_context)
    (
        function_entries,
        block_entries,
        bb_string_uses,
        entry_blocks,
        block_edges,
        orphan_blocks,
        call_function_edges,
        call_import_edges,
        import_entries,
        export_entries,
    ) = collect_structure_from_context(vex_binary_context, strings_by_address, ingest_decompiled_code)

    logger.info(f"Binary: {binary_name} (SHA256: {sha256_binary[:16]}...)")
    logger.info(f"  Classification: {classification}" +
                (f", Family: {malware_family}" if malware_family else "") +
                (f", Vendor: {vendor}" if vendor else "") +
                (f", Product: {product}" if product else "") +
                (f", FW: {firmware_version}" if firmware_version else ""))
    logger.info(f"  Functions: {len(function_entries)}, Blocks: {len(block_entries)}, "
                f"Imports: {len(import_entries)}, Exports: {len(export_entries)}, Strings: {len(bb_string_uses)}")
    logger.debug(f"  Entry blocks: {len(entry_blocks)}, CFG edges: {len(block_edges)}")
    logger.debug(f"  Orphan blocks: {len(orphan_blocks)}")
    logger.debug(f"  Internal calls: {len(call_function_edges)}, Import calls: {len(call_import_edges)}")
    logger.debug(f"  Import entries: {len(import_entries)}")
    logger.debug(f"  Export entries: {len(export_entries)}")

    with driver.session(database=database) as session:
        try:
            session.execute_write(
                write_binary_context_tx,
                sha256_binary=sha256_binary,
                binary_name=binary_name,
                bcc_file_path=absolute_bcc_file_path,
                binary_file_path=binary_file_path,
                classification=classification,
                malware_family=malware_family,
                tags=tags,
                vendor=vendor,
                product=product,
                firmware_version=firmware_version,
                function_entries=function_entries,
                block_entries=block_entries,
                bb_string_uses=bb_string_uses,
                entry_blocks=entry_blocks,
                block_edges=block_edges,
                orphan_blocks=orphan_blocks,
                call_function_edges=call_function_edges,
                call_import_edges=call_import_edges,
                import_entries=import_entries,
                export_entries=export_entries,
            )
        except Exception as e:
            logger.error(f"Error while writing binary context for {sha256_binary}, rolled back: {e}")
            raise

    logger.info("Binary context imported successfully.")

    # Set decompiled_code_ingested flag if decompiled code was ingested
    if ingest_decompiled_code:
        with driver.session(database=database) as session:
            session.run("""
                MATCH (b:Binary {sha256: $sha256})
                SET b.decompiled_code_ingested = true
            """, sha256=sha256_binary)
        logger.info("Decompiled code ingested flag set to true")

    return {
        "num_functions": len(function_entries),
        "num_blocks": len(block_entries),
        "num_string_uses": len(bb_string_uses),
        "num_entry_blocks": len(entry_blocks),
        "num_cfg_edges": len(block_edges),
        "num_orphan_blocks": len(orphan_blocks),
        "num_internal_call_edges": len(call_function_edges),
        "num_import_call_edges": len(call_import_edges),
        "num_import_entries": len(import_entries),
        "num_export_entries": len(export_entries),
    }


def load_binql_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load binql-lite configuration from YAML file.

    Args:
        config_path: Optional path to config file. If None, uses default location.

    Returns:
        Configuration dictionary
    """
    if config_path is None:
        config_path = Path(__file__).parent / "binql_config.yaml"

    if not config_path.exists():
        logger.warning(f"Config file not found: {config_path}. Using defaults.")
        return {
            "bcc_storage": {
                "output_dir": "bccs",
                "persistent": True,
                "organize_by_hash": True,
            },
            "bcc_generation": {
                "timeout": 300,
                "parallel": 0,
                "verbosity": 1,
                "skip_failures": True,
                "min_file_size": 1024,
                "max_file_size": 104857600,
            },
            "binary_filtering": {
                "include_extensions": [],
                "exclude_extensions": [".txt", ".log", ".json", ".md", ".xml", ".html", ".css", ".js"],
                "min_size": 1024,
                "max_size": 104857600,
                "skip_symlinks": True,
                "require_executable": False,
            },
            "metadata_defaults": {
                "classification": "unknown",
                "vendor": None,
                "product": None,
                "firmware_version": None,
                "tags": [],
                "malware_family": None,
            },
        }

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    return config


def get_neo4j_credentials(config_path: Optional[Path] = None) -> Dict[str, str]:
    """
    Get Neo4j credentials from config file and environment variables.

    Priority order:
    1. Environment variables (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE)
    2. binql_config.yaml neo4j section
    3. Hardcoded defaults

    Args:
        config_path: Optional path to binql_config.yaml

    Returns:
        Dictionary with uri, user, password, database keys
    """
    # Load from config file
    config = load_binql_config(config_path)
    neo4j_config = config.get("neo4j", {})

    # Get from environment variables (priority) or config file (fallback) or defaults
    return {
        "uri": os.environ.get("NEO4J_URI", neo4j_config.get("uri", "neo4j://127.0.0.1:7687")),
        "user": os.environ.get("NEO4J_USER", neo4j_config.get("user", "neo4j")),
        "password": os.environ.get("NEO4J_PASSWORD", neo4j_config.get("password", "12345678")),
        "database": os.environ.get("NEO4J_DATABASE", neo4j_config.get("database", "neo4j")),
    }



def execute_cypher_query(
    driver: Driver,
    database: str,
    query: str,
    limit: int = 25,
    output_format: str = "table",
) -> None:
    """
    Execute a raw Cypher query and display results.

    Args:
        driver: Neo4j driver instance
        database: Database name
        query: Cypher query string to execute
        limit: Maximum number of results (0 = no limit)
        output_format: Output format - 'table', 'json', or 'csv'
    """
    # Add LIMIT clause if not already present and limit > 0
    query_upper = query.upper().strip()
    if limit > 0 and "LIMIT" not in query_upper:
        query = f"{query.rstrip().rstrip(';')} LIMIT {limit}"

    logger.info(f"Executing Cypher query...")
    logger.debug(f"Query: {query}")

    try:
        with driver.session(database=database) as session:
            result = session.run(query)
            records = list(result)
            keys = result.keys() if records else []

            if not records:
                print("\n(No results)")
                return

            if output_format == "json":
                _print_results_json(records, keys)
            elif output_format == "csv":
                _print_results_csv(records, keys)
            else:  # table format (default)
                _print_results_table(records, keys)

            print(f"\n({len(records)} row{'s' if len(records) != 1 else ''})")

    except Neo4jError as e:
        logger.error(f"Query execution failed: {e.message}")
        raise


def _print_results_table(records: list, keys: list) -> None:
    """Print query results in a formatted table."""
    if not records or not keys:
        return

    # Calculate column widths
    col_widths = {key: len(str(key)) for key in keys}
    for record in records:
        for key in keys:
            value = record.get(key)
            value_str = _format_value(value)
            col_widths[key] = max(col_widths[key], len(value_str))

    # Cap column widths at 60 characters for readability
    col_widths = {k: min(v, 60) for k, v in col_widths.items()}

    # Print header
    header = " | ".join(str(key).ljust(col_widths[key]) for key in keys)
    separator = "-+-".join("-" * col_widths[key] for key in keys)
    print(f"\n{header}")
    print(separator)

    # Print rows
    for record in records:
        row_values = []
        for key in keys:
            value = record.get(key)
            value_str = _format_value(value)
            # Truncate long values
            if len(value_str) > col_widths[key]:
                value_str = value_str[:col_widths[key] - 3] + "..."
            row_values.append(value_str.ljust(col_widths[key]))
        print(" | ".join(row_values))


def _print_results_json(records: list, keys: list) -> None:
    """Print query results as JSON."""
    import json as json_module
    output = []
    for record in records:
        row = {}
        for key in keys:
            value = record.get(key)
            row[key] = _serialize_value(value)
        output.append(row)
    print(json_module.dumps(output, indent=2, default=str))


def _print_results_csv(records: list, keys: list) -> None:
    """Print query results as CSV."""
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(keys)
    for record in records:
        row = [_format_value(record.get(key)) for key in keys]
        writer.writerow(row)
    print(output.getvalue().strip())


def _format_value(value) -> str:
    """Format a Neo4j value for display."""
    if value is None:
        return ""
    if isinstance(value, list):
        # Format lists compactly
        if len(value) == 0:
            return "[]"
        if len(value) <= 3:
            return "[" + ", ".join(_format_value(v) for v in value) + "]"
        return f"[{_format_value(value[0])}, ... ({len(value)} items)]"
    if isinstance(value, dict):
        return str(value)
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _serialize_value(value):
    """Serialize a Neo4j value for JSON output."""
    if value is None:
        return None
    if isinstance(value, list):
        return [_serialize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    if hasattr(value, '__dict__'):
        # Handle Neo4j node/relationship objects
        return dict(value)
    return value


def parse_args():
    # Load Neo4j credentials from config + environment variables
    creds = get_neo4j_credentials()

    parser = argparse.ArgumentParser(
        description="Create Neo4j constraints and import binary contexts. "
                    "Automatically initializes database if constraints don't exist."
    )
    parser.add_argument(
        "--uri",
        default=creds["uri"],
        help=f"Neo4j URI (default: {creds['uri']}, from binql_config.yaml or NEO4J_URI env var)",
    )
    parser.add_argument(
        "--user",
        default=creds["user"],
        help=f"Neo4j username (default: {creds['user']}, from binql_config.yaml or NEO4J_USER env var)",
    )
    parser.add_argument(
        "--password",
        default=creds["password"],
        help=f"Neo4j password (default from binql_config.yaml or NEO4J_PASSWORD env var)",
    )
    parser.add_argument(
        "--db",
        "--database",
        dest="database",
        default=TARGET_DB,
        help=f"Target database name (default: {TARGET_DB})",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop and recreate the target database before applying constraints.",
    )
    parser.add_argument(
        "--check-db",
        action="store_true",
        help="Check Neo4j connectivity and authentication, then exit. "
             "Useful as a quick liveness check before running ingestion.",
    )
    parser.add_argument(
        "--bcc", "--binary_context",
        dest="binary_context",
        type=str,
        help="Path to a .bcc file to load and create/update a Binary and its StringLiteral nodes.",
    )
    parser.add_argument(
        "--bcc_dir", "--binary_context_dir",
        dest="binary_context_dir",
        type=str,
        help="Path to a directory containing .bcc files. All .bcc files in the directory will be imported.",
    )
    parser.add_argument(
        "--update-decompiled-code",
        type=str,
        metavar="SHA256",
        help="Update existing binary in Neo4j with decompiled code from its stored BCC file. "
             "Requires binary to be already ingested with --bcc. "
             "Example: --update-decompiled-code abc123...",
    )
    parser.add_argument(
        "--update-all-decompiled-code",
        action="store_true",
        help="Update ALL binaries in Neo4j that don't have decompiled code. "
             "Batch operation that processes all binaries with stored BCC paths. "
             "Use with caution on large databases.",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to binql_config.yaml configuration file (default: labs/lab1/binql_config.yaml). "
             "Used for binary ingestion settings, BCC storage, and filtering rules.",
    )
    parser.add_argument(
        "--max_files",
        type=int,
        default=20,
        help="Maximum number of files to process from directory (0 = no limit, default: 20). "
             "Applies to --bcc_dir.",
    )
    parser.add_argument(
        "--list-binaries", "--list_binaries",
        action="store_true",
        dest="list_binaries",
        help="List all ingested Binary nodes in the database with SHA256, name, and function count",
    )
    parser.add_argument(
        "--ingest_decompiled_code",
        action="store_true",
        default=True,
        dest="ingest_decompiled_code",
        help="Ingest full decompiled C code for functions into Neo4j (default: enabled). "
             "Required for CVE triage, vulnerability analysis, and patch diff workflows. "
             "Use --skip-decompiled-code to disable.",
    )
    parser.add_argument(
        "--skip-decompiled-code",
        action="store_false",
        dest="ingest_decompiled_code",
        help="Skip ingesting decompiled C code for functions. "
             "Reduces storage requirements and ingestion time, but disables "
             "CVE triage, vulnerability analysis, and patch diff detailed analysis.",
    )
    parser.add_argument(
        "--cypher",
        type=str,
        metavar="QUERY",
        help="Execute a raw Cypher query against the database and display results. "
             "Use with --limit to control number of results. "
             "Example: --cypher 'MATCH (b:Binary) RETURN b.name LIMIT 5'",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum number of results to return for --cypher queries (default: 25). "
             "Set to 0 for no limit.",
    )
    parser.add_argument(
        "--output-format",
        type=str,
        choices=["table", "json", "csv"],
        default="table",
        dest="output_format",
        help="Output format for --cypher query results (default: table). "
             "Options: table (human-readable), json (machine-readable), csv (spreadsheet).",
    )
    parser.add_argument(
        "-v", "--verbose",
        dest="verbosity",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Verbosity: 0 (quiet/progress bar only), 1 (normal/suppress binarycontext INFO), "
             "2 (verbose/show all details) (default: 1)",
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point for binql-lite."""
    args = parse_args()

    # Setup logging based on verbosity
    setup_logging(args.verbosity)

    # Attempt to connect to Neo4j with user-friendly error messages
    try:
        gdb_driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    except ServiceUnavailable as e:
        logger.error("=" * 80)
        logger.error("ERROR: Cannot connect to Neo4j")
        logger.error("=" * 80)
        logger.error("")
        logger.error("Possible causes:")
        logger.error("  1. Neo4j is not running")
        logger.error("  2. Neo4j is not listening on %s", args.uri)
        logger.error("  3. Firewall is blocking the connection")
        logger.error("")
        logger.error("Solutions:")
        logger.error("  • Start Neo4j: sudo systemctl start neo4j")
        logger.error("  • Check Neo4j status: sudo systemctl status neo4j")
        logger.error("  • Verify URI is correct (current: %s)", args.uri)
        logger.error("")
        logger.error("Technical details: %s", str(e))
        logger.error("=" * 80)
        return
    except AuthError as e:
        logger.error("=" * 80)
        logger.error("ERROR: Authentication failed")
        logger.error("=" * 80)
        logger.error("")
        logger.error("Invalid username or password for Neo4j.")
        logger.error("  Current user: %s", args.user)
        logger.error("")
        logger.error("Solutions:")
        logger.error("  • Verify credentials are correct")
        logger.error("  • Use --user and --password arguments to specify credentials")
        logger.error("")
        logger.error("Technical details: %s", str(e))
        logger.error("=" * 80)
        return
    except Exception as e:
        logger.error("=" * 80)
        logger.error("ERROR: Unexpected error connecting to Neo4j")
        logger.error("=" * 80)
        logger.error("")
        logger.error("Technical details: %s", str(e))
        logger.error("=" * 80)
        return

    try:
        if args.check_db:
            try:
                gdb_driver.verify_connectivity()

                # Run a minimal query to validate that sessions work.
                # IMPORTANT: `RETURN ...` is only allowed in a user database (not `system`).
                # Prefer the configured target DB, but fall back to `neo4j` if the configured DB does not exist.
                database_candidates = [args.database]
                if args.database != "neo4j":
                    database_candidates.append("neo4j")

                last_error: Exception | None = None
                for database_name in database_candidates:
                    try:
                        with gdb_driver.session(database=database_name) as session:
                            session.run("RETURN 1 AS ok").consume()
                        last_error = None
                        break
                    except Neo4jError as e:
                        last_error = e
                        continue

                if last_error is not None:
                    raise last_error

                logger.info("✓ Neo4j liveness check passed (connectivity + credentials OK)")
            except (ServiceUnavailable, AuthError) as e:
                logger.error("✗ Neo4j liveness check failed: %s", str(e))
                return
            except Exception as e:
                logger.error("✗ Neo4j liveness check failed (unexpected error): %s", str(e))
                return
            else:
                return

        # Handle --cypher query execution
        if args.cypher:
            execute_cypher_query(gdb_driver, args.database, args.cypher, args.limit, args.output_format)
            return

        if args.reset:
            reset_database(gdb_driver, args.database)
            # After reset, always create constraints
            create_constraints(gdb_driver, args.database)
        else:
            # Check if database is initialized (has constraints)
            if not check_constraints_exist(gdb_driver, args.database):
                logger.info(f"No constraints found in database '{args.database}'. Initializing...")
                create_constraints(gdb_driver, args.database)
            else:
                logger.info(f"Database '{args.database}' already initialized (constraints exist).")

        # Load configuration if provided
        config = None
        if args.config:
            config = load_binql_config(Path(args.config))

        # Handle binary context import (mutually exclusive)
        modes = [args.binary_context, args.binary_context_dir]
        active_modes = [m for m in modes if m]

        if len(active_modes) > 1:
            logger.error("ERROR: Cannot specify multiple modes. Choose one of: --bcc, --bcc_dir")
            return

        if args.binary_context:
            # Deep ingest: single .bcc file
            bcc_path = Path(args.binary_context)
            parent_dir = bcc_path.parent
            metadata_dict = load_metadata_file(parent_dir)
            file_metadata = get_binary_metadata(bcc_path.name, metadata_dict)
            # CLI flag overrides metadata setting
            ingest_decompiled = args.ingest_decompiled_code or file_metadata.get("ingest_decompiled_code", False)
            add_binary_context(gdb_driver, args.database, args.binary_context, file_metadata, ingest_decompiled)
        elif args.binary_context_dir:
            # Deep ingest: directory of .bcc files
            process_directory(
                gdb_driver,
                args.database,
                args.binary_context_dir,
                args.verbosity,
                args.max_files,
                args.ingest_decompiled_code,
            )
        elif args.update_decompiled_code or args.update_all_decompiled_code:
            # Update existing binaries with decompiled code
            try:
                logger.info("=" * 60)
                if args.update_all_decompiled_code:
                    logger.info("UPDATE ALL BINARIES: Decompiled Code Ingestion")
                else:
                    logger.info("UPDATE BINARY: Decompiled Code Ingestion")
                logger.info("=" * 60)

                stats = update_binary_decompiled_code(
                    driver=gdb_driver,
                    database=args.database,
                    sha256=args.update_decompiled_code,
                    update_all=args.update_all_decompiled_code,
                    force=False,  # TODO: Add --force flag if needed
                )

                logger.info("=" * 60)
                logger.info("UPDATE COMPLETE")
                logger.info("=" * 60)
                logger.info(f"  Binaries updated:  {stats['binaries_updated']}")
                logger.info(f"  Functions updated: {stats['functions_updated']}")
                if stats["binaries_failed"] > 0:
                    logger.info(f"  Binaries failed:   {stats['binaries_failed']}")
                logger.info("=" * 60)

            except (FileNotFoundError, ValueError) as e:
                logger.error(f"ERROR: {e}")
                return
        elif args.list_binaries:
            # List all ingested Binary nodes
            try:
                print("=" * 60)
                print("INGESTED BINARIES")
                print("=" * 60)

                with gdb_driver.session(database=args.database) as session:
                    result = session.run("""
                        MATCH (b:Binary)
                        OPTIONAL MATCH (b)-[:HAS_FUNCTION]->(f:Function)
                        WITH b, count(f) as function_count
                        RETURN
                            b.sha256 AS sha256,
                            b.name AS name,
                            b.classification AS classification,
                            b.bcc_file_path AS bcc_file_path,
                            b.decompiled_code_ingested AS decompiled_code_ingested,
                            function_count
                        ORDER BY b.name, b.sha256
                    """)

                    binaries = list(result)

                    if not binaries:
                        print("\nNo binaries found in database.\n")
                    else:
                        print(f"\nFound {len(binaries)} binary(ies):\n")
                        print("-" * 140)
                        print(
                            f"{'Name':<35} {'SHA256':<66} {'Funcs':<6} {'BCC':<5} {'Decomp':<7} {'Class':<15}"
                        )
                        print("-" * 140)

                        for record in binaries:
                            sha256 = record["sha256"] or "N/A"
                            name = record["name"] or "N/A"
                            classification = record["classification"] or "N/A"
                            function_count = record["function_count"]
                            bcc_exists = "✓" if record["bcc_file_path"] else "✗"
                            decompiled = "✓" if record["decompiled_code_ingested"] else "✗"

                            # Truncate name if too long
                            if len(name) > 33:
                                name = name[:30] + "..."

                            print(
                                f"{name:<35} {sha256:<66} {function_count:<6} {bcc_exists:<5} {decompiled:<7} {classification:<15}"
                            )

                        print("-" * 140)
                        print(f"\nTotal: {len(binaries)} binary(ies)")
                        print("Legend: BCC = BCC file path stored, Decomp = Decompiled code ingested")
                        print("        Class = Classification (unknown, benign, malicious, suspicious)")

                print("=" * 60)

            except Exception as e:
                logger.error(f"ERROR: {e}")
                return

    finally:
        gdb_driver.close()


if __name__ == "__main__":
    main()


