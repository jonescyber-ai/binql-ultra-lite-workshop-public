"""
Common utilities and constants for the BinQL Ultra-Lite Workshop.
This module provides shared constants, enums, dataclasses, and utility functions
used across multiple labs.

Module Organization:
    1. Imports
    2. Constants (module-level configuration values)
    3. Enums and Dataclasses
    4. Functions
"""
import multiprocessing
import os
from enum import Enum
from pathlib import Path

# =============================================================================
# Constants
# =============================================================================

# Project root path - computed once at module load
ROOT_PROJECT_FOLDER_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Random seed for reproducibility
RANDOM_SEED = 0

# Function size constraints
MIN_FUNCTION_SIZE = 100
DEFAULT_MIN_FUNCTION_SIZE = 25
DEFAULT_MAX_FUNCTION_SIZE = 3000

# Cache and performance settings
DEFAULT_LRU_CACHE_MAX_SIZE = 1024
NUM_CPUS = multiprocessing.cpu_count()

# Function name patterns to ignore during analysis
IGNORE_FUNCTION_NAMES = ["sub_", "GLOBAL_", "_start", "register_tm", "__do", "frame_dummy", "operator"]


# =============================================================================
# Enums and Dataclasses
# =============================================================================

class Label(Enum):
    BENIGN = 1
    MALWARE = 2
    MATCH = 3
    NO_MATCH = 4
    NONE = 5


class VerbosityLevel(Enum):
    """
    Verbosity levels for logging and output control.

    SILENT (0): No output
        - Suppresses progress bars
        - Suppresses all print statements
        - Suppresses work queue status messages
        - Suppresses summary statistics

    NORMAL (1): Standard output (default)
        - Shows progress bars
        - Shows summary statistics at completion
        - Suppresses work queue status messages
        - Suppresses debug warnings

    VERBOSE (2): Detailed output
        - Shows progress bars
        - Shows summary statistics
        - Shows work queue status messages
        - Shows debug warnings (e.g., ambiguous call preferences)
    """
    SILENT = 0
    NORMAL = 1
    VERBOSE = 2


# =============================================================================
# Functions
# =============================================================================

def get_project_root() -> str:
    """
    Get the absolute path to the project root directory.

    Returns:
        Absolute path to the project root as a string.

    Example:
        >>> from lab_common.common import get_project_root
        >>> root = get_project_root()
        >>> print(root)  # <project_root>/binql-ultra-lite-workshop
    """
    return ROOT_PROJECT_FOLDER_PATH


def get_output_dir(lab_name: str, create: bool = True) -> str:
    """
    Get the output directory path for a specific lab.

    All lab outputs should be written to `project_root/output/<lab_name>/` for consistency.
    This function ensures the directory exists (by default) and returns the absolute path.

    Args:
        lab_name: Name of the lab (e.g., "lab1", "lab2"). Used as subdirectory name.
        create: If True (default), create the directory if it doesn't exist.

    Returns:
        Absolute path to the output directory as a string.

    Example:
        >>> from lab_common.common import get_output_dir
        >>> output_dir = get_output_dir("lab1")
        >>> print(output_dir)  # <project_root>/binql-ultra-lite-workshop/output/lab1
    """
    output_path = os.path.join(ROOT_PROJECT_FOLDER_PATH, "output", lab_name)
    if create:
        os.makedirs(output_path, exist_ok=True)
    return output_path
