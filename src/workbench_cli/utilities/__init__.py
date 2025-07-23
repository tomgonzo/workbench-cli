"""
Utilities package for the Workbench CLI.

This package contains utility functions for scan workflows, target validation,
archive preparation, and error handling.
"""

from .error_handling import format_and_print_error, handler_error_wrapper
from .scan_workflows import (
    wait_for_scan_completion,
    determine_scans_to_run,
    fetch_results,
    display_results,
    save_results_to_file,
    fetch_display_save_results,
    format_duration,
    print_operation_summary,
)
from .scan_target_validators import (
    ensure_scan_compatibility,
    validate_reuse_source,
)
from .prep_upload_archive import UploadArchivePrep
from .bazel_utils import BazelUtils
from .git_utils import GitUtils

__all__ = [
    # Error handling
    'format_and_print_error',
    'handler_error_wrapper',
    # Scan workflows
    'wait_for_scan_completion',
    'determine_scans_to_run',
    'fetch_results',
    'display_results',
    'save_results_to_file',
    'fetch_display_save_results',
    'format_duration',
    'print_operation_summary',
    # Target validation
    'ensure_scan_compatibility',
    'validate_reuse_source',
    # Archive preparation
    'UploadArchivePrep',
    # Bazel utilities
    'BazelUtils',
    # Git utilities
    'GitUtils',
] 
