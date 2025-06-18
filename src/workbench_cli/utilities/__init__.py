"""
Utilities package for the Workbench CLI.

This package contains utility functions for scan workflows, target validation,
archive preparation, and error handling.
"""

from .error_handling import format_and_print_error, handler_error_wrapper
from .scan_workflows import (
    assert_scan_is_idle,
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
from .git_diff_utils import get_git_repo_root, get_changed_files, create_diff_archive
from .ref_autodetection import autodetect_git_refs

__all__ = [
    # Error handling
    'format_and_print_error',
    'handler_error_wrapper',
    # Scan workflows
    'assert_scan_is_idle',
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
    # Git Diff Scanning
    'get_git_repo_root',
    'get_changed_files',
    'create_diff_archive',
    'autodetect_git_refs',
] 