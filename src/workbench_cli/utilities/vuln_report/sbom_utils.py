"""
SBOM utilities for vulnerability report augmentation workflows.

This module provides SBOM download and resource management functionality
used by augmentation flows to work with existing SBOMs across multiple formats.
"""

import logging
import tempfile
import argparse
import os
from contextlib import contextmanager
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...api import WorkbenchAPI

logger = logging.getLogger(__name__)


def download_sbom(
    workbench: "WorkbenchAPI",
    scan_code: str,
    *,
    sbom_format: str = "cyclonedx",
    include_vex: bool = True,
    params: Optional[argparse.Namespace] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Download a scan-level SBOM from Workbench for augmentation."""
    fmt_normalised = sbom_format.lower()
    
    if fmt_normalised not in {"cyclonedx", "cyclone_dx", "cdx"}:
        if not quiet:
            print(f"   ℹ️  SBOM format '{sbom_format}' not yet supported")
        return None

    report_type = "cyclone_dx"

    try:
        is_async = report_type in workbench.ASYNC_REPORT_TYPES
        if not quiet:
            print(f"   📡 Generating SBOM {'asynchronously' if is_async else 'synchronously'}...")

        if is_async:
            process_id = workbench.generate_scan_report(scan_code, report_type=report_type, include_vex=include_vex)
            workbench._wait_for_process(
                process_description=f"SBOM generation (Process ID: {process_id})",
                check_function=workbench.check_scan_report_status,
                check_args={"process_id": process_id, "scan_code": scan_code},
                status_accessor=lambda d: d.get("progress_state", "UNKNOWN"),
                success_values={"FINISHED"},
                failure_values={"FAILED", "CANCELLED", "ERROR"},
                max_tries=getattr(params, "scan_number_of_tries", 60) if params else 60,
                wait_interval=3,
                progress_indicator=not quiet,
            )
            response = workbench.download_scan_report(process_id)
        else:
            response = workbench.generate_scan_report(scan_code, report_type=report_type, include_vex=include_vex)

        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            content = response.content.decode("utf-8") if hasattr(response, "content") else str(response)
            tmp.write(content)
            if not quiet:
                print(f"   ✅ SBOM downloaded → {tmp.name}")
            return tmp.name

    except Exception as exc:
        logger.debug(f"SBOM download failed: {exc}")
        return None


@contextmanager
def managed_sbom_download(
    workbench: "WorkbenchAPI",
    scan_code: str,
    *,
    sbom_format: str = "cyclonedx",
    include_vex: bool = True,
    params: Optional[argparse.Namespace] = None,
    quiet: bool = False
):
    """
    Context manager for SBOM download with automatic cleanup.
    
    Provides automatic resource management for downloaded SBOM files,
    ensuring cleanup even if exceptions occur during processing.
    
    Args:
        workbench: The Workbench API client
        scan_code: The scan identifier
        sbom_format: SBOM format to download ("cyclonedx", "spdx", etc.)
        include_vex: Whether to include VEX data in the SBOM
        params: Optional command line parameters
        quiet: If True, suppress progress messages
        
    Yields:
        Optional[str]: Path to the downloaded SBOM file, or None if download failed
        
    Example:
        with managed_sbom_download(workbench, scan_code, quiet=params.quiet) as sbom_path:
            if sbom_path:
                # Process the SBOM file
                process_sbom(sbom_path)
            # File is automatically cleaned up here
    """
    sbom_path = None
    try:
        # Download the SBOM
        sbom_path = download_sbom(
            workbench=workbench,
            scan_code=scan_code,
            sbom_format=sbom_format,
            include_vex=include_vex,
            params=params,
            quiet=quiet
        )
        
        if sbom_path and not quiet:
            print(f"   📥 Downloaded SBOM: {os.path.basename(sbom_path)}")
        
        # Yield the path to the caller
        yield sbom_path
        
    finally:
        # Cleanup: Remove the temporary file if it exists
        if sbom_path and os.path.exists(sbom_path):
            try:
                os.unlink(sbom_path)
                logger.debug(f"Cleaned up temporary SBOM file: {sbom_path}")
                if not quiet and sbom_path:
                    print(f"   🧹 Cleaned up temporary SBOM file")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary SBOM file {sbom_path}: {e}")
                # Don't raise exception during cleanup - just log the warning


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "download_sbom",
    "managed_sbom_download",
] 