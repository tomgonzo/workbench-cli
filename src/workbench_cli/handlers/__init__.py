# workbench_cli/handlers/__init__.py

import logging

# Common logger for all handlers
logger = logging.getLogger("workbench-cli")

# Import handlers
from .scan import handle_scan
from .scan_git import handle_scan_git
from .import_da import handle_import_da
from .import_sbom import handle_import_sbom
from .show_results import handle_show_results
from .evaluate_gates import handle_evaluate_gates
from .download_reports import handle_download_reports
from .export_sarif import handle_export_sarif
from .export_vulns import handle_export_vulns

__all__ = [
    'handle_scan',
    'handle_scan_git',
    'handle_import_da',
    'handle_import_sbom',
    'handle_show_results',
    'handle_evaluate_gates',
    'handle_download_reports',
    'handle_export_sarif',
    'handle_export_vulns'
]
