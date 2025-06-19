# workbench_cli/cli.py

import argparse
import os
import logging
from argparse import RawTextHelpFormatter

# Import WorkbenchAPI to access report type constants
from .api import WorkbenchAPI
from .exceptions import ValidationError

logger = logging.getLogger(__name__)

# --- Helper functions for common arguments ---
def add_common_scan_options(subparser):
    scan_options_args = subparser.add_argument_group("KB Scan Options")
    scan_options_args.add_argument("--limit", help="Limits KB scan results (Default: 10)", type=int, default=10)
    scan_options_args.add_argument("--sensitivity", help="Sets KB snippet sensitivity (Default: 10)", type=int, default=10)
    scan_options_args.add_argument("--autoid-file-licenses", help="Auto-Identify license declarations in files.", action="store_true", default=False)
    scan_options_args.add_argument("--autoid-file-copyrights", help="Auto-Identify copyright statements in files.", action="store_true", default=False)
    scan_options_args.add_argument("--autoid-pending-ids", help="Auto-Identify pending files using the Top Match.", action="store_true", default=False)
    scan_options_args.add_argument("--delta-scan", help="For KB scans, only scan new/modified files with Delta Scan.", action="store_true", default=False)
    scan_options_args.add_argument("--id-reuse", help="Enable reuse of existing identifications to speed up scan process.", action="store_true", default=False)
    scan_options_args.add_argument(
        "--id-reuse-type",
        help="Specify the source type for identification reuse:\n"
             "  'any'     - use any existing identification in the system\n"
             "  'only_me' - only reuse identifications made by the current user token\n"
             "  'project' - reuse identifications from a specific project (requires --id-reuse-source)\n"
             "  'scan'    - reuse identifications from a specific scan (requires --id-reuse-source)",
        choices=["any", "only_me", "project", "scan"],
        default="any"
    )
    scan_options_args.add_argument("--id-reuse-source", help="Name of the project or scan to reuse identifications from.\n"
                                "Required when --id-reuse-type is 'project' or 'scan'.", 
                                metavar="NAME")
    scan_options_args.add_argument("--run-dependency-analysis", help="Run dependency analysis after KB scan.", action="store_true", default=False)
    scan_options_args.add_argument("--dependency-analysis-only", help="Run dependency analysis without performing a KB scan. Mutually exclusive with --run-dependency-analysis.", action="store_true", default=False)
    scan_options_args.add_argument("--no-wait", help="Exit after confirming scan has started instead of waiting for completion.", action="store_true", default=False)


def add_common_monitoring_options(subparser):
    monitor_args = subparser.add_argument_group("Scan Monitoring Options")
    monitor_args.add_argument("--scan-number-of-tries", help="Number of status checks before timeout (Default: 960)", type=int, default=960)
    monitor_args.add_argument("--scan-wait-time", help="Seconds between status checks (Default: 30)", type=int, default=30)

def add_common_result_options(subparser):
    results_display_args = subparser.add_argument_group("Result Display & Save Options")
    results_display_args.add_argument("--show-licenses", help="Shows all licenses found by the identification process.", action="store_true", default=False)
    results_display_args.add_argument("--show-components", help="Shows all components found by the identification process.", action="store_true", default=False)
    results_display_args.add_argument("--show-dependencies", help="Shows all components found by Dependency Analysis.", action="store_true", default=False)
    results_display_args.add_argument("--show-scan-metrics", help="Show metrics on file identifications (total files, pending id, identified, no matches).", action="store_true", default=False)
    results_display_args.add_argument("--show-policy-warnings", help="Shows Policy Warnings in identified components or dependencies.", action="store_true", default=False)
    results_display_args.add_argument("--show-vulnerabilities", help="Shows a summary of vulnerabilities found in the scan.", action="store_true", default=False)
    results_display_args.add_argument("--path-result", help="Saves the requested results to this file/directory (JSON format).", metavar="PATH")

# --- Main Parsing Function ---
def parse_cmdline_args():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
        
    Raises:
        ValidationError: If required arguments are missing or invalid
    """
    parser = argparse.ArgumentParser(
        description="FossID Workbench CLI - A command-line tool for interacting with FossID Workbench.",
        formatter_class=RawTextHelpFormatter,
        epilog="""
Environment Variables for Credentials:
  WORKBENCH_URL    : API Endpoint URL (e.g., https://workbench.example.com/api.php)
  WORKBENCH_USER   : Workbench Username
  WORKBENCH_TOKEN  : Workbench API Token

Example Usage:
  # Full scan uploading a directory, show results
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    scan --project-name MYPROJ --scan-name MYSCAN01 --path ./src --run-dependency-analysis --show-components --show-licenses

  # Scan using identification reuse from a specific project
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    scan --project-name MYPROJ --scan-name MYSCAN02 --path ./src --id-reuse --id-reuse-type project --id-reuse-source "MyBaseProject"

  # Import DA results only
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    import-da --project-name MYPROJ --scan-name MYSCAN03 --path ./ort-test-data/analyzer-result.json

  # Show results for an existing scan
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    show-results --project-name MYPROJ --scan-name MYSCAN01 --show-licenses --show-components

  # Evaluate gates for a scan
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    evaluate-gates --project-name MYPROJ --scan-name MYSCAN01 --policy-check --show-pending-files

  # Scan a Git repository
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    scan-git --project-name MYGITPROJ --scan-name MYGITSCAN01 --git-url https://github.com/owner/repo.git --git-branch develop

  # Download reports for a project
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    download-reports --project-name MYPROJ --report-scope project --report-type xlsx,spdx --report-save-path reports/

  # Download all available reports for a project
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    download-reports --project-name MYPROJ --report-scope project --report-save-path reports/

  # Download reports for a specific scan (globally)
  workbench-cli --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    download-reports --scan-name MYSCAN01 --report-scope scan --report-type html --report-save-path reports/
"""
    )

    # --- Global Arguments (apply to all subcommands) ---
    global_args = parser.add_argument_group("Global Arguments")
    global_args.add_argument(
        "--api-url",
        help="API Endpoint URL (e.g., https://workbench.example.com/api.php). Overrides WORKBENCH_URL env var.",
        default=os.getenv("WORKBENCH_URL"),
        required=not os.getenv("WORKBENCH_URL"), # Required if not in env
        metavar="URL"
    )
    global_args.add_argument(
        "--api-user",
        help="Workbench Username. Overrides WORKBENCH_USER env var.",
        default=os.getenv("WORKBENCH_USER"),
        required=not os.getenv("WORKBENCH_USER"), # Required if not in env
        metavar="USER"
    )
    global_args.add_argument(
        "--api-token",
        help="Workbench API Token. Overrides WORKBENCH_TOKEN env var.",
        default=os.getenv("WORKBENCH_TOKEN"),
        required=not os.getenv("WORKBENCH_TOKEN"), # Required if not in env
        metavar="TOKEN"
    )
    global_args.add_argument(
        "--log",
        help="Logging level (Default: INFO)",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )

    # --- Subparsers ---
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True, metavar='COMMAND')

    # --- 'scan' Subcommand ---
    scan_parser = subparsers.add_parser(
        'scan',
        help='Run a standard scan by uploading code.',
        description='Run a standard scan by uploading a local directory or file to Workbench.',
        formatter_class=RawTextHelpFormatter
    )
    scan_parser.add_argument("--project-name", help="Project Name to associate the scan with.", required=True, metavar="NAME")
    scan_parser.add_argument("--scan-name", help="Scan Name to create or use.", required=True, metavar="NAME")
    scan_parser.add_argument("--path", help="Local directory/file to upload and scan.", required=True, metavar="PATH")
    scan_parser.add_argument("--recursively-extract-archives", help="Recursively extract nested archives (Default: True).", action=argparse.BooleanOptionalAction, default=True)
    scan_parser.add_argument("--jar-file-extraction", help="Control extraction of jar files (Default: False).", action=argparse.BooleanOptionalAction, default=False)
    add_common_scan_options(scan_parser)
    add_common_monitoring_options(scan_parser)
    add_common_result_options(scan_parser)

    # --- 'import-da' Subcommand ---
    import_da_parser = subparsers.add_parser(
        'import-da',
        help='Import Dependency Analysis results from a file.',
        description='Import Dependency Analysis results from an analyzer-result.json file.',
        formatter_class=RawTextHelpFormatter
    )
    import_da_parser.add_argument("--project-name", help="Project name to associate the scan with.", type=str, required=True, metavar="NAME")
    import_da_parser.add_argument("--scan-name", help="Scan name to import DA results into.", type=str, required=True, metavar="NAME")
    import_da_parser.add_argument("--path", help="Path to the 'analyzer-result.json' file to be imported.", type=str, required=True)
    add_common_monitoring_options(import_da_parser)
    add_common_result_options(import_da_parser)

    # --- 'show-results' Subcommand ---
    show_results_parser = subparsers.add_parser(
        'show-results',
        help='Fetch and display results for an existing scan.',
        description='Fetch and display results for an existing scan, optionally saving them to a file.',
        formatter_class=RawTextHelpFormatter
    )
    show_results_parser.add_argument("--scan-name", help="Scan Name to fetch results for.", required=True, metavar="NAME")
    show_results_parser.add_argument("--project-name", help="Project Name containing the scan.", required=True, metavar="NAME")
    add_common_monitoring_options(show_results_parser)
    add_common_result_options(show_results_parser)

    # --- 'evaluate-gates' Subcommand ---
    evaluate_gates_parser = subparsers.add_parser(
        'evaluate-gates',
        help='Check scan status and policy violations.',
        description='Checks scan completion, pending IDs, and policy violations. Sets exit code based on --fail-on.',
        formatter_class=RawTextHelpFormatter
    )
    evaluate_gates_parser.add_argument("--project-name", help="Project name containing the scan.", type=str, required=True, metavar="NAME")
    evaluate_gates_parser.add_argument("--scan-name", help="Scan name to evaluate gates for.", type=str, required=True, metavar="NAME")
    evaluate_gates_parser.add_argument("--show-pending-files", help="Display the File Names with Pending IDs.", action="store_true", default=False)
    evaluate_gates_parser.add_argument(
        "--fail-on-vuln-severity",
        help="Fail if vulnerabilities of this severity OR HIGHER are found.",
        choices=['critical', 'high', 'medium', 'low'],
        default=None, # Default is None, meaning don't fail based on severity unless specified
        metavar='SEVERITY'
    )
    evaluate_gates_parser.add_argument(
        "--fail-on-pending",
        help="Fail the gate if any files are found in the 'Pending Identification' state.",
        action="store_true"
    )
    evaluate_gates_parser.add_argument(
        "--fail-on-policy",
        help="Fail the gate if any policy violations are found.",
        action="store_true"
    )
    add_common_monitoring_options(evaluate_gates_parser)

    # --- 'download-reports' Subcommand ---
    download_reports_parser = subparsers.add_parser(
        'download-reports',
        help='Generate and download reports for a scan or project.',
        description='Generate and download reports for a completed scan or project.',
        formatter_class=RawTextHelpFormatter
    )
    download_reports_parser.add_argument(
        "--project-name",
        help="Name of the Project (required if --report-scope is 'project', optional otherwise).",
        metavar="NAME"
    )
    # scan-name is required unless scope is project (handled in post-parsing validation)
    download_reports_parser.add_argument(
        "--scan-name",
        help="Scan Name to generate reports for (required if --report-scope is 'scan').",
        metavar="NAME"
    )
    download_reports_parser.add_argument(
        "--report-scope",
        help="Scope of the report (Default: scan). Use 'project' for project-level reports.",
        choices=["scan", "project"],
        default="scan",
        metavar="SCOPE"
    )
    download_reports_parser.add_argument(
        "--report-type",
        help="Report types to generate and download. Multiple types can be comma-separated.\n"
             f"For Scans (Default Scope): {', '.join(sorted(list(WorkbenchAPI.SCAN_REPORT_TYPES)))}\n"
             f"For Projects: {', '.join(sorted(list(WorkbenchAPI.PROJECT_REPORT_TYPES)))}\n"
             "If not specified, all available report types for the chosen scope will be downloaded.",
        required=False,
        default="ALL",
        metavar="TYPE"
    )
    download_reports_parser.add_argument("--report-save-path", help="Output directory for reports (Default: current dir).", default=".", metavar="PATH")
    gen_opts = download_reports_parser.add_argument_group("Report Generation Options")
    gen_opts.add_argument("--selection-type", help="Filter licenses included in the report.", choices=["include_foss", "include_marked_licenses", "include_copyleft", "include_all_licenses"], metavar="TYPE")
    gen_opts.add_argument("--selection-view", help="Filter report content by identification view.", choices=["pending_identification", "marked_as_identified", "all"], metavar="VIEW")
    gen_opts.add_argument("--disclaimer", help="Include custom text as a disclaimer in the report.", metavar="TEXT")
    gen_opts.add_argument("--include-vex", help="Include VEX data in CycloneDX/Excel reports (Default: True).", action=argparse.BooleanOptionalAction, default=True)
    add_common_monitoring_options(download_reports_parser)

    # --- 'scan-git' Subcommand ---
    scan_git_parser = subparsers.add_parser(
        'scan-git',
        help='Run a scan directly from a Git repository.',
        description='Clones a Branch or Tag directly from your Git SCM to the Workbench server and scans it.',
        formatter_class=RawTextHelpFormatter
    )
    scan_git_parser.add_argument("--project-name", help="Project name for the scan.", type=str, required=True, metavar="NAME")
    scan_git_parser.add_argument("--scan-name", help="Scan name for the scan.", type=str, required=True, metavar="NAME")
    scan_git_parser.add_argument("--git-url", help="URL of the Git repository to scan.", type=str, required=True)
    scan_git_parser.add_argument("--git-depth", help="Specify clone depth (integer, optional).", type=int, metavar="DEPTH")

    ref_group = scan_git_parser.add_mutually_exclusive_group(required=True)
    ref_group.add_argument("--git-branch", help="The git branch to scan.", type=str, metavar="BRANCH")
    ref_group.add_argument("--git-tag", help="The git tag to scan.", type=str, metavar="TAG")
    ref_group.add_argument("--git-commit", help="The git commit to scan.", type=str, metavar="COMMIT")

    add_common_scan_options(scan_git_parser)
    add_common_monitoring_options(scan_git_parser)
    add_common_result_options(scan_git_parser)

    # --- Validate args after parsing ---
    args = parser.parse_args()
    
    # Validate common parameters
    if not args.api_url or not args.api_user or not args.api_token:
        raise ValidationError("API URL, user, and token must be provided")
    
    # Fix API URL if it doesn't end with '/api.php'
    if args.api_url and not args.api_url.endswith('/api.php'):
        if args.api_url.endswith('/'):
            args.api_url = args.api_url + 'api.php'
        else:
            args.api_url = args.api_url + '/api.php'
    
    # Validate command-specific parameters
    if args.command == 'scan' or args.command == 'scan-git':
        # For scan command, validate path exists
        if args.command == 'scan':
            if not args.path:
                raise ValidationError("Path is required for scan command")
            if not os.path.exists(args.path):
                raise ValidationError(f"Path does not exist: {args.path}")
        
        # For scan-git, validate Git URL and reference
        if args.command == 'scan-git':
            if not args.git_url:
                raise ValidationError("Git URL is required for scan-git command")
            if not args.git_branch and not args.git_tag and not args.git_commit:
                raise ValidationError("Must specify either a git branch, tag, or commit to scan")
            if args.git_branch and args.git_tag:
                raise ValidationError("Cannot specify both git branch and tag")
            if args.git_branch and args.git_commit:
                raise ValidationError("Cannot specify both git branch and commit")
            if args.git_tag and args.git_commit:
                raise ValidationError("Cannot specify both git tag and commit")
        
        # Validate ID reuse parameters for both scan and scan-git
        if args.id_reuse and args.id_reuse_type in ['project', 'scan'] and not args.id_reuse_source:
            raise ValidationError("ID reuse source project/scan name is required when id-reuse-type is 'project' or 'scan'")
        if args.id_reuse and args.id_reuse_type not in ['project', 'scan'] and args.id_reuse_source:
            logger.warning(f"--id-reuse-source ('{args.id_reuse_source}') provided but --id-reuse-type is '{args.id_reuse_type}'. Source name will be ignored.")
            args.id_reuse_source = None
    
    elif args.command == 'import-da':
        # Validate path for import-da
        if not args.path:
            raise ValidationError("Path is required for import-da command")
        if not os.path.exists(args.path):
            raise ValidationError(f"Path does not exist: {args.path}")
    
    elif args.command == 'download-reports':
        # Validate project name for project scope
        if args.report_scope == 'project' and not args.project_name:
            raise ValidationError("Project name is required for project scope report")
        
        # Validate scan name for scan scope
        if args.report_scope == 'scan' and not args.scan_name:
            raise ValidationError("Scan name is required for scan scope report")
    
    elif args.command == 'show-results':
        # Validate that at least one show flag is provided
        show_flags = [
            args.show_licenses, args.show_components, args.show_dependencies,
            args.show_scan_metrics, args.show_policy_warnings, args.show_vulnerabilities
        ]
        if not any(show_flags):
            raise ValidationError("At least one '--show-*' flag must be provided")
    
    return args
