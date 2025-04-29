# tests/test_cli.py

import pytest
from unittest.mock import patch, MagicMock
import argparse
import os # Added for environ patch

# Import the function to test
from workbench_agent.main import main # Correct import
from workbench_agent.cli import parse_cmdline_args # Keep this if testing parsing separately

from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError, # Keep for direct validation errors
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# --- Basic Command Parsing ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.'])
@patch('os.path.exists', return_value=True) # Mock path validation
def test_parse_scan_command(mock_exists):
    args = parse_cmdline_args()
    assert args.command == 'scan'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.path == '.'
    assert args.api_url == 'X/api.php' # Check URL fix
    assert args.api_user == 'Y'
    assert args.api_token == 'Z'
    assert args.limit == 10 # Check default
    assert args.log == 'INFO' # Check default log level

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--scan-name', 'S1', '--report-save-path', '/tmp/reports'])
def test_parse_download_reports_scan_scope():
    args = parse_cmdline_args()
    assert args.command == 'download-reports'
    assert args.report_scope == 'scan' # Check default scope
    assert args.scan_name == 'S1'
    assert args.project_name is None
    assert args.report_type == 'ALL' # Check default type
    assert args.report_save_path == '/tmp/reports' # Check non-default path

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--project-name', 'P1', '--report-scope', 'project', '--report-type', 'xlsx'])
def test_parse_download_reports_project_scope():
    args = parse_cmdline_args()
    assert args.command == 'download-reports'
    assert args.report_scope == 'project'
    assert args.project_name == 'P1'
    assert args.scan_name is None # scan-name is optional if scope is project
    assert args.report_type == 'xlsx'
    assert args.report_save_path == '.' # Check default path

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-branch', 'dev'])
def test_parse_scan_git_branch():
    args = parse_cmdline_args()
    assert args.command == 'scan-git'
    assert args.project_name == 'PG'
    assert args.scan_name == 'SG'
    assert args.git_url == 'http://git.com'
    assert args.git_branch == 'dev'
    assert args.git_tag is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-tag', 'v1.0'])
def test_parse_scan_git_tag():
    args = parse_cmdline_args()
    assert args.command == 'scan-git'
    assert args.git_tag == 'v1.0'
    assert args.git_branch is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'import-da', '--project-name', 'P', '--scan-name', 'S', '--path', 'results.json'])
@patch('os.path.exists', return_value=True) # Mock path validation
def test_parse_import_da(mock_exists):
    args = parse_cmdline_args()
    assert args.command == 'import-da'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.path == 'results.json'

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'evaluate-gates', '--project-name', 'P', '--scan-name', 'S', '--policy-check', '--show-files'])
def test_parse_evaluate_gates():
    args = parse_cmdline_args()
    assert args.command == 'evaluate-gates'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.policy_check is True
    assert args.show_files is True

# --- Test Flags and Defaults ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--log', 'DEBUG', '--delta-scan', '--autoid-pending-ids'])
@patch('os.path.exists', return_value=True) # Mock path validation
def test_parse_flags_and_log_level(mock_exists):
    args = parse_cmdline_args()
    assert args.log == 'DEBUG'
    assert args.delta_scan is True
    assert args.autoid_pending_ids is True
    assert args.autoid_file_licenses is False # Check default
    assert args.run_dependency_analysis is False # Check default

# --- Test Validation Logic ---

# Use ValidationError where the custom validation logic raises it directly
# Use SystemExit where argparse itself is expected to exit

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--id-reuse', '--id-reuse-type', 'project'])
@patch('os.path.exists', return_value=True)
def test_parse_validation_id_reuse_missing_source(mock_exists):
    with pytest.raises(ValidationError, match="ID reuse source project/scan name is required"):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--report-scope', 'project'])
def test_parse_validation_download_missing_project():
    with pytest.raises(ValidationError, match="Project name is required for project scope report"):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--report-scope', 'scan'])
def test_parse_validation_download_missing_scan():
    with pytest.raises(ValidationError, match="Scan name is required for scan scope report"):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'show-results', '--project-name', 'P', '--scan-name', 'S'])
def test_parse_validation_show_results_missing_show_flag():
    with pytest.raises(ValidationError, match="At least one '--show-*' flag must be provided"):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-branch', 'dev', '--git-tag', 'v1'])
def test_parse_validation_scan_git_branch_and_tag():
    with pytest.raises(ValidationError, match="Cannot specify both git branch and tag"):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com'])
def test_parse_validation_scan_git_missing_ref():
    with pytest.raises(ValidationError, match="Must specify either git branch or tag"):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '/non/existent/path'])
@patch('os.path.exists', return_value=False) # Mock os.path.exists
def test_parse_validation_scan_non_existent_path(mock_exists):
    with pytest.raises(ValidationError, match="Path does not exist: /non/existent/path"):
         parse_cmdline_args()
    mock_exists.assert_called_once_with('/non/existent/path')

# Test missing credentials (if not provided by env vars)
@patch.dict(os.environ, {"WORKBENCH_URL": "", "WORKBENCH_USER": "", "WORKBENCH_TOKEN": ""}, clear=True)
@patch('sys.argv', ['workbench-agent', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.'])
@patch('os.path.exists', return_value=True)
def test_parse_validation_missing_credentials(mock_exists):
    with pytest.raises(ValidationError, match="API URL, user, and token must be provided"):
         parse_cmdline_args()

# --- ADDED TEST: Test credentials from environment variables ---
@patch.dict(os.environ, {"WORKBENCH_URL": "http://env.com", "WORKBENCH_USER": "env_user", "WORKBENCH_TOKEN": "env_token"}, clear=True)
@patch('sys.argv', ['workbench-agent', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.']) # No credential args
@patch('os.path.exists', return_value=True) # Assume path exists
def test_parse_credentials_from_env_vars(mock_exists):
    try:
        args = parse_cmdline_args()
        assert args.api_url == 'http://env.com/api.php' # Check URL fix too
        assert args.api_user == 'env_user'
        assert args.api_token == 'env_token'
    except (ValidationError, SystemExit) as e:
        pytest.fail(f"Parsing failed unexpectedly when using env vars: {e}")

# --- More Specific Validation Tests ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z']) # No command
def test_parse_args_no_command():
    # Argparse itself might exit or raise, depending on setup.
    # Assuming custom validation catches this first.
    with pytest.raises(ValidationError, match="No command specified"):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S']) # No path
def test_parse_args_scan_no_path():
    with pytest.raises(ValidationError, match="Path is required for scan command"):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'P', '--scan-name', 'S', '--git-branch', 'main']) # No git url
def test_parse_args_scan_git_no_url():
    with pytest.raises(ValidationError, match="Git URL is required for scan-git command"):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'import-da', '--project-name', 'P', '--scan-name', 'S']) # No path
def test_parse_args_import_da_no_path():
    with pytest.raises(ValidationError, match="Path is required for import-da command"):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'unknown-command'])
def test_parse_args_unknown_command():
    # Argparse usually handles unknown commands with SystemExit
    with pytest.raises(SystemExit):
        parse_cmdline_args()

# --- Test main() Exception Handling ---

# Mock the handler functions used by main
@patch("workbench_agent.cli.handle_scan")
@patch("workbench_agent.cli.handle_scan_git")
@patch("workbench_agent.cli.handle_import_da")
@patch("workbench_agent.cli.handle_evaluate_gates")
@patch("workbench_agent.cli.handle_show_results")
@patch("workbench_agent.cli.handle_download_reports")
@patch("workbench_agent.cli.Workbench") # Mock Workbench instantiation
@patch("workbench_agent.cli.parse_cmdline_args") # Mock arg parsing
def run_main_with_exception(exc_to_raise, mock_parse, mock_wb, *mock_handlers):
    """Helper to run main and simulate an exception."""
    mock_args = MagicMock()
    mock_args.command = "scan" # Assume scan command for simplicity
    mock_args.log = "INFO" # Default log level
    mock_parse.return_value = mock_args

    # Find the handler corresponding to the command and set its side_effect
    # For simplicity, assume handle_scan raises the error
    mock_handlers[0].side_effect = exc_to_raise

    return main()

def test_main_success():
    # Use the helper, but don't raise an exception
    # Need to mock the return value of the handler if it's checked (e.g., evaluate-gates)
    with patch("workbench_agent.cli.handle_scan", return_value=None) as mock_handle_scan, \
         patch("workbench_agent.cli.Workbench"), \
         patch("workbench_agent.cli.parse_cmdline_args") as mock_parse:
        mock_args = MagicMock(command="scan", log="INFO")
        mock_parse.return_value = mock_args
        result = main()
        assert result == 0
        mock_handle_scan.assert_called_once()

def test_main_validation_error():
    # Simulate parse_cmdline_args raising the error
    with patch("workbench_agent.cli.parse_cmdline_args", side_effect=ValidationError("Invalid args")):
        result = main()
        assert result == 1 # Exit code for validation error

def test_main_configuration_error():
    assert run_main_with_exception(ConfigurationError("Bad config")) == 1

def test_main_authentication_error():
    assert run_main_with_exception(AuthenticationError("Bad token")) == 1

def test_main_project_not_found():
    assert run_main_with_exception(ProjectNotFoundError("Proj X")) == 1

def test_main_scan_not_found():
    assert run_main_with_exception(ScanNotFoundError("Scan Y")) == 1

def test_main_api_error():
    assert run_main_with_exception(ApiError("API down")) == 1

def test_main_network_error():
    assert run_main_with_exception(NetworkError("No connection")) == 1

def test_main_process_error():
    assert run_main_with_exception(ProcessError("Scan failed")) == 1

def test_main_process_timeout():
    assert run_main_with_exception(ProcessTimeoutError("Scan timeout")) == 1

def test_main_file_system_error():
    assert run_main_with_exception(FileSystemError("Cannot write")) == 1

def test_main_compatibility_error():
    assert run_main_with_exception(CompatibilityError("Git mismatch")) == 1

def test_main_unexpected_error():
    assert run_main_with_exception(Exception("Something broke")) == 1 # Generic exit code 1

def test_main_evaluate_gates_fail_returns_1():
    # Special case for evaluate-gates returning False
    with patch("workbench_agent.cli.handle_evaluate_gates", return_value=False) as mock_handler, \
         patch("workbench_agent.cli.Workbench"), \
         patch("workbench_agent.cli.parse_cmdline_args") as mock_parse:
        mock_args = MagicMock(command="evaluate-gates", log="INFO")
        mock_parse.return_value = mock_args
        result = main()
        assert result == 1 # Should exit 1 if gates fail
        mock_handler.assert_called_once()

