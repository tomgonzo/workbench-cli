# tests/test_cli.py

import pytest
from unittest.mock import patch, MagicMock
import argparse
import os # Added for environ patch
import re

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
    assert args.git_commit is None  # Verify git_commit is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-tag', 'v1.0'])
def test_parse_scan_git_tag():
    args = parse_cmdline_args()
    assert args.command == 'scan-git'
    assert args.git_tag == 'v1.0'
    assert args.git_branch is None
    assert args.git_commit is None  # Verify git_commit is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-commit', 'abc123'])
def test_parse_scan_git_commit():
    args = parse_cmdline_args()
    assert args.command == 'scan-git'
    assert args.project_name == 'PG'
    assert args.scan_name == 'SG'
    assert args.git_url == 'http://git.com'
    assert args.git_commit == 'abc123'
    assert args.git_branch is None  # Verify git_branch is None
    assert args.git_tag is None  # Verify git_tag is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'import-da', '--project-name', 'P', '--scan-name', 'S', '--path', 'results.json'])
@patch('os.path.exists', return_value=True) # Mock path validation
def test_parse_import_da(mock_exists):
    args = parse_cmdline_args()
    assert args.command == 'import-da'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.path == 'results.json'

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'evaluate-gates', '--project-name', 'P', '--scan-name', 'S', '--show-pending-files'])
def test_parse_evaluate_gates():
    args = parse_cmdline_args()
    assert args.command == 'evaluate-gates'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.show_pending_files is True
    assert not hasattr(args, 'policy_check')  # Should not have this attribute anymore
    assert not hasattr(args, 'show_files')  # Should not have this attribute anymore

# --- Test Flags and Defaults ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', '--log', 'DEBUG', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--delta-scan', '--autoid-pending-ids'])
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
    with pytest.raises(ValidationError, match=re.escape("At least one '--show-*' flag must be provided")):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-branch', 'dev', '--git-tag', 'v1'])
def test_parse_validation_scan_git_branch_and_tag():
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-branch', 'dev', '--git-commit', 'abc123'])
def test_parse_validation_scan_git_branch_and_commit():
    with pytest.raises(SystemExit):  # Argparse handles this validation, raising SystemExit
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-tag', 'v1.0', '--git-commit', 'abc123'])
def test_parse_validation_scan_git_tag_and_commit():
    with pytest.raises(SystemExit):  # Argparse handles this validation, raising SystemExit
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com'])
def test_parse_validation_scan_git_missing_ref():
    with pytest.raises(SystemExit):  # Argparse handles this validation, raising SystemExit
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '/non/existent/path'])
@patch('os.path.exists', return_value=False) # Mock os.path.exists
def test_parse_validation_scan_non_existent_path(mock_exists):
    with pytest.raises(ValidationError, match=re.escape("Path does not exist: /non/existent/path")):
         parse_cmdline_args()
    mock_exists.assert_any_call('/non/existent/path')

# Test missing credentials (if not provided by env vars)
@patch.dict(os.environ, {"WORKBENCH_URL": "", "WORKBENCH_USER": "", "WORKBENCH_TOKEN": ""}, clear=True)
@patch('sys.argv', ['workbench-agent', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.'])
@patch('os.path.exists', return_value=True)
def test_parse_validation_missing_credentials(mock_exists):
    with pytest.raises(SystemExit):
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
    with pytest.raises(SystemExit):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S']) # No path
def test_parse_args_scan_no_path():
    with pytest.raises(SystemExit):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'P', '--scan-name', 'S', '--git-branch', 'main']) # No git url
def test_parse_args_scan_git_no_url():
    with pytest.raises(SystemExit):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'import-da', '--project-name', 'P', '--scan-name', 'S']) # No path
def test_parse_args_import_da_no_path():
    with pytest.raises(SystemExit):
        parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'unknown-command'])
def test_parse_args_unknown_command():
    # Argparse usually handles unknown commands with SystemExit
    with pytest.raises(SystemExit):
        parse_cmdline_args()

# --- Test main() Exception Handling ---

# Mock the handler functions used by main
@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan", "--project-name", "P", "--scan-name", "S", "--path", "."])
@patch("os.path.exists", return_value=True)
@patch("workbench_agent.handlers.handle_scan", return_value=None)
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args") 
def test_main_success(mock_parse, mock_wb, mock_handle_scan, mock_exists):
    # Set up the mock args
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    
    # Run main and check success
    result = main()
    assert result == 0
    mock_handle_scan.assert_called_once()

def test_main_validation_error():
    # Simulate parse_cmdline_args raising the error
    with patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"]), \
         patch("workbench_agent.main.parse_cmdline_args", side_effect=ValidationError("Invalid args")):
        result = main()
        assert result == 1 # Exit code for validation error

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=ConfigurationError("Bad config"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_configuration_error(mock_parse, mock_wb, mock_handle_scan):
    # Set up the mock args
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    
    # Run main
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=AuthenticationError("Auth failed"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_authentication_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=ProjectNotFoundError("Project not found"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_project_not_found(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=ScanNotFoundError("Scan not found"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_scan_not_found(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=ApiError("API error"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_api_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=NetworkError("Network error"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_network_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=ProcessError("Process error"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_process_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=ProcessTimeoutError("Process timeout"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_process_timeout(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=FileSystemError("File system error"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_file_system_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=CompatibilityError("Compatibility error"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_compatibility_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", side_effect=Exception("Unexpected error"))
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_unexpected_error(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "evaluate-gates"])
@patch("workbench_agent.handlers.handle_evaluate_gates", return_value=False)
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_evaluate_gates_fail_returns_1(mock_parse, mock_wb, mock_handle_gates):
    mock_args = MagicMock(command="evaluate-gates", log="INFO")
    mock_parse.return_value = mock_args
    result = main()
    assert result == 1

# Test ID reuse parameters
@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--id-reuse', '--id-reuse-type', 'project', '--id-reuse-source', 'ReusePrj'])
@patch('os.path.exists', return_value=True)
def test_parse_id_reuse_project(mock_exists):
    args = parse_cmdline_args()
    assert args.id_reuse is True
    assert args.id_reuse_type == 'project'
    assert args.id_reuse_source == 'ReusePrj'

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--id-reuse', '--id-reuse-type', 'scan', '--id-reuse-source', 'ReuseScan'])
@patch('os.path.exists', return_value=True)
def test_parse_id_reuse_scan(mock_exists):
    args = parse_cmdline_args()
    assert args.id_reuse is True
    assert args.id_reuse_type == 'scan'
    assert args.id_reuse_source == 'ReuseScan'

# Test behavior when id-reuse-source is provided with id-reuse-type that doesn't need it
@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--id-reuse', '--id-reuse-type', 'any', '--id-reuse-source', 'UnneededSource'])
@patch('os.path.exists', return_value=True)
def test_parse_id_reuse_source_ignored(mock_exists):
    # The warning is logged directly in parse_cmdline_args, not through the logger mock
    # We can only check the result of the parsing
    args = parse_cmdline_args()
    assert args.id_reuse is True
    assert args.id_reuse_type == 'any' 
    assert args.id_reuse_source is None  # Source should be ignored for 'any' type

# Test help text formatting 
@patch('sys.argv', ['workbench-agent', '--help'])
@patch('argparse.ArgumentParser.print_help')
@patch('sys.exit')
def test_help_text_formatting(mock_exit, mock_print_help):
    import argparse
    from workbench_agent.cli import add_common_scan_options
    
    # Create a parser to test the help text formatting
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers()
    test_parser = subparser.add_parser('test')
    
    # Apply our add_common_scan_options to it
    add_common_scan_options(test_parser)
    
    # Get help text for id-reuse-type
    for action in test_parser._action_groups:
        for act in action._actions:
            if act.dest == 'id_reuse_type':
                help_text = act.help
                assert "use any existing identification" in help_text
                assert "reuse identifications from" in help_text
    
    # Force the original parse call to exit to not interfere with test
    mock_exit.side_effect = SystemExit
    with pytest.raises(SystemExit):
        parse_cmdline_args()

# --- Test Handler Return Types ---
@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", return_value=True)  # Return True for success
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_with_scan_handler_return_true(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    
    # Run main
    result = main()
    assert result == 0  # Should return 0 (success) when handler returns True
    mock_handle_scan.assert_called_once()

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan"])
@patch("workbench_agent.handlers.handle_scan", return_value=False)  # Return False for failure
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_with_scan_handler_return_false(mock_parse, mock_wb, mock_handle_scan):
    mock_args = MagicMock(command="scan", log="INFO")
    mock_parse.return_value = mock_args
    
    # Run main
    result = main()
    # For non-evaluate-gates commands, the boolean return value isn't used for exit code
    # It should still be 0 since no exception occurred
    assert result == 0
    mock_handle_scan.assert_called_once()

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "show-results"])
@patch("workbench_agent.handlers.handle_show_results", return_value=True)
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_with_show_results_handler_return_true(mock_parse, mock_wb, mock_handle):
    mock_args = MagicMock(command="show-results", log="INFO")
    mock_parse.return_value = mock_args
    
    result = main()
    assert result == 0
    mock_handle.assert_called_once()

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "import-da"])
@patch("workbench_agent.handlers.handle_import_da", return_value=True)
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_with_import_da_handler_return_true(mock_parse, mock_wb, mock_handle):
    mock_args = MagicMock(command="import-da", log="INFO")
    mock_parse.return_value = mock_args
    
    result = main()
    assert result == 0
    mock_handle.assert_called_once()

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "download-reports"])
@patch("workbench_agent.handlers.handle_download_reports", return_value=True)
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_with_download_reports_handler_return_true(mock_parse, mock_wb, mock_handle):
    mock_args = MagicMock(command="download-reports", log="INFO")
    mock_parse.return_value = mock_args
    
    result = main()
    assert result == 0
    mock_handle.assert_called_once()

@patch("sys.argv", ["workbench-agent", "--api-url", "X", "--api-user", "Y", "--api-token", "Z", "scan-git"])
@patch("workbench_agent.handlers.handle_scan_git", return_value=True)
@patch("workbench_agent.api.Workbench")
@patch("workbench_agent.main.parse_cmdline_args")
def test_main_with_scan_git_handler_return_true(mock_parse, mock_wb, mock_handle):
    mock_args = MagicMock(command="scan-git", log="INFO")
    mock_parse.return_value = mock_args
    
    result = main()
    assert result == 0
    mock_handle.assert_called_once()

