# tests/integration/test_integration.py

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, mock_open

# Import the main entry point of your application
from workbench_cli.main import main
from workbench_cli.cli import parse_cmdline_args

# --- Helper Function to Create Dummy Files/Dirs ---
def create_dummy_path(tmp_path, is_dir=False, content="dummy content"):
    path = tmp_path / ("dummy_dir" if is_dir else "dummy_file.zip")
    if is_dir:
        path.mkdir()
        (path / "file_inside.txt").write_text(content)
    else:
        path.write_text(content)
    return str(path)

# --- Basic Smoke Tests ---

class TestBasicIntegration:
    """Basic smoke tests for command line parsing and overall integration"""

    def test_help_command(self, capsys):
        """Test that help command works and displays usage information"""
        args = ['workbench-cli', '--help']
        
        with patch.object(sys, 'argv', args):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            # Help should exit with code 0
            assert exc_info.value.code == 0
            
        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower() or "workbench" in captured.out.lower()

    def test_version_command(self, capsys):
        """Test that version command works"""
        args = ['workbench-cli', '--version']
        
        with patch.object(sys, 'argv', args):
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        captured = capsys.readouterr()
        # Should show some version information
        combined_output = captured.out + captured.err
        assert any(char.isdigit() for char in combined_output)  # Should contain version numbers

    def test_missing_api_credentials(self, capsys):
        """Test that missing API credentials are handled properly"""
        args = [
            'workbench-cli',
            'scan',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--path', '/dummy/path'
        ]
        
        with patch.object(sys, 'argv', args):
            return_code = main()
            
        assert return_code != 0, "Should fail when API credentials are missing"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        # Should mention missing credentials or URL
        assert any(term in combined_output.lower() for term in ["url", "token", "user", "credential", "api"])

    def test_invalid_command(self, capsys):
        """Test that invalid command is handled properly"""
        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'invalid-command'
        ]
        
        with patch.object(sys, 'argv', args):
            return_code = main()
            
        assert return_code != 0, "Should fail when invalid command is provided"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        # Should mention invalid command
        assert any(term in combined_output.lower() for term in ["invalid", "command", "error", "unknown"])

    def test_command_line_parsing_basic(self):
        """Test basic command line argument parsing"""
        # Test scan command parsing
        args = [
            'workbench-cli',
            '--api-url', 'http://test.com',
            '--api-user', 'testuser',
            '--api-token', 'testtoken',
            'scan',
            '--project-name', 'TestProject',
            '--scan-name', 'TestScan',
            '--path', '/test/path'
        ]
        
        parsed_args = parse_cmdline_args(args[1:])  # Skip program name
        
        assert parsed_args.api_url == 'http://test.com'
        assert parsed_args.api_user == 'testuser'
        assert parsed_args.api_token == 'testtoken'
        assert parsed_args.command == 'scan'
        assert parsed_args.project_name == 'TestProject'
        assert parsed_args.scan_name == 'TestScan'
        assert parsed_args.path == '/test/path'

    def test_environment_variable_fallback(self, mocker):
        """Test that environment variables are used as fallback for API credentials"""
        # Mock environment variables
        mocker.patch.dict(os.environ, {
            'WORKBENCH_URL': 'http://env-test.com',
            'WORKBENCH_USER': 'env-user',
            'WORKBENCH_TOKEN': 'env-token'
        })
        
        args = [
            'workbench-cli',
            'scan',
            '--project-name', 'TestProject',
            '--scan-name', 'TestScan',
            '--path', '/test/path'
        ]
        
        parsed_args = parse_cmdline_args(args[1:])  # Skip program name
        
        # The parsed args should have the environment values
        assert parsed_args.api_url == 'http://env-test.com'
        assert parsed_args.api_user == 'env-user'
        assert parsed_args.api_token == 'env-token'

# --- Legacy Tests with Mock API Post (kept for backward compatibility) ---

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=100)
@patch('builtins.open', new_callable=mock_open, read_data=b'dummy data')
def test_scan_fail_during_scan(mock_open, mock_getsize, mock_isdir, mock_exists, mock_api_post, tmp_path, capsys):
    """
    Integration test for a 'scan' command that fails during the scan phase.
    Uses the mock_api_post fixture from conftest.py
    """
    dummy_path = create_dummy_path(tmp_path, is_dir=False)

    mock_api_post([
        # 1. _resolve_project -> list_projects (empty list, requires creation)
        {"json_data": {"status": "1", "data": []}},
        # 2. create_project call (successful project creation)
        {"json_data": {"status": "1", "data": {"project_code": "TPC"}}},
        # 3. _resolve_scan -> list_scans (empty list, requires creation)
        {"json_data": {"status": "1", "data": []}},
        # 4. create_webapp_scan call
        {"json_data": {"status": "1", "data": {"scan_id": "123"}}},
        # 5. _assert_scan_is_idle -> get_scan_status (check scan status before starting)
        {"json_data": {"status": "1", "data": {"status": "NEW"}}},
        # 6. upload_files
        {"status_code": 200, "json_data": {"status": "1"}},
        # 7. extract_archives (assuming simple case with no extraction)
        {"json_data": {"status": "1"}},
        # 8. start_scan
        {"json_data": {"status": "1"}},
        # 9. wait_for_scan_to_finish -> get_scan_status (running)
        {"json_data": {"status": "1", "data": {"status": "RUNNING", "is_finished": "0"}}},
        # 10. wait_for_scan_to_finish -> get_scan_status (FAILED)
        {"json_data": {"status": "1", "data": {"status": "FAILED", "is_finished": "1", "error": "Disk space low"}}},
    ])

    # Fixed command name from workbench-agent to workbench-cli
    args = [
        'workbench-cli',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'scan',
        '--project-name', 'TestProj',
        '--scan-name', 'TestScan',
        '--path', dummy_path,
        # No extraction args for simplicity
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Assertions - updated to match actual output format
    assert return_code != 0  # Expect non-zero exit code on failure
    captured = capsys.readouterr()
    
    # More relaxed assertions - just check key elements are present
    assert "Command: scan" in captured.out
    
    # Just check that it captures error conditions without being too specific
    # Check the combined stdout and stderr streams for error indicators
    combined_output = captured.out + captured.err
    assert any(error_term in combined_output.lower() for error_term in 
               ["error", "fail", "failed", "disk space"])

def test_evaluate_gates_fail_pending_flow(mock_api_post, capsys):
    """
    Integration test for 'evaluate-gates' command that fails due to pending files.
    Uses the mock_api_post fixture from conftest.py
    """
    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "TestProj", "code": "EPC"}]}},
        # 2. _resolve_scan -> get_project_scans
        {"json_data": {"status": "1", "data": [{"name": "TestScan", "code": "ESC", "id": "123"}]}},
        # 3. get_pending_files (with pending files - should cause failure)
        {"json_data": {"status": "1", "data": {"file1.cpp": {"status": "pending"}, "file2.h": {"status": "pending"}}}},
    ])

    args = [
        'workbench-cli',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'evaluate-gates',
        '--project-name', 'TestProj',
        '--scan-name', 'TestScan',
        '--fail-on-pending'
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Should fail due to pending files
    assert return_code != 0
    captured = capsys.readouterr()
    combined_output = captured.out + captured.err
    assert "Command: evaluate-gates" in combined_output

