# tests/integration/test_scan_integration.py

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, mock_open

from workbench_cli.main import main

# --- Helper Function to Create Dummy Files/Dirs ---
def create_dummy_path(tmp_path, is_dir=False, content="dummy content"):
    path = tmp_path / ("dummy_dir" if is_dir else "dummy_file.zip")
    if is_dir:
        path.mkdir()
        (path / "file_inside.txt").write_text(content)
    else:
        path.write_text(content)
    return str(path)

class TestScanIntegration:
    """Integration tests for the scan command"""

    def test_scan_success_flow_simple(self, mocker, tmp_path, capsys):
        """
        Integration test for a successful 'scan' command flow.
        Uses simplified mocking approach with correct API method names.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)
        
        # Mock the resolver methods with correct class names
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock the core scan operations with correct method names
        mocker.patch('workbench_cli.api.upload_api.UploadAPI.upload_scan_target', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        
        # Mock the waiting operations with correct class names
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_archive_extraction',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 5.0))
        
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 10.0))
        
        # Mock status checkers with correct class name
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # File system operations
        mocker.patch('os.path.exists', return_value=True)
        mocker.patch('os.path.isdir', return_value=False)
        mocker.patch('os.path.getsize', return_value=100)
        mocker.patch('builtins.open', new_callable=mock_open, read_data=b'dummy data')

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--path', dummy_path
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"
        
        # Verify we got a success message in the output
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Workbench CLI finished successfully" in combined_output

    def test_scan_with_autoid_flags(self, mocker, tmp_path, capsys):
        """
        Test scan command with AutoID flags enabled.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)
        
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock scan operations with correct method names
        mocker.patch('workbench_cli.api.upload_api.UploadAPI.upload_scan_target', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        
        # Mock waiting operations
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 10.0))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # File system operations
        mocker.patch('os.path.exists', return_value=True)
        mocker.patch('os.path.isdir', return_value=False)
        mocker.patch('os.path.getsize', return_value=100)
        mocker.patch('builtins.open', new_callable=mock_open, read_data=b'dummy data')

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScanAutoID',
            '--path', dummy_path,
            '--autoid-file-licenses',
            '--autoid-file-copyrights',
            '--autoid-pending-ids'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Scan with AutoID should succeed"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan" in combined_output

    def test_scan_with_dependency_analysis(self, mocker, tmp_path, capsys):
        """
        Test scan command with dependency analysis enabled.
        """
        dummy_path = create_dummy_path(tmp_path, is_dir=False)
        
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock scan operations with correct method names
        mocker.patch('workbench_cli.api.upload_api.UploadAPI.upload_scan_target', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.start_dependency_analysis', return_value=None)
        
        # Mock waiting operations
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 10.0))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # File system operations
        mocker.patch('os.path.exists', return_value=True)
        mocker.patch('os.path.isdir', return_value=False)
        mocker.patch('os.path.getsize', return_value=100)
        mocker.patch('builtins.open', new_callable=mock_open, read_data=b'dummy data')

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScanDA',
            '--path', dummy_path,
            '--run-dependency-analysis'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Scan with DA should succeed"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan" in combined_output

    def test_scan_failure_invalid_path(self, mocker, tmp_path, capsys):
        """
        Test scan command with invalid path (should fail).
        """
        # Don't create the dummy path, so it doesn't exist
        invalid_path = str(tmp_path / "nonexistent_file.zip")
        
        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--path', invalid_path
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code != 0, "Scan with invalid path should fail"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        # Should contain some indication of path error
        assert any(term in combined_output.lower() for term in ["path", "file", "not found", "error"]) 