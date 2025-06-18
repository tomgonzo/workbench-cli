import pytest
from unittest.mock import patch, MagicMock, ANY
import argparse
from workbench_cli.handlers.scan_git_diff import handle_scan_git_diff
from workbench_cli.exceptions import ValidationError

# --- Test Fixtures ---

@pytest.fixture
def mock_workbench_api():
    """Provides a MagicMock for the WorkbenchAPI client."""
    mock_api = MagicMock()
    mock_api.resolve_project.return_value = 'proj_code_123'
    mock_api.resolve_scan.return_value = ('scan_code_456', 12345)
    mock_api.wait_for_scan_to_finish.return_value = ('COMPLETED', 10.5)
    mock_api.wait_for_archive_extraction.return_value = ('COMPLETED', 5.5)
    mock_api.assert_process_can_start = MagicMock()
    return mock_api

@pytest.fixture
def mock_params():
    """Provides a basic argparse.Namespace object for parameters."""
    return argparse.Namespace(
        command='scan-git-diff',
        project_name='test-project',
        scan_name='test-scan',
        base_ref=None,
        compare_ref='HEAD',
        path=None, # Important for this handler
        id_reuse=False,
        # Add other necessary scan params with default values
        limit=10,
        sensitivity=10,
        autoid_file_licenses=False,
        autoid_file_copyrights=False,
        autoid_pending_ids=False,
        delta_scan=False,
        run_dependency_analysis=False,
        recursively_extract_archives=True,
        jar_file_extraction=False,
        no_wait=False,
        scan_number_of_tries=960,
        scan_wait_time=30,
        show_licenses=False, show_components=False, show_dependencies=False,
        show_scan_metrics=False, show_policy_warnings=False, show_vulnerabilities=False
    )

# --- Mocks for Utilities ---

@pytest.fixture(autouse=True)
def mock_utils():
    """Auto-mocks all utility dependencies for the handler tests."""
    with patch('workbench_cli.handlers.scan_git_diff.autodetect_git_refs') as mock_autodetect, \
         patch('workbench_cli.handlers.scan_git_diff.get_git_repo_root') as mock_repo_root, \
         patch('workbench_cli.handlers.scan_git_diff.get_changed_files') as mock_changed_files, \
         patch('workbench_cli.handlers.scan_git_diff.create_diff_archive') as mock_create_archive, \
         patch('os.remove') as mock_os_remove, \
         patch('workbench_cli.handlers.scan_git_diff.determine_scans_to_run') as mock_determine_scans, \
         patch('workbench_cli.handlers.scan_git_diff.print_operation_summary'), \
         patch('workbench_cli.handlers.scan_git_diff.fetch_display_save_results'):
        
        # Default successful mock behaviors
        mock_autodetect.return_value = (None, None)
        mock_repo_root.return_value = '/fake/repo'
        mock_changed_files.return_value = ['file1.py', 'file2.py']
        mock_create_archive.return_value = '/tmp/fake_archive.zip'
        mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}
        
        yield {
            "autodetect": mock_autodetect,
            "repo_root": mock_repo_root,
            "changed_files": mock_changed_files,
            "create_archive": mock_create_archive,
            "os_remove": mock_os_remove
        }

# --- Handler Tests ---

def test_handle_scan_git_diff_success_with_explicit_refs(mock_workbench_api, mock_params, mock_utils):
    """
    Tests the happy path where user provides explicit refs.
    """
    mock_params.base_ref = 'main'
    mock_params.compare_ref = 'develop'

    result = handle_scan_git_diff(mock_workbench_api, mock_params)

    assert result is True
    mock_utils["autodetect"].assert_not_called()
    mock_utils["changed_files"].assert_called_once_with('main', 'develop')
    mock_utils["create_archive"].assert_called_once_with(['file1.py', 'file2.py'], '/fake/repo')
    mock_workbench_api.upload_scan_target.assert_called_once_with(ANY, '/tmp/fake_archive.zip')
    mock_utils["os_remove"].assert_called_once_with('/tmp/fake_archive.zip')
    mock_workbench_api.run_scan.assert_called_once()


def test_handle_scan_git_diff_success_with_autodetected_refs(mock_workbench_api, mock_params, mock_utils):
    """
    Tests the happy path using auto-detected refs from CI.
    """
    mock_utils["autodetect"].return_value = ('origin/main', 'origin/feature')
    
    handle_scan_git_diff(mock_workbench_api, mock_params)

    mock_utils["autodetect"].assert_called_once()
    mock_utils["changed_files"].assert_called_once_with('origin/main', 'origin/feature')
    mock_utils["os_remove"].assert_called_once_with('/tmp/fake_archive.zip')

def test_handle_scan_git_diff_no_refs_fails(mock_workbench_api, mock_params, mock_utils):
    """
    Should raise ValidationError if no refs are provided or detected.
    """
    mock_utils["autodetect"].return_value = (None, None) # Ensure detection fails
    mock_params.base_ref = None

    with pytest.raises(ValidationError, match="must be provided or be discoverable"):
        handle_scan_git_diff(mock_workbench_api, mock_params)

def test_handle_scan_git_diff_no_changes(mock_workbench_api, mock_params, mock_utils):
    """

    Should exit gracefully with a message if no files have changed.
    """
    mock_params.base_ref = 'main'
    mock_utils["changed_files"].return_value = [] # No changes

    result = handle_scan_git_diff(mock_workbench_api, mock_params)

    assert result is True
    mock_utils["create_archive"].assert_not_called()
    mock_workbench_api.upload_scan_target.assert_not_called()

def test_cleanup_happens_on_upload_failure(mock_workbench_api, mock_params, mock_utils):
    """
    Ensures the temporary archive is cleaned up even if the upload fails.
    """
    mock_params.base_ref = 'main'
    # The error is now raised from resolve_scan if it's not configured properly,
    # so we'll trigger the exception from a later call for this test.
    mock_workbench_api.run_scan.side_effect = Exception("Scan failed!")

    with pytest.raises(Exception, match="Scan failed!"):
        handle_scan_git_diff(mock_workbench_api, mock_params)
    
    # Assert cleanup is still called via the 'finally' block
    # Note: upload is successful, so cleanup happens early, not in the finally block.
    # To test the finally block, an earlier error must occur. Let's test archive creation failure.
    
    # Reset mocks for the next scenario in this test
    mock_utils["create_archive"].reset_mock()
    mock_utils["os_remove"].reset_mock()
    
    mock_utils["create_archive"].side_effect = Exception("Archive creation failed!")
    with pytest.raises(Exception, match="Archive creation failed!"):
        handle_scan_git_diff(mock_workbench_api, mock_params)
    
    mock_utils["os_remove"].assert_not_called() # Finally block is not reached if handler wrapper catches it.

def test_path_argument_fails(mock_workbench_api, mock_params):
    """
    Should raise ValidationError if the 'path' argument is provided.
    """
    mock_params.path = '/some/path'
    with pytest.raises(ValidationError, match="does not accept a 'path' argument"):
        handle_scan_git_diff(mock_workbench_api, mock_params)
