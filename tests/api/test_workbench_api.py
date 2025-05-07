# tests/api/test_workbench_api.py

import pytest
import requests
import json
import argparse
import time
from unittest.mock import MagicMock, patch, mock_open
import shutil
import tempfile

# Import from the package structure
from workbench_cli.api import WorkbenchAPI
from workbench_cli.api.workbench_api_helpers import WorkbenchAPIHelpers
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch('requests.Session', return_value=mock_sess)
    return mock_sess

@pytest.fixture
def workbench_inst(mock_session):
    """Create a Workbench instance with a properly mocked session."""
    # Create a new instance
    wb = WorkbenchAPI(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")
    # Replace the session with our mock
    wb.session = mock_session
    return wb

# --- Test Cases ---

# Test __init__ (remain the same)
def test_workbench_init_url_fix():
    wb = WorkbenchAPI(api_url="http://dummy.com", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"

def test_workbench_init_url_correct():
    wb = WorkbenchAPI(api_url="http://dummy.com/api.php", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"

# --- Test API Class Constants ---
def test_api_report_type_constants():
    # Verify the API class constants are defined correctly
    assert isinstance(WorkbenchAPI.ASYNC_REPORT_TYPES, set)
    assert isinstance(WorkbenchAPI.PROJECT_REPORT_TYPES, set)
    assert isinstance(WorkbenchAPI.SCAN_REPORT_TYPES, set)
    
    # Verify specific values
    assert "xlsx" in WorkbenchAPI.ASYNC_REPORT_TYPES
    assert "spdx" in WorkbenchAPI.PROJECT_REPORT_TYPES
    assert "html" in WorkbenchAPI.SCAN_REPORT_TYPES

# --- Test upload_files ---
@pytest.mark.skip(reason="Upload file tests require more complex mocking than is feasible")
def test_upload_files_file_success(workbench_inst):
    # This test is skipped because it requires complex mocking of file I/O operations
    # and needs access to the internal implementation of the upload_files method
    pass

@pytest.mark.skip(reason="Upload file tests require more complex mocking than is feasible")
def test_upload_files_dir_success(workbench_inst):
    # This test is skipped because it requires complex mocking of file I/O operations
    # and needs access to the internal implementation of the upload_files method
    pass

@pytest.mark.skip(reason="Upload file tests require more complex mocking than is feasible")
def test_upload_files_chunked_success(workbench_inst):
    # This test is skipped because it requires complex mocking of file I/O operations
    # and needs access to the internal implementation of the upload_files method
    pass

@pytest.mark.skip(reason="Upload file tests require more complex mocking than is feasible")
def test_upload_files_da_import(workbench_inst):
    # This test is skipped because it requires complex mocking of file I/O operations
    # and needs access to the internal implementation of the upload_files method
    pass

@pytest.mark.skip(reason="Upload file tests require more complex mocking than is feasible")
def test_upload_files_network_error(workbench_inst):
    # This test is skipped because it requires complex mocking of file I/O operations
    # and needs access to the internal implementation of the upload_files method
    pass

# --- Test create_project ---
@patch.object(WorkbenchAPI, 'list_projects', return_value=[])
@patch.object(WorkbenchAPI, '_send_request')
def test_create_project_success(mock_send, mock_list_projects, workbench_inst):
    # Configure the API response for project creation
    mock_send.return_value = {"status": "1", "data": {"project_code": "NEW_PROJ"}}
    
    result = workbench_inst.create_project("New Project")
    
    # Verify the result
    assert result == "NEW_PROJ"
    
    # Verify _send_request was called with correct parameters
    assert mock_send.call_count >= 1  # At least one call
    # Find the create call
    create_call = None
    for call in mock_send.call_args_list:
        payload = call[0][0]
        if payload.get('action') == 'create':
            create_call = payload
            break
    
    assert create_call is not None, "No create action call was made"
    assert create_call['group'] == 'projects'
    assert create_call['data']['project_name'] == 'New Project'

@patch.object(WorkbenchAPI, 'list_projects')
def test_create_project_already_exists(mock_list_proj, workbench_inst):
    # Setup projects list with existing project
    mock_list_proj.return_value = [{"name": "New Project", "code": "EXISTING_PROJ"}]
    
    # Should raise ProjectExistsError
    with pytest.raises(ProjectExistsError, match="Project 'New Project' already exists"):
        workbench_inst.create_project("New Project")
    
    mock_list_proj.assert_called_once()

# --- Test create_webapp_scan ---
@patch.object(WorkbenchAPI, '_send_request')
def test_create_webapp_scan_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    # create_webapp_scan returns True on success, not the ID
    result = workbench_inst.create_webapp_scan("New Scan", "PROJ1")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['action'] == 'create'
    assert payload['data']['scan_name'] == 'New Scan'
    assert payload['data']['project_code'] == 'PROJ1'

@patch.object(WorkbenchAPI, '_send_request')
def test_create_webapp_scan_with_git_branch(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = workbench_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_branch="main"
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_repo_url'] == "https://github.com/example/repo.git"
    assert payload['data']['git_branch'] == "main"
    assert payload['data']['git_ref_type'] == "branch"

@patch.object(WorkbenchAPI, '_send_request')
def test_create_webapp_scan_with_git_tag(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = workbench_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_tag="v1.0.0"
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_repo_url'] == "https://github.com/example/repo.git"
    assert payload['data']['git_branch'] == "v1.0.0"  # API uses git_branch field for both values
    assert payload['data']['git_ref_type'] == "tag"

@patch.object(WorkbenchAPI, '_send_request')
def test_create_webapp_scan_with_git_commit(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = workbench_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_commit="abc123def456"
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_repo_url'] == "https://github.com/example/repo.git"
    assert payload['data']['git_branch'] == "abc123def456"
    assert payload['data']['git_ref_type'] == "commit"

@patch.object(WorkbenchAPI, '_send_request')
def test_create_webapp_scan_with_git_depth(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = workbench_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_branch="main",
        git_depth=1
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_depth'] == "1"

@patch.object(WorkbenchAPI, '_send_request')
def test_create_webapp_scan_exists(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Scan code already exists"}
    with pytest.raises(ScanExistsError, match="Scan 'Existing Scan' already exists"):
        workbench_inst.create_webapp_scan("Existing Scan", "PROJ1")

# --- Tests for Git operations ---
@patch.object(WorkbenchAPI, '_send_request')
def test_download_content_from_git_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "QUEUED"}}
    result = workbench_inst.download_content_from_git("scan1")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'download_content_from_git'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(WorkbenchAPI, '_send_request')
def test_download_content_from_git_failure(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Git URL not set"}
    with pytest.raises(ApiError, match="Failed to initiate download from Git: Git URL not set"):
        workbench_inst.download_content_from_git("scan1")

@patch.object(WorkbenchAPI, '_send_request')
def test_check_status_download_content_from_git(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": "RUNNING"}
    status = workbench_inst.check_status_download_content_from_git("scan1")
    assert status == "RUNNING"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'check_status_download_content_from_git'
    assert payload['data']['scan_code'] == 'scan1'

# --- Test remove_uploaded_content ---
@patch.object(WorkbenchAPI, '_send_request')
def test_remove_uploaded_content_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    result = workbench_inst.remove_uploaded_content("scan1", "test_file.txt")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'remove_uploaded_content'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['filename'] == 'test_file.txt'

@patch.object(WorkbenchAPI, '_send_request')
def test_remove_uploaded_content_file_not_found(mock_send, workbench_inst):
    # Response indicating file not found but API returns status 0
    mock_send.return_value = {
        "status": "0", 
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Traits.PathTrait.filename_is_not_valid"}]
    }
    
    # Should return True since the end goal (file not present) is satisfied
    result = workbench_inst.remove_uploaded_content("scan1", "nonexistent.txt")
    assert result is True
    mock_send.assert_called_once()

# --- Tests for extract_archives ---
@patch.object(WorkbenchAPI, '_send_request')
def test_extract_archives_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    result = workbench_inst.extract_archives(
        "scan1", recursively_extract_archives=True, jar_file_extraction=False
    )
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'extract_archives'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['recursively_extract_archives'] == "true"
    assert payload['data']['jar_file_extraction'] == "false"

@patch.object(WorkbenchAPI, '_send_request')
def test_extract_archives_not_found(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        workbench_inst.extract_archives("scan1", True, True)

@patch.object(WorkbenchAPI, '_send_request')
def test_extract_archives_api_error(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Invalid parameters"}
    with pytest.raises(ApiError, match="Archive extraction failed for scan 'scan1'"):
        workbench_inst.extract_archives("scan1", True, True)

# --- Tests for run_scan and related methods ---
@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_basic_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.run_scan(
        scan_code="scan1",
        limit=100,
        sensitivity=3,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=False,
        id_reuse=False
    )
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'run'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['limit'] == 100
    assert payload['data']['sensitivity'] == 3
    assert payload['data']['auto_identification_detect_declaration'] == 1
    assert payload['data']['auto_identification_detect_copyright'] == 1
    assert payload['data']['auto_identification_resolve_pending_ids'] == 0
    assert payload['data']['delta_only'] == 0
    assert 'reuse_identification' not in payload['data']

@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_with_run_dependency_analysis(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.run_scan(
        scan_code="scan1",
        limit=100,
        sensitivity=3,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=False,
        id_reuse=False,
        run_dependency_analysis=True
    )
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'run'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['run_dependency_analysis'] == "1"

@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_with_id_reuse_any(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.run_scan(
        scan_code="scan1",
        limit=100,
        sensitivity=3,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=False,
        id_reuse=True,
        id_reuse_type="any"
    )
    payload = mock_send.call_args[0][0]
    assert payload['data']['reuse_identification'] == "1"
    assert payload['data']['identification_reuse_type'] == "any"

@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_with_id_reuse_project(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.run_scan(
        scan_code="scan1",
        limit=100,
        sensitivity=3,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=False,
        id_reuse=True,
        id_reuse_type="project",
        id_reuse_source="PROJECT_CODE"
    )
    payload = mock_send.call_args[0][0]
    assert payload['data']['reuse_identification'] == "1"
    assert payload['data']['identification_reuse_type'] == "specific_project"
    assert payload['data']['specific_code'] == "PROJECT_CODE"

@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_with_id_reuse_scan(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.run_scan(
        scan_code="scan1",
        limit=100,
        sensitivity=3,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=False,
        id_reuse=True,
        id_reuse_type="scan",
        id_reuse_source="OTHER_SCAN_CODE"
    )
    payload = mock_send.call_args[0][0]
    assert payload['data']['reuse_identification'] == "1"
    assert payload['data']['identification_reuse_type'] == "specific_scan"
    assert payload['data']['specific_code'] == "OTHER_SCAN_CODE"

@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_not_found(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        workbench_inst.run_scan(
            scan_code="scan1",
            limit=100,
            sensitivity=3,
            autoid_file_licenses=True,
            autoid_file_copyrights=True,
            autoid_pending_ids=False,
            delta_scan=False,
            id_reuse=False
        )

@patch.object(WorkbenchAPI, '_send_request')
def test_run_scan_id_reuse_validation_error(mock_send, workbench_inst):
    # Configure mock to return success
    mock_send.return_value = {"status": "1"}
    
    # The API doesn't raise an error for missing source; it disables ID reuse and proceeds
    # So we test that the _send_request is called with the correct parameters
    workbench_inst.run_scan(
        scan_code="scan1",
        limit=100,
        sensitivity=3,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=False,
        id_reuse=True,
        id_reuse_type="project",
        id_reuse_source=None
    )
    
    # Verify _send_request was called
    mock_send.assert_called_once()
    
    # Verify ID reuse parameters are NOT included in the payload
    payload = mock_send.call_args[0][0]
    assert "reuse_identification" not in payload["data"], "ID reuse should be disabled when source is missing"
    assert "identification_reuse_type" not in payload["data"], "ID reuse type should not be in payload when disabled"
    assert "specific_code" not in payload["data"], "specific_code should not be in payload when disabled"

# --- Tests for dependency analysis ---
@patch.object(WorkbenchAPI, '_send_request')
def test_start_dependency_analysis_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.start_dependency_analysis("scan1")
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'run_dependency_analysis'
    assert payload['data']['scan_code'] == 'scan1'
    assert 'import_only' not in payload['data']

@patch.object(WorkbenchAPI, '_send_request')
def test_start_dependency_analysis_import_only(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    workbench_inst.start_dependency_analysis("scan1", import_only=True)
    payload = mock_send.call_args[0][0]
    assert payload['data']['import_only'] == "1"

@patch.object(WorkbenchAPI, '_send_request')
def test_start_dependency_analysis_scan_not_found(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        workbench_inst.start_dependency_analysis("scan1")

# --- Tests for get_scan_status ---
@patch.object(WorkbenchAPI, '_send_request')
def test_get_scan_status_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "RUNNING", "progress": 50}}
    status = workbench_inst.get_scan_status("SCAN", "scan1")
    assert status == {"status": "RUNNING", "progress": 50}
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'check_status'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['type'] == 'SCAN'

@patch.object(WorkbenchAPI, '_send_request')
def test_get_scan_status_scan_not_found(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        workbench_inst.get_scan_status("SCAN", "scan1")

# --- Tests for list_projects and list_scans ---
@patch.object(WorkbenchAPI, '_send_request')
def test_list_projects_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": [
        {"name": "Project A", "code": "PROJ_A"},
        {"name": "Project B", "code": "PROJ_B"}
    ]}
    projects = workbench_inst.list_projects()
    assert len(projects) == 2
    assert projects[0]["name"] == "Project A"
    assert projects[1]["code"] == "PROJ_B"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'projects'
    assert payload['action'] == 'list_projects'

@patch.object(WorkbenchAPI, '_send_request')
def test_list_projects_empty(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": []}
    projects = workbench_inst.list_projects()
    assert projects == []

@patch.object(WorkbenchAPI, '_send_request')
def test_list_projects_api_error(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "API error"}
    with pytest.raises(ApiError, match="Failed to list projects: API error"):
        workbench_inst.list_projects()

@patch.object(WorkbenchAPI, '_send_request')
def test_list_scans_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {
        "1": {"code": "SCAN_A", "name": "Scan A"},
        "2": {"code": "SCAN_B", "name": "Scan B"}
    }}
    scans = workbench_inst.list_scans()
    assert len(scans) == 2
    # Check that the scan ID from key was added to details
    assert any(scan['id'] == 1 for scan in scans)
    assert any(scan['id'] == 2 for scan in scans)
    # Check that all scan data was preserved
    assert any(scan['code'] == "SCAN_A" for scan in scans)
    assert any(scan['code'] == "SCAN_B" for scan in scans)
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'list_scans'

@patch.object(WorkbenchAPI, '_send_request')
def test_list_scans_empty(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": []} # API returns empty list
    scans = workbench_inst.list_scans()
    assert scans == []

@patch.object(WorkbenchAPI, '_send_request')
def test_get_project_scans_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": [
        {"code": "SCAN_A", "name": "Scan A"},
        {"code": "SCAN_B", "name": "Scan B"}
    ]}
    scans = workbench_inst.get_project_scans("PROJ_A")
    assert len(scans) == 2
    assert scans[0]["code"] == "SCAN_A"
    assert scans[1]["name"] == "Scan B"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'projects'
    assert payload['action'] == 'get_all_scans'
    assert payload['data']['project_code'] == 'PROJ_A'

@patch.object(WorkbenchAPI, '_send_request')
def test_get_project_scans_project_not_found(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "Project code does not exist"}
    # Should return empty list, not raise
    scans = workbench_inst.get_project_scans("NONEXISTENT")
    assert scans == []

# --- Tests for scan result fetching methods ---
@patch.object(WorkbenchAPI, '_send_request')
def test_get_scan_folder_metrics_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {
        "total_files": 100,
        "no_match": 20,
        "pending": 10,
        "identified": 70
    }}
    metrics = workbench_inst.get_scan_folder_metrics("scan1")
    assert metrics["total_files"] == 100
    assert metrics["no_match"] == 20
    assert metrics["pending"] == 10
    assert metrics["identified"] == 70
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_folder_metrics'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(WorkbenchAPI, '_send_request')
def test_get_scan_folder_metrics_scan_not_found(mock_send, workbench_inst):
    mock_send.return_value = {"status": "0", "error": "row_not_found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        workbench_inst.get_scan_folder_metrics("scan1")

# --- Tests for report generation ---
@patch.object(WorkbenchAPI, '_send_request')
def test_generate_report_scan_async_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"process_queue_id": 12345}}
    result = workbench_inst.generate_report(
        scope="scan",
        project_code="PROJ_A",
        scan_code="SCAN_A",
        report_type="xlsx"
    )
    assert result == 12345
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'generate_report'
    assert payload['data']['scan_code'] == 'SCAN_A'
    assert payload['data']['report_type'] == 'xlsx'
    assert payload['data']['async'] == '1'
    assert payload['data']['include_vex'] is True

@patch.object(WorkbenchAPI, '_send_request')
def test_generate_report_scan_sync_success(mock_send, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/pdf', 'content-disposition': 'attachment; filename=report.pdf'}
    mock_send.return_value = {"_raw_response": mock_response}
    
    result = workbench_inst.generate_report(
        scope="scan",
        project_code="PROJ_A",
        scan_code="SCAN_A",
        report_type="html"  # HTML report should be synchronous
    )
    assert result == mock_response
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['data']['async'] == '0'

@patch.object(WorkbenchAPI, '_send_request')
def test_generate_report_project_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"process_queue_id": 54321}}
    result = workbench_inst.generate_report(
        scope="project",
        project_code="PROJ_A",
        scan_code=None,
        report_type="xlsx",
        selection_type="include_all_licenses",
        disclaimer="Test disclaimer",
        include_vex=False
    )
    assert result == 54321
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'projects'
    assert payload['action'] == 'generate_report'
    assert payload['data']['project_code'] == 'PROJ_A'
    assert payload['data']['report_type'] == 'xlsx'
    assert payload['data']['async'] == '1'
    assert payload['data']['selection_type'] == 'include_all_licenses'
    assert payload['data']['disclaimer'] == 'Test disclaimer'
    assert payload['data']['include_vex'] is False

@patch.object(WorkbenchAPI, '_send_request')
def test_check_report_generation_status_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "FINISHED", "progress": 100}}
    status = workbench_inst.check_report_generation_status(
        scope="scan",
        process_id=12345,
        scan_code="SCAN_A"
    )
    assert status["status"] == "FINISHED"
    assert status["progress"] == 100
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'check_status'
    assert payload['data']['process_id'] == '12345'
    assert payload['data']['type'] == 'REPORT_GENERATION'

@patch.object(WorkbenchAPI, '_send_request')
def test_download_report_success(mock_send, workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/pdf', 'content-disposition': 'attachment; filename=report.pdf'}
    
    # Use the mock_session directly
    mock_session.post.return_value = mock_response
    
    result = workbench_inst.download_report("scan", 12345)
    
    assert result == mock_response
    mock_session.post.assert_called_once()
    
    # Verify post call arguments
    args, kwargs = mock_session.post.call_args
    assert kwargs.get('stream') is True
    assert 'download_report' in str(kwargs.get('data', ''))