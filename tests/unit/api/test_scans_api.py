# tests/unit/api/test_scans_api.py

import pytest
import requests
import json
from unittest.mock import MagicMock, patch

# Import from the package structure
from workbench_cli.api.scans_api import ScansAPI
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
def scans_api_inst(mock_session):
    """Create a ScansAPI instance with a properly mocked session."""
    # Create a new instance with required parameters
    api = ScansAPI(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")
    # Replace the session with our mock
    api.session = mock_session
    return api

# --- Test Cases ---

# --- Test create_webapp_scan ---
@patch.object(ScansAPI, '_send_request')
def test_create_webapp_scan_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    # create_webapp_scan returns True on success, not the ID
    result = scans_api_inst.create_webapp_scan("New Scan", "PROJ1")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['action'] == 'create'
    assert payload['data']['scan_name'] == 'New Scan'
    assert payload['data']['project_code'] == 'PROJ1'

@patch.object(ScansAPI, '_send_request')
def test_create_webapp_scan_with_git_branch(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = scans_api_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_branch="main"
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_repo_url'] == "https://github.com/example/repo.git"
    assert payload['data']['git_branch'] == "main"
    assert payload['data']['git_ref_type'] == "branch"

@patch.object(ScansAPI, '_send_request')
def test_create_webapp_scan_with_git_tag(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = scans_api_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_tag="v1.0.0"
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_repo_url'] == "https://github.com/example/repo.git"
    assert payload['data']['git_branch'] == "v1.0.0"  # API uses git_branch field for both values
    assert payload['data']['git_ref_type'] == "tag"

@patch.object(ScansAPI, '_send_request')
def test_create_webapp_scan_with_git_commit(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = scans_api_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_commit="abc123def456"
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_repo_url'] == "https://github.com/example/repo.git"
    assert payload['data']['git_branch'] == "abc123def456"
    assert payload['data']['git_ref_type'] == "commit"

@patch.object(ScansAPI, '_send_request')
def test_create_webapp_scan_with_git_depth(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = scans_api_inst.create_webapp_scan(
        "Git Scan", "PROJ1", 
        git_url="https://github.com/example/repo.git",
        git_branch="main",
        git_depth=1
    )
    assert result is True
    payload = mock_send.call_args[0][0]
    assert payload['data']['git_depth'] == "1"

@patch.object(ScansAPI, '_send_request')
def test_create_webapp_scan_exists(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Scan code already exists"}
    with pytest.raises(ScanExistsError, match="Scan 'Existing Scan' already exists"):
        scans_api_inst.create_webapp_scan("Existing Scan", "PROJ1")

# --- Tests for Git operations ---
@patch.object(ScansAPI, '_send_request')
def test_download_content_from_git_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "QUEUED"}}
    result = scans_api_inst.download_content_from_git("scan1")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'download_content_from_git'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(ScansAPI, '_send_request')
def test_download_content_from_git_failure(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Git URL not set"}
    with pytest.raises(ApiError, match="Failed to initiate download from Git: Git URL not set"):
        scans_api_inst.download_content_from_git("scan1")

@patch.object(ScansAPI, '_send_request')
def test_check_status_download_content_from_git(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": "RUNNING"}
    status = scans_api_inst.check_status_download_content_from_git("scan1")
    assert status == "RUNNING"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'check_status_download_content_from_git'
    assert payload['data']['scan_code'] == 'scan1'

# --- Test remove_uploaded_content ---
@patch.object(ScansAPI, '_send_request')
def test_remove_uploaded_content_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    result = scans_api_inst.remove_uploaded_content("scan1", "test_file.txt")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'remove_uploaded_content'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['filename'] == 'test_file.txt'

@patch.object(ScansAPI, '_send_request')
def test_remove_uploaded_content_file_not_found(mock_send, scans_api_inst):
    # Response indicating file not found but API returns status 0
    mock_send.return_value = {
        "status": "0", 
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Traits.PathTrait.filename_is_not_valid"}]
    }
    
    # Should return True since the end goal (file not present) is satisfied
    result = scans_api_inst.remove_uploaded_content("scan1", "nonexistent.txt")
    assert result is True
    mock_send.assert_called_once()

# --- Tests for extract_archives ---
@patch.object(ScansAPI, '_send_request')
def test_extract_archives_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    result = scans_api_inst.extract_archives(
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

@patch.object(ScansAPI, '_send_request')
def test_extract_archives_not_found(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_api_inst.extract_archives("scan1", True, True)

@patch.object(ScansAPI, '_send_request')
def test_extract_archives_api_error(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Invalid parameters"}
    with pytest.raises(ApiError, match="Archive extraction failed for scan 'scan1'"):
        scans_api_inst.extract_archives("scan1", True, True)

# --- Tests for run_scan and related methods ---
@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_basic_success(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.run_scan(
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

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_with_run_dependency_analysis(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.run_scan(
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

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_with_id_reuse_any(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.run_scan(
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

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_with_id_reuse_project(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.run_scan(
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

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_with_id_reuse_scan(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.run_scan(
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

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_not_found(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_api_inst.run_scan(
            scan_code="scan1",
            limit=100,
            sensitivity=3,
            autoid_file_licenses=True,
            autoid_file_copyrights=True,
            autoid_pending_ids=False,
            delta_scan=False,
            id_reuse=False
        )

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_run_scan_id_reuse_validation_error(mock_send, mock_ensure, scans_api_inst):
    # Configure mock to return success
    mock_send.return_value = {"status": "1"}
    
    # The API doesn't raise an error for missing source; it disables ID reuse and proceeds
    # So we test that the _send_request is called with the correct parameters
    scans_api_inst.run_scan(
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
@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_start_dependency_analysis_success(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.start_dependency_analysis("scan1")
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'run_dependency_analysis'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['import_only'] == "0"

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_start_dependency_analysis_import_only(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "1"}
    scans_api_inst.start_dependency_analysis("scan1", import_only=True)
    payload = mock_send.call_args[0][0]
    assert payload['data']['import_only'] == "1"

@patch.object(ScansAPI, 'ensure_process_can_start')
@patch.object(ScansAPI, '_send_request')
def test_start_dependency_analysis_scan_not_found(mock_send, mock_ensure, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ApiError, match="Failed to start dependency analysis for 'scan1': Scan not found"):
        scans_api_inst.start_dependency_analysis("scan1")

# --- Tests for get_scan_status ---
@patch.object(ScansAPI, '_send_request')
def test_get_scan_status_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "RUNNING", "progress": 50}}
    status = scans_api_inst.get_scan_status("SCAN", "scan1")
    assert status == {"status": "RUNNING", "progress": 50}
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'check_status'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['type'] == 'SCAN'

@patch.object(ScansAPI, '_send_request')
def test_get_scan_status_scan_not_found(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_api_inst.get_scan_status("SCAN", "scan1")

# --- Tests for list_scans ---
@patch.object(ScansAPI, '_send_request')
def test_list_scans_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {
        "1": {"code": "SCAN_A", "name": "Scan A"},
        "2": {"code": "SCAN_B", "name": "Scan B"}
    }}
    scans = scans_api_inst.list_scans()
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

@patch.object(ScansAPI, '_send_request')
def test_list_scans_empty(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": []} # API returns empty list
    scans = scans_api_inst.list_scans()
    assert scans == []

# --- Tests for scan result fetching methods ---
@patch.object(ScansAPI, '_send_request')
def test_get_scan_folder_metrics_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {
        "total_files": 100,
        "no_match": 20,
        "pending": 10,
        "identified": 70
    }}
    metrics = scans_api_inst.get_scan_folder_metrics("scan1")
    assert metrics["total_files"] == 100
    assert metrics["no_match"] == 20
    assert metrics["pending"] == 10
    assert metrics["identified"] == 70
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_folder_metrics'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(ScansAPI, '_send_request')
def test_get_scan_folder_metrics_scan_not_found(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "row_not_found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_api_inst.get_scan_folder_metrics("scan1")

# --- Tests for scan component and license fetching ---
@patch.object(ScansAPI, '_send_request')
def test_get_scan_identified_components_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {
        "1": {"name": "Component A", "version": "1.0"},
        "2": {"name": "Component B", "version": "2.0"}
    }}
    components = scans_api_inst.get_scan_identified_components("scan1")
    assert len(components) == 2
    assert components[0]["name"] == "Component A"
    assert components[1]["version"] == "2.0"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_scan_identified_components'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(ScansAPI, '_send_request')
def test_get_scan_identified_licenses_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": [
        {"name": "MIT", "id": 1},
        {"name": "Apache-2.0", "id": 2}
    ]}
    licenses = scans_api_inst.get_scan_identified_licenses("scan1")
    assert len(licenses) == 2
    assert licenses[0]["name"] == "MIT"
    assert licenses[1]["name"] == "Apache-2.0"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_scan_identified_licenses'
    assert payload['data']['scan_code'] == 'scan1'
    assert payload['data']['unique'] == "1"

@patch.object(ScansAPI, '_send_request')
def test_get_dependency_analysis_results_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": [
        {"name": "dep1", "version": "1.0"},
        {"name": "dep2", "version": "2.0"}
    ]}
    deps = scans_api_inst.get_dependency_analysis_results("scan1")
    assert len(deps) == 2
    assert deps[0]["name"] == "dep1"
    assert deps[1]["version"] == "2.0"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_dependency_analysis_results'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(ScansAPI, '_send_request')
def test_get_dependency_analysis_results_not_run(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "0", "error": "Dependency analysis has not been run"}
    deps = scans_api_inst.get_dependency_analysis_results("scan1")
    assert deps == []

@patch.object(ScansAPI, '_send_request')
def test_get_pending_files_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {
        "file1.txt": "pending",
        "file2.txt": "pending"
    }}
    pending = scans_api_inst.get_pending_files("scan1")
    assert len(pending) == 2
    assert "file1.txt" in pending
    assert "file2.txt" in pending
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_pending_files'
    assert payload['data']['scan_code'] == 'scan1'

@patch.object(ScansAPI, '_send_request')
def test_get_policy_warnings_counter_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"count": 5}}
    warnings = scans_api_inst.get_policy_warnings_counter("scan1")
    assert warnings["count"] == 5
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['group'] == 'scans'
    assert payload['action'] == 'get_policy_warnings_counter'
    assert payload['data']['scan_code'] == 'scan1'

# --- Tests for report generation ---
@patch.object(ScansAPI, '_send_request')
def test_generate_scan_report_async_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"process_queue_id": 12345}}
    result = scans_api_inst.generate_scan_report(
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

@patch.object(ScansAPI, '_send_request')
def test_generate_scan_report_sync_success(mock_send, scans_api_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/pdf', 'content-disposition': 'attachment; filename=report.pdf'}
    mock_send.return_value = {"_raw_response": mock_response}
    
    result = scans_api_inst.generate_scan_report(
        scan_code="SCAN_A",
        report_type="html"  # HTML report should be synchronous
    )
    assert result == mock_response
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['data']['async'] == '0'

@patch.object(ScansAPI, '_send_request')
def test_check_scan_report_status_success(mock_send, scans_api_inst):
    mock_send.return_value = {"status": "1", "data": {"status": "FINISHED", "progress": 100}}
    status = scans_api_inst.check_scan_report_status(
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

@patch.object(ScansAPI, '_send_request')
@patch.object(ScansAPI, 'ensure_process_can_start')
def test_get_scan_information_failure(mock_ensure_process_can_start, mock_send_request, scans_api_inst):
    mock_send_request.return_value = {"status": "0", "error": "Not found"}
    with pytest.raises(ApiError, match="Not found"):
        scans_api_inst.get_scan_information("scan1")

@patch.object(ScansAPI, '_send_request')
@patch.object(ScansAPI, 'ensure_process_can_start')
def test_method_pre_check_failure(mock_ensure_process_can_start, mock_send_request, scans_api_inst, capsys):
    mock_ensure_process_can_start.side_effect = Exception("Pre-check failed")
    
    with pytest.raises(Exception, match="Pre-check failed"):
        scans_api_inst.run_scan("scan1", 10, 10, False, False, False, False, False)

    assert "Pre-scan check failed" in capsys.readouterr().err
    mock_send_request.assert_not_called() 