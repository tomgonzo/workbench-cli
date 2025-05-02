# tests/handlers/test_import_da_handler.py

import pytest
from unittest.mock import MagicMock, patch

# Import handler and dependencies
from workbench_agent.handlers import import_da
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ProjectNotFoundError,
    ScanNotFoundError,
    CompatibilityError,
    ValidationError
)

# Test success case
def test_handle_import_da_success(mock_workbench, mock_params):
    """Tests the successful execution of handle_import_da."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "DAProj"
    mock_params.scan_name = "DAScan"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='TEST_PROJ_CODE') as mock_resolve_proj, \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('TEST_SCAN_CODE', 123)) as mock_resolve_scan, \
         patch('workbench_agent.handlers.import_da._fetch_display_save_results') as mock_fetch:
        
        # Execute the handler
        import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify the expected methods were called
        mock_resolve_proj.assert_called_once_with(mock_workbench, 'DAProj', create_if_missing=True)
        mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name='DAScan', project_name='DAProj', create_if_missing=True, params=mock_params)
        mock_workbench.upload_files.assert_called_once_with('TEST_SCAN_CODE', '/path/to/results.json', is_da_import=True)
        mock_workbench.start_dependency_analysis.assert_called_once_with('TEST_SCAN_CODE', import_only=True)
        mock_workbench.wait_for_scan_to_finish.assert_called_once_with('DEPENDENCY_ANALYSIS', 'TEST_SCAN_CODE', 10, 5)
        mock_fetch.assert_called_once_with(mock_workbench, mock_params, 'TEST_SCAN_CODE')

# Test start dependency analysis failure
def test_handle_import_da_start_da_fails(mock_workbench, mock_params):
    """Tests failure during start_dependency_analysis."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    
    # Configure start_dependency_analysis to fail
    mock_workbench.start_dependency_analysis.side_effect = ApiError("Failed to start DA")
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)):
        
        # Execute and verify exception
        with pytest.raises(ApiError, match="Failed to start DA"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.upload_files.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_called_once()
        mock_workbench.wait_for_scan_to_finish.assert_not_called()

# Test upload failure (FileSystemError)
def test_handle_import_da_upload_fails_filesystem(mock_workbench, mock_params):
    """Tests failure during upload_files (FileSystemError)."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    
    # Configure upload_files to fail
    mock_workbench.upload_files.side_effect = FileSystemError("Cannot read results file")
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)):
        
        # Execute and verify exception
        with pytest.raises(FileSystemError, match="Cannot read results file"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.upload_files.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_not_called()
        mock_workbench.wait_for_scan_to_finish.assert_not_called()

# Test upload failure (NetworkError)
def test_handle_import_da_upload_fails_network(mock_workbench, mock_params):
    """Tests failure during upload_files (NetworkError)."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    
    # Configure upload_files to fail
    mock_workbench.upload_files.side_effect = NetworkError("Upload connection failed")
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)):
        
        # Execute and verify exception
        with pytest.raises(WorkbenchAgentError, match="Error during DA results file upload from"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.start_dependency_analysis.assert_not_called()
        mock_workbench.wait_for_scan_to_finish.assert_not_called()

# Test project not found
def test_handle_import_da_project_not_found(mock_workbench, mock_params):
    """Tests propagation of ProjectNotFoundError from _resolve_project."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "NonExistent"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', side_effect=ProjectNotFoundError("DA project not found")):
        
        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError, match="DA project not found"):
            import_da.handle_import_da(mock_workbench, mock_params)

# Test scan not found
def test_handle_import_da_scan_not_found(mock_workbench, mock_params):
    """Tests propagation of ScanNotFoundError from _resolve_scan."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "NonExistent"
    mock_params.path = "/path/to/results.json"
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', side_effect=ScanNotFoundError("DA scan not found")):
        
        # Execute and verify exception
        with pytest.raises(ScanNotFoundError, match="DA scan not found"):
            import_da.handle_import_da(mock_workbench, mock_params)

# Test scan compatibility error
def test_handle_import_da_compatibility_error(mock_workbench, mock_params):
    """Tests propagation of CompatibilityError from _resolve_scan."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "ExistingNonDA"
    mock_params.path = "/path/to/results.json"
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', side_effect=CompatibilityError("Scan exists but is not DA")):
        
        # Execute and verify exception
        with pytest.raises(CompatibilityError, match="Scan exists but is not DA"):
            import_da.handle_import_da(mock_workbench, mock_params)

# Test wait process error
def test_handle_import_da_wait_process_error(mock_workbench, mock_params):
    """Tests propagation of ProcessError from wait_for_scan_to_finish."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure wait_for_scan_to_finish to fail
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessError("Scan failed during processing")
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)):
        
        # Execute and verify exception
        with pytest.raises(ProcessError, match="Scan failed during processing"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.upload_files.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_called_once()
        mock_workbench.wait_for_scan_to_finish.assert_called_once()

# Test wait timeout error
def test_handle_import_da_wait_timeout_error(mock_workbench, mock_params):
    """Tests propagation of ProcessTimeoutError from wait_for_scan_to_finish."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure wait_for_scan_to_finish to fail
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Scan timed out")
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)):
        
        # Execute and verify exception
        with pytest.raises(ProcessTimeoutError, match="Scan timed out"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.upload_files.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_called_once()
        mock_workbench.wait_for_scan_to_finish.assert_called_once()

# Test fetch API error
def test_handle_import_da_fetch_api_error(mock_workbench, mock_params):
    """Tests propagation of ApiError from _fetch_display_save_results."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)), \
         patch('workbench_agent.handlers.import_da._fetch_display_save_results', side_effect=ApiError("Error fetching results")):
        
        # Execute and verify exception
        with pytest.raises(ApiError, match="Error fetching results"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.upload_files.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_called_once()
        mock_workbench.wait_for_scan_to_finish.assert_called_once()

# Test unexpected error
def test_handle_import_da_unexpected_error(mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchAgentError."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Patch all relevant functions
    with patch('os.path.isfile', return_value=True), \
         patch('workbench_agent.handlers.import_da._resolve_project', return_value='PC'), \
         patch('workbench_agent.handlers.import_da._resolve_scan', return_value=('SC', 1)), \
         patch('workbench_agent.handlers.import_da._fetch_display_save_results', side_effect=Exception("Unexpected fetch failure")):
        
        # Execute and verify exception
        with pytest.raises(WorkbenchAgentError, match="Failed to execute import-da command: Unexpected fetch failure"):
            import_da.handle_import_da(mock_workbench, mock_params)
        
        # Verify methods called up to the failure point
        mock_workbench.upload_files.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_called_once()
        mock_workbench.wait_for_scan_to_finish.assert_called_once()
