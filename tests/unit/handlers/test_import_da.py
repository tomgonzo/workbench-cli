# tests/unit/handlers/test_import_da.py

import pytest
import os
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_cli.handlers.import_da import handle_import_da, _get_project_and_scan_codes
from workbench_cli.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
    FileSystemError,
    ValidationError,
    ApiError,
    NetworkError,
    WorkbenchCLIError,
    ProcessError,
    ProcessTimeoutError,
    CompatibilityError
)


class TestImportDAHandler:
    """Test cases for the import-da handler."""

    @patch('workbench_cli.handlers.import_da.fetch_display_save_results')
    @patch('workbench_cli.handlers.import_da.print_operation_summary')
    @patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_is_idle')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_da_success(self, mock_isfile, mock_exists, mock_assert_idle, 
                                    mock_ensure_compat, mock_print_summary, mock_fetch, 
                                    mock_workbench, mock_params):
        """Tests the successful execution of handle_import_da."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.project_name = "DAProj"
        mock_params.scan_name = "DAScan"
        mock_params.path = "/path/to/results.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

        # Execute the handler
        result = handle_import_da(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.resolve_project.assert_called_once_with("DAProj", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("DAScan", "DAProj", 
                                                          create_if_missing=True, params=mock_params)
        mock_workbench.upload_dependency_analysis_results.assert_called_once_with(
            scan_code="TEST_SCAN_CODE", path="/path/to/results.json"
        )
        mock_workbench.ensure_process_can_start.assert_called_once_with(
            "DEPENDENCY_ANALYSIS", "TEST_SCAN_CODE", wait_max_tries=10, wait_interval=5
        )
        mock_workbench.start_dependency_analysis.assert_called_once_with(
            scan_code="TEST_SCAN_CODE", import_only=True
        )
        mock_workbench.wait_for_scan_to_finish.assert_called_once_with(
            "DEPENDENCY_ANALYSIS", "TEST_SCAN_CODE", 10, 2
        )
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.import_da.print_operation_summary')
    @patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_is_idle')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_da_no_wait(self, mock_isfile, mock_exists, mock_assert_idle, 
                                    mock_ensure_compat, mock_print_summary, 
                                    mock_workbench, mock_params):
        """Tests the execution of handle_import_da with no wait."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.project_name = "DAProj"
        mock_params.scan_name = "DAScan"
        mock_params.path = "/path/to/results.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = True
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)

        # Execute the handler
        result = handle_import_da(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.resolve_project.assert_called_once()
        mock_workbench.resolve_scan.assert_called_once()
        mock_workbench.upload_dependency_analysis_results.assert_called_once()
        mock_workbench.start_dependency_analysis.assert_called_once()
        # Should not wait or fetch results in no-wait mode
        mock_workbench.wait_for_scan_to_finish.assert_not_called()
        mock_print_summary.assert_called_once()

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_da_scan_not_found(self, mock_isfile, mock_exists, 
                                           mock_workbench, mock_params):
        """Tests the execution of handle_import_da with a scan not found."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.project_name = "DAProj"
        mock_params.scan_name = "DAScan"
        mock_params.path = "/path/to/results.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

        # Execute and verify exception
        with pytest.raises(ScanNotFoundError):
            handle_import_da(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_da_project_not_found(self, mock_isfile, mock_exists, 
                                              mock_workbench, mock_params):
        """Tests the execution of handle_import_da with a project not found."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "DAScan"
        mock_params.path = "/path/to/results.json"
        
        # Configure mocks
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_import_da(mock_workbench, mock_params)

    def test_handle_import_da_no_path(self, mock_workbench, mock_params):
        """Tests validation error when no path is provided."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.path = None

        # Execute and verify exception
        with pytest.raises(ValidationError, match="A path must be provided"):
            handle_import_da(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=False)
    def test_handle_import_da_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_import_da(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=False)
    def test_handle_import_da_path_not_file(self, mock_isfile, mock_exists, 
                                          mock_workbench, mock_params):
        """Tests validation error when path is not a file."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.path = "/path/to/directory"

        # Execute and verify exception
        with pytest.raises(ValidationError, match="must be a file"):
            handle_import_da(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.import_da.fetch_display_save_results', 
           side_effect=ApiError("Error fetching results"))
    @patch('workbench_cli.handlers.import_da.print_operation_summary')
    @patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_is_idle')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_da_fetch_api_error(self, mock_isfile, mock_exists, mock_assert_idle, 
                                            mock_ensure_compat, mock_print_summary, mock_fetch,
                                            mock_workbench, mock_params):
        """Tests handling of ApiError from fetch_display_save_results."""
        # Configure params
        mock_params.command = 'import-da'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.path = "/path/to/results.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = False

        # Configure mocks
        mock_workbench.resolve_project.return_value = 'PC'
        mock_workbench.resolve_scan.return_value = ('SC', 1)
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

        # Execute - should complete but log warning about fetch failure
        result = handle_import_da(mock_workbench, mock_params)
        
        # Should still return True despite fetch error
        assert result is True
        mock_fetch.assert_called_once()


class TestGetProjectAndScanCodes:
    """Test cases for the _get_project_and_scan_codes helper function."""
    
    def test_get_project_and_scan_codes_success(self, mock_workbench, mock_params):
        """Tests successful resolution of project and scan codes."""
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 456)
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        
        # Execute
        project_code, scan_code = _get_project_and_scan_codes(mock_workbench, mock_params)
        
        # Verify
        assert project_code == 'PROJ_CODE'
        assert scan_code == 'SCAN_CODE'
        mock_workbench.resolve_project.assert_called_once_with("TestProject", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("TestScan", "TestProject", 
                                                          create_if_missing=True, params=mock_params) 