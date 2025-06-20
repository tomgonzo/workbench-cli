# tests/unit/handlers/test_import_sbom.py

import pytest
import os
from unittest.mock import MagicMock, patch, call

from workbench_cli.handlers.import_sbom import handle_import_sbom, _get_project_and_scan_codes, _validate_sbom_file
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


class TestImportSBOMHandler:
    """Test cases for the import-sbom handler."""

    @patch('workbench_cli.handlers.import_sbom.fetch_display_save_results')
    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_success(self, mock_isfile, mock_exists, mock_validate_sbom, mock_assert_idle, mock_ensure_compat, mock_print_summary, mock_fetch, mock_workbench, mock_params):
        """Tests the successful execution of handle_import_sbom."""
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = False
        
        mock_validate_sbom.return_value = ('cyclonedx', '1.6', {'components_count': 42})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

        result = handle_import_sbom(mock_workbench, mock_params)
        
        assert result is True
        mock_validate_sbom.assert_called_once_with("/path/to/sbom.json")
        mock_workbench.resolve_project.assert_called_once_with("SBOMProj", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("SBOMScan", "SBOMProj", create_if_missing=True, params=mock_params, import_from_report=True)
        mock_workbench.upload_sbom_file.assert_called_once_with(scan_code="TEST_SCAN_CODE", path="/path/to/sbom.json")
        mock_workbench.import_report.assert_called_once_with(scan_code="TEST_SCAN_CODE")

    def test_handle_import_sbom_no_path(self, mock_workbench, mock_params):
        """Tests validation error when no path is provided."""
        mock_params.command = 'import-sbom'
        mock_params.path = None

        with pytest.raises(ValidationError, match="A path must be provided for the import-sbom command"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=False)
    def test_handle_import_sbom_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        mock_params.command = 'import-sbom'
        mock_params.path = "/nonexistent/path"

        with pytest.raises(FileSystemError, match="does not exist"):
            handle_import_sbom(mock_workbench, mock_params)


class TestValidateSBOMFile:
    """Test cases for the _validate_sbom_file function."""

    @patch('workbench_cli.handlers.import_sbom.SBOMValidator.validate_sbom_file')
    def test_validate_sbom_file_success(self, mock_validator):
        """Tests successful SBOM validation."""
        mock_validator.return_value = ('cyclonedx', '1.6', {'components_count': 42})
        
        result = _validate_sbom_file('/path/to/sbom.json')
        
        assert result == ('cyclonedx', '1.6', {'components_count': 42})
        mock_validator.assert_called_once_with('/path/to/sbom.json')

    @patch('workbench_cli.handlers.import_sbom.SBOMValidator.validate_sbom_file')
    def test_validate_sbom_file_validation_error(self, mock_validator):
        """Tests SBOM validation error."""
        mock_validator.side_effect = ValidationError("Invalid format")
        
        with pytest.raises(ValidationError, match="Invalid format"):
            _validate_sbom_file('/path/to/invalid.json')


class TestGetProjectAndScanCodes:
    """Test cases for the _get_project_and_scan_codes function."""

    def test_get_project_and_scan_codes_success(self, mock_workbench, mock_params):
        """Tests successful project and scan code resolution."""
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        
        mock_workbench.resolve_project.return_value = 'PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        
        project_code, scan_code = _get_project_and_scan_codes(mock_workbench, mock_params)
        
        assert project_code == 'PROJ_CODE'
        assert scan_code == 'SCAN_CODE'
        mock_workbench.resolve_project.assert_called_once_with("TestProject", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("TestScan", "TestProject", create_if_missing=True, params=mock_params, import_from_report=True)
import os
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_cli.handlers.import_sbom import handle_import_sbom, _get_project_and_scan_codes, _validate_sbom_file
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


class TestImportSBOMHandler:
    """Test cases for the import-sbom handler."""

    @patch('workbench_cli.handlers.import_sbom.fetch_display_save_results')
    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_success(self, mock_isfile, mock_exists, mock_validate_sbom, 
                                       mock_assert_idle, mock_ensure_compat, mock_print_summary, 
                                       mock_fetch, mock_workbench, mock_params):
        """Tests the successful execution of handle_import_sbom."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = False
        
        # Configure mocks
        mock_validate_sbom.return_value = ('cyclonedx', '1.6', {'components_count': 42})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

        # Execute the handler
        result = handle_import_sbom(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_validate_sbom.assert_called_once_with("/path/to/sbom.json")
        mock_workbench.resolve_project.assert_called_once_with("SBOMProj", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("SBOMScan", "SBOMProj", 
                                                          create_if_missing=True, params=mock_params,
                                                          import_from_report=True)
        mock_ensure_compat.assert_called_once_with(mock_workbench, mock_params, "TEST_SCAN_CODE")
        mock_assert_idle.assert_called_once_with(mock_workbench, "TEST_SCAN_CODE", mock_params, ["REPORT_IMPORT"])
        mock_workbench.upload_sbom_file.assert_called_once_with(
            scan_code="TEST_SCAN_CODE", path="/path/to/sbom.json"
        )
        mock_workbench.import_report.assert_called_once_with(scan_code="TEST_SCAN_CODE")
        mock_workbench.wait_for_scan_to_finish.assert_called_once_with(
            "REPORT_IMPORT", "TEST_SCAN_CODE", 10, 2
        )
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_no_wait(self, mock_isfile, mock_exists, mock_validate_sbom,
                                       mock_assert_idle, mock_ensure_compat, mock_print_summary, 
                                       mock_workbench, mock_params):
        """Tests the execution of handle_import_sbom with no wait."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = True
        
        # Configure mocks
        mock_validate_sbom.return_value = ('spdx', '2.3', {'packages_count': 15})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)

        # Execute the handler
        result = handle_import_sbom(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_validate_sbom.assert_called_once()
        mock_workbench.resolve_project.assert_called_once()
        mock_workbench.resolve_scan.assert_called_once()
        mock_workbench.upload_sbom_file.assert_called_once()
        mock_workbench.import_report.assert_called_once()
        # Should not wait or fetch results in no-wait mode
        mock_workbench.wait_for_scan_to_finish.assert_not_called()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_scan_not_found(self, mock_isfile, mock_exists, mock_validate_sbom,
                                              mock_workbench, mock_params):
        """Tests the execution of handle_import_sbom with a scan not found."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        
        # Configure mocks
        mock_validate_sbom.return_value = ('cyclonedx', '1.5', {})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

        # Execute and verify exception
        with pytest.raises(ScanNotFoundError):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_project_not_found(self, mock_isfile, mock_exists, mock_validate_sbom,
                                                 mock_workbench, mock_params):
        """Tests the execution of handle_import_sbom with a project not found."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        
        # Configure mocks
        mock_validate_sbom.return_value = ('cyclonedx', '1.4', {})
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_import_sbom(mock_workbench, mock_params)

    def test_handle_import_sbom_no_path(self, mock_workbench, mock_params):
        """Tests validation error when no path is provided."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.path = None

        # Execute and verify exception
        with pytest.raises(ValidationError, match="A path must be provided for the import-sbom command"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=False)
    def test_handle_import_sbom_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=False)
    def test_handle_import_sbom_path_not_file(self, mock_isfile, mock_exists, 
                                             mock_workbench, mock_params):
        """Tests validation error when path is not a file."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.path = "/path/to/directory"

        # Execute and verify exception
        with pytest.raises(ValidationError, match="must be a file"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file', 
           side_effect=ValidationError("Invalid SBOM format"))
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_validation_error(self, mock_isfile, mock_exists, mock_validate_sbom,
                                               mock_workbench, mock_params):
        """Tests handling of SBOM validation error."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.path = "/path/to/invalid.json"

        # Execute and verify exception
        with pytest.raises(ValidationError, match="SBOM validation failed"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.import_sbom.fetch_display_save_results', 
           side_effect=ApiError("Error fetching results"))
    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_fetch_api_error(self, mock_isfile, mock_exists, mock_validate_sbom,
                                              mock_assert_idle, mock_ensure_compat, mock_print_summary, 
                                              mock_fetch, mock_workbench, mock_params):
        """Tests handling of ApiError from fetch_display_save_results (should not fail the whole operation)."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.path = "/path/to/sbom.json"
        mock_params.scan_number_of_tries = 10
        mock_params.scan_wait_time = 5
        mock_params.no_wait = False

        # Configure mocks
        mock_validate_sbom.return_value = ('cyclonedx', '1.6', {})
        mock_workbench.resolve_project.return_value = 'P_CODE'
        mock_workbench.resolve_scan.return_value = ('S_CODE', 1)
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 10.0)

        # Execute - should complete successfully despite fetch error
        result = handle_import_sbom(mock_workbench, mock_params)
        
        # Should still return True even though fetch failed
        assert result is True
        
        # Verify core operations still completed
        mock_workbench.upload_sbom_file.assert_called_once()
        mock_workbench.import_report.assert_called_once()
        mock_fetch.assert_called_once()  # Was attempted but failed

    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_upload_error(self, mock_isfile, mock_exists, mock_validate_sbom,
                                           mock_assert_idle, mock_ensure_compat, mock_print_summary,
                                           mock_workbench, mock_params):
        """Tests handling of upload error."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"

        # Configure mocks
        mock_validate_sbom.return_value = ('cyclonedx', '1.6', {})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
        mock_workbench.upload_sbom_file.side_effect = ApiError("Upload failed")

        # Execute and verify exception
        with pytest.raises(WorkbenchCLIError, match="Failed to upload SBOM file"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_import_error(self, mock_isfile, mock_exists, mock_validate_sbom,
                                           mock_assert_idle, mock_ensure_compat, mock_print_summary,
                                           mock_workbench, mock_params):
        """Tests handling of import_report error."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"

        # Configure mocks
        mock_validate_sbom.return_value = ('spdx', '2.2', {})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
        mock_workbench.import_report.side_effect = ApiError("Import failed")

        # Execute and verify exception
        with pytest.raises(WorkbenchCLIError, match="Failed to start SBOM import"):
            handle_import_sbom(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.import_sbom.print_operation_summary')
    @patch('workbench_cli.handlers.import_sbom.ensure_scan_compatibility')
    @patch('workbench_cli.handlers.import_sbom.assert_scan_is_idle')
    @patch('workbench_cli.handlers.import_sbom._validate_sbom_file')
    @patch('os.path.exists', return_value=True)
    @patch('os.path.isfile', return_value=True)
    def test_handle_import_sbom_timeout_error(self, mock_isfile, mock_exists, mock_validate_sbom,
                                            mock_assert_idle, mock_ensure_compat, mock_print_summary,
                                            mock_workbench, mock_params):
        """Tests handling of timeout during SBOM import."""
        # Configure params
        mock_params.command = 'import-sbom'
        mock_params.project_name = "SBOMProj"
        mock_params.scan_name = "SBOMScan"
        mock_params.path = "/path/to/sbom.json"
        mock_params.no_wait = False

        # Configure mocks
        mock_validate_sbom.return_value = ('cyclonedx', '1.6', {})
        mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
        mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Import timed out")

        # Execute and verify exception
        with pytest.raises(ProcessTimeoutError, match="Import timed out"):
            handle_import_sbom(mock_workbench, mock_params)


class TestValidateSBOMFile:
    """Test cases for the _validate_sbom_file function."""

    @patch('workbench_cli.handlers.import_sbom.SBOMValidator.validate_sbom_file')
    def test_validate_sbom_file_success(self, mock_validator):
        """Tests successful SBOM validation."""
        mock_validator.return_value = ('cyclonedx', '1.6', {'components_count': 42})
        
        result = _validate_sbom_file('/path/to/sbom.json')
        
        assert result == ('cyclonedx', '1.6', {'components_count': 42})
        mock_validator.assert_called_once_with('/path/to/sbom.json')

    @patch('workbench_cli.handlers.import_sbom.SBOMValidator.validate_sbom_file')
    def test_validate_sbom_file_validation_error(self, mock_validator):
        """Tests SBOM validation error."""
        mock_validator.side_effect = ValidationError("Invalid format")
        
        with pytest.raises(ValidationError, match="Invalid format"):
            _validate_sbom_file('/path/to/invalid.json')

    @patch('workbench_cli.handlers.import_sbom.SBOMValidator.validate_sbom_file')
    def test_validate_sbom_file_unexpected_error(self, mock_validator):
        """Tests unexpected error during SBOM validation."""
        mock_validator.side_effect = Exception("Unexpected error")
        
        with pytest.raises(Exception, match="Unexpected error"):
            _validate_sbom_file('/path/to/sbom.json')


class TestGetProjectAndScanCodes:
    """Test cases for the _get_project_and_scan_codes function."""

    def test_get_project_and_scan_codes_success(self, mock_workbench, mock_params):
        """Tests successful project and scan code resolution."""
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        
        mock_workbench.resolve_project.return_value = 'PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        
        project_code, scan_code = _get_project_and_scan_codes(mock_workbench, mock_params)
        
        assert project_code == 'PROJ_CODE'
        assert scan_code == 'SCAN_CODE'
        mock_workbench.resolve_project.assert_called_once_with("TestProject", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with(
            "TestScan", "TestProject", create_if_missing=True, 
            params=mock_params, import_from_report=True
        )

    def test_get_project_and_scan_codes_project_error(self, mock_workbench, mock_params):
        """Tests project resolution error."""
        mock_params.project_name = "NonExistent"
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")
        
        with pytest.raises(ProjectNotFoundError):
            _get_project_and_scan_codes(mock_workbench, mock_params)

    def test_get_project_and_scan_codes_scan_error(self, mock_workbench, mock_params):
        """Tests scan resolution error."""
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        
        mock_workbench.resolve_project.return_value = 'PROJ_CODE'
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
        
        with pytest.raises(ScanNotFoundError):
            _get_project_and_scan_codes(mock_workbench, mock_params) 