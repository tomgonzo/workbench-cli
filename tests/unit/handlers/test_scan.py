# tests/unit/handlers/test_scan.py

import pytest
import os
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_cli.handlers.scan import handle_scan
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    FileSystemError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError
)


class TestScanHandler:
    """Test cases for the scan handler."""

    @patch('workbench_cli.handlers.scan.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_success_full_scan(self, mock_exists, mock_ensure_compat, 
                                         mock_determine_scans, mock_print_summary, mock_fetch,
                                         mock_workbench, mock_params):
        """Tests successful scan with both KB scan and dependency analysis."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = True
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = True
        mock_workbench._is_status_check_supported.return_value = True
        mock_workbench.wait_for_archive_extraction.return_value = ({}, 5.0)
        mock_workbench.wait_for_scan_to_finish.side_effect = [({}, 30.0), ({}, 15.0)]  # KB scan, then DA
        
        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.resolve_project.assert_called_once_with("ScanProject", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with(
            scan_name="ScanTest", project_name="ScanProject", create_if_missing=True, params=mock_params
        )
        mock_workbench.upload_scan_target.assert_called_once_with('SCAN_CODE', "/test/path")
        mock_workbench.extract_archives.assert_called_once_with(
            'SCAN_CODE', mock_params.recursively_extract_archives, mock_params.jar_file_extraction
        )
        mock_workbench.run_scan.assert_called_once()
        assert mock_workbench.wait_for_scan_to_finish.call_count == 2  # KB scan + DA
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_no_wait(self, mock_exists, mock_ensure_compat, 
                                mock_determine_scans, mock_print_summary,
                                mock_workbench, mock_params):
        """Tests scan with no-wait mode."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False  # No extraction needed
        
        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.run_scan.assert_called_once()
        # Should not wait for scans to finish in no-wait mode
        mock_workbench.wait_for_scan_to_finish.assert_not_called()

    @patch('workbench_cli.handlers.scan.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_dependency_analysis_only(self, mock_exists, mock_ensure_compat, 
                                                 mock_determine_scans, mock_print_summary, mock_fetch,
                                                 mock_workbench, mock_params):
        """Tests scan with dependency analysis only."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = True
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 15.0)  # Only DA
        
        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {
            "run_kb_scan": False,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with('SCAN_CODE', import_only=False)
        mock_workbench.run_scan.assert_not_called()  # Should not run KB scan
        mock_workbench.wait_for_scan_to_finish.assert_called_once_with(
            "DEPENDENCY_ANALYSIS", 'SCAN_CODE', mock_params.scan_number_of_tries, mock_params.scan_wait_time
        )
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_dependency_analysis_only_no_wait(self, mock_exists, mock_ensure_compat, 
                                                         mock_determine_scans,
                                                         mock_workbench, mock_params):
        """Tests scan with dependency analysis only and no-wait mode."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        
        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {
            "run_kb_scan": False,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with('SCAN_CODE', import_only=False)
        mock_workbench.wait_for_scan_to_finish.assert_not_called()  # No wait mode

    def test_handle_scan_no_path(self, mock_workbench, mock_params):
        """Tests validation error when no path is provided."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.path = None

        # Execute and verify exception
        with pytest.raises(ValidationError, match="A path must be provided"):
            handle_scan(mock_workbench, mock_params)

    @patch('os.path.exists', return_value=False)
    def test_handle_scan_path_not_exists(self, mock_exists, mock_workbench, mock_params):
        """Tests file system error when path doesn't exist."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.path = "/nonexistent/path"

        # Execute and verify exception
        with pytest.raises(FileSystemError, match="does not exist"):
            handle_scan(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_project_not_found(self, mock_exists, mock_ensure_compat,
                                          mock_workbench, mock_params):
        """Tests scan when project resolution fails."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_scan(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.scan.validate_reuse_source')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_with_id_reuse(self, mock_exists, mock_ensure_compat, 
                                     mock_determine_scans, mock_validate_reuse,
                                     mock_workbench, mock_params):
        """Tests scan with ID reuse enabled."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = True
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        mock_validate_reuse.return_value = ("project", "REUSE_CODE")
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_validate_reuse.assert_called_once_with(mock_workbench, mock_params)
        mock_workbench.run_scan.assert_called_once()
        # Check that ID reuse parameters were passed (positional args)
        call_args = mock_workbench.run_scan.call_args
        args = call_args[0]
        assert args[7] is True  # id_reuse parameter (7th index)
        assert args[8] == "project"  # api_reuse_type parameter (8th index)
        assert args[9] == "REUSE_CODE"  # resolved_specific_code_for_reuse (9th index)

    @patch('workbench_cli.handlers.scan.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('time.sleep')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_archive_extraction_not_supported(self, mock_exists, mock_sleep, mock_ensure_compat, 
                                                         mock_determine_scans, mock_print_summary, mock_fetch,
                                                         mock_workbench, mock_params):
        """Tests scan when archive extraction status check is not supported."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = True  # Extraction triggered
        mock_workbench._is_status_check_supported.return_value = False  # Not supported
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.extract_archives.assert_called_once()
        mock_workbench._is_status_check_supported.assert_called_once_with('SCAN_CODE', "EXTRACT_ARCHIVES")
        mock_sleep.assert_called_once_with(3)  # Should sleep when status check not supported
        mock_workbench.wait_for_archive_extraction.assert_not_called()

    @patch('workbench_cli.handlers.scan.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_clear_content_fails(self, mock_exists, mock_ensure_compat, 
                                           mock_determine_scans, mock_print_summary, mock_fetch,
                                           mock_workbench, mock_params):
        """Tests scan when clearing existing content fails."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.remove_uploaded_content.side_effect = Exception("Clear failed")
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler - should continue despite clear failure
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.remove_uploaded_content.assert_called_once_with('SCAN_CODE', '')
        mock_workbench.upload_scan_target.assert_called_once()  # Should continue with upload

    @patch('workbench_cli.handlers.scan.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_kb_scan_timeout(self, mock_exists, mock_ensure_compat, 
                                       mock_determine_scans, mock_print_summary, mock_fetch,
                                       mock_workbench, mock_params):
        """Tests scan when KB scan times out."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Scan timed out")
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute and verify exception
        with pytest.raises(ProcessTimeoutError):
            handle_scan(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.scan.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan.print_operation_summary')
    @patch('workbench_cli.handlers.scan.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
    @patch('os.path.exists', return_value=True)
    def test_handle_scan_no_show_flags(self, mock_exists, mock_ensure_compat, 
                                     mock_determine_scans, mock_print_summary, mock_fetch,
                                     mock_workbench, mock_params):
        """Tests scan when no show flags are provided."""
        # Configure params
        mock_params.command = 'scan'
        mock_params.project_name = "ScanProject"
        mock_params.scan_name = "ScanTest"
        mock_params.path = "/test/path"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        mock_params.show_licenses = False
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'SCAN_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('SCAN_CODE', 123)
        mock_workbench.upload_scan_target.return_value = None
        mock_workbench.extract_archives.return_value = False
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 30.0)
        
        # Mock scan operations to run KB scan only
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler
        result = handle_scan(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_print_summary.assert_called_once()
        # Should not fetch results when no show flags are provided
        mock_fetch.assert_not_called() 