# tests/unit/handlers/test_download_reports.py

import pytest
import os
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_cli.handlers.download_reports import handle_download_reports
from workbench_cli.exceptions import (
    ProcessError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError,
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    FileSystemError,
    ProcessTimeoutError
)


class TestDownloadReportsHandler:
    """Test cases for the download-reports handler."""

    def setup_method(self):
        """Setup common mock attributes for workbench API."""
        self.scan_report_types = {'html', 'xlsx', 'spdx', 'spdx_lite', 'cyclone_dx', 'string_match', 'dynamic_top_matched_components'}
        self.project_report_types = {'xlsx', 'spdx', 'spdx_lite', 'cyclone_dx'}
        self.async_report_types = {'xlsx', 'spdx', 'spdx_lite', 'cyclone_dx', 'basic'}

    @patch('workbench_cli.handlers.download_reports.wait_for_scan_completion')
    @patch('os.makedirs')
    @patch('os.path.exists', return_value=False)
    def test_handle_download_reports_scan_sync(self, mock_exists, mock_makedirs, mock_wait, 
                                             mock_workbench, mock_params):
        """Tests downloading a synchronous scan report."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        mock_params.report_type = "html"
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        mock_params.selection_type = None
        mock_params.selection_view = None
        mock_params.disclaimer = None
        mock_params.include_vex = True
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        mock_workbench.ASYNC_REPORT_TYPES = self.async_report_types
        
        # Setup mock responses
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        
        # Mock response object
        mock_response = MagicMock()
        mock_response.content = b"<html>Report content</html>"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_workbench.generate_scan_report.return_value = mock_response
        mock_workbench._save_report_content = MagicMock()
        
        # Execute
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        mock_makedirs.assert_called_once_with("reports", exist_ok=True)
        mock_workbench.resolve_project.assert_called_once_with("TestProject", create_if_missing=False)
        mock_workbench.resolve_scan.assert_called_once_with(
            scan_name="TestScan", project_name="TestProject", create_if_missing=False, params=mock_params
        )
        mock_wait.assert_called_once()
        mock_workbench.generate_scan_report.assert_called_once()
        mock_workbench._save_report_content.assert_called_once()

    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True)
    def test_handle_download_reports_project_async(self, mock_exists, mock_makedirs,
                                                  mock_workbench, mock_params):
        """Tests downloading an asynchronous project report."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = None
        mock_params.report_type = "xlsx"
        mock_params.report_scope = "project"
        mock_params.report_save_path = "reports"
        mock_params.selection_type = None
        mock_params.selection_view = None
        mock_params.disclaimer = None
        mock_params.include_vex = True
        mock_params.scan_number_of_tries = 60
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        mock_workbench.ASYNC_REPORT_TYPES = self.async_report_types
        
        # Setup mock responses
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        process_id = 12345
        mock_workbench.generate_project_report.return_value = process_id
        mock_workbench.check_project_report_status = MagicMock()
        mock_workbench._wait_for_process = MagicMock()
        
        # Mock download response
        mock_response = MagicMock()
        mock_response.content = b"XLSX content"
        mock_response.headers = {"Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
        mock_workbench.download_project_report.return_value = mock_response
        mock_workbench._save_report_content = MagicMock()
        
        # Execute
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        mock_workbench.resolve_project.assert_called_once_with("TestProject", create_if_missing=False)
        mock_workbench.generate_project_report.assert_called_once()
        mock_workbench._wait_for_process.assert_called_once()
        mock_workbench.download_project_report.assert_called_once_with(process_id)
        mock_workbench._save_report_content.assert_called_once()

    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True)
    def test_handle_download_reports_all_types(self, mock_exists, mock_makedirs, mock_workbench, mock_params):
        """Tests downloading all report types."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject" 
        mock_params.scan_name = None
        mock_params.report_type = "ALL"  # Should resolve to all project types
        mock_params.report_scope = "project"
        mock_params.report_save_path = "reports"
        mock_params.selection_type = None
        mock_params.selection_view = None
        mock_params.disclaimer = None
        mock_params.include_vex = True
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        mock_workbench.ASYNC_REPORT_TYPES = self.async_report_types
        
        # Setup mock responses
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.generate_project_report.return_value = 12345
        mock_workbench._wait_for_process = MagicMock()
        
        # Mock download response
        mock_response = MagicMock()
        mock_response.content = b"Report content"
        mock_workbench.download_project_report.return_value = mock_response
        mock_workbench._save_report_content = MagicMock()
        
        # Execute
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify - should process all project report types
        assert result is True
        expected_calls = len(self.project_report_types)
        assert mock_workbench.generate_project_report.call_count == expected_calls
        assert mock_workbench._save_report_content.call_count == expected_calls

    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True)
    def test_handle_download_reports_multiple_types(self, mock_exists, mock_makedirs, mock_workbench, mock_params):
        """Tests downloading multiple specific report types."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        mock_params.report_type = "html,xlsx"  # Multiple types
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        mock_params.selection_type = None
        mock_params.selection_view = None
        mock_params.disclaimer = None
        mock_params.include_vex = True
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        mock_workbench.ASYNC_REPORT_TYPES = self.async_report_types
        
        # Setup mock responses
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 1)
        
        # Mock different responses for different report types
        def mock_generate_scan_report(scan_code, **kwargs):
            if kwargs.get('report_type') == 'html':
                # Sync response
                mock_response = MagicMock()
                mock_response.content = b"<html>content</html>"
                return mock_response
            elif kwargs.get('report_type') == 'xlsx':
                # Async process ID
                return 12345
                
        mock_workbench.generate_scan_report.side_effect = mock_generate_scan_report
        mock_workbench._wait_for_process = MagicMock()
        
        # Mock download response for async
        mock_response = MagicMock()
        mock_response.content = b"XLSX content"
        mock_workbench.download_scan_report.return_value = mock_response
        mock_workbench._save_report_content = MagicMock()
        
        # Execute
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        assert mock_workbench.generate_scan_report.call_count == 2
        mock_workbench._save_report_content.assert_called()

    def test_handle_download_reports_invalid_scan_report_type(self, mock_workbench, mock_params):
        """Tests validation error for invalid scan report type."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        mock_params.report_type = "invalid_type"
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        
        # Execute and verify
        with pytest.raises(ValidationError, match="Report type 'invalid_type' is not supported for scan scope"):
            handle_download_reports(mock_workbench, mock_params)

    def test_handle_download_reports_invalid_project_report_type(self, mock_workbench, mock_params):
        """Tests validation error for invalid project report type."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = None
        mock_params.report_type = "html"  # HTML not supported for project scope
        mock_params.report_scope = "project"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        
        # Execute and verify
        with pytest.raises(ValidationError, match="Report type 'html' is not supported for project scope"):
            handle_download_reports(mock_workbench, mock_params)

    def test_handle_download_reports_scan_no_scan_name(self, mock_workbench, mock_params):
        """Tests validation error when scan name is missing for scan scope."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = None  # Missing scan name
        mock_params.report_type = "html"
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        
        # Execute and verify
        with pytest.raises(ValidationError, match="Scan name is required for scan scope reports"):
            handle_download_reports(mock_workbench, mock_params)

    def test_handle_download_reports_project_no_project_name(self, mock_workbench, mock_params):
        """Tests validation error when project name is missing for project scope."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = None  # Missing project name
        mock_params.scan_name = None
        mock_params.report_type = "xlsx"
        mock_params.report_scope = "project"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        
        # Execute and verify
        with pytest.raises(ValidationError, match="Project name is required for project scope reports"):
            handle_download_reports(mock_workbench, mock_params)

    def test_handle_download_reports_project_resolve_fails(self, mock_workbench, mock_params):
        """Tests project resolution failure."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = None
        mock_params.report_type = "xlsx"
        mock_params.report_scope = "project"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.PROJECT_REPORT_TYPES = self.project_report_types
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")
        
        # Execute and verify
        with pytest.raises(ProjectNotFoundError):
            handle_download_reports(mock_workbench, mock_params)

    def test_handle_download_reports_scan_resolve_fails(self, mock_workbench, mock_params):
        """Tests scan resolution failure."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "NonExistent"
        mock_params.report_type = "html"
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
        
        # Execute and verify
        with pytest.raises(ScanNotFoundError):
            handle_download_reports(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.download_reports.wait_for_scan_completion')
    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True)
    def test_handle_download_reports_scan_incomplete_warning(self, mock_exists, mock_makedirs, mock_wait,
                                                           mock_workbench, mock_params):
        """Tests handling of incomplete scan with warning."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        mock_params.report_type = "html"
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 1)
        mock_wait.return_value = (False, False, {})  # scan NOT completed
        
        # Mock response object
        mock_response = MagicMock()
        mock_response.content = b"<html>Report content</html>"
        mock_workbench.generate_scan_report.return_value = mock_response
        mock_workbench._save_report_content = MagicMock()
        
        # Execute - should still succeed but with warnings
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        mock_wait.assert_called_once()
        mock_workbench.generate_scan_report.assert_called_once()

    @patch('workbench_cli.handlers.download_reports.wait_for_scan_completion')
    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True)
    def test_handle_download_reports_wait_for_scan_api_error(self, mock_exists, mock_makedirs, mock_wait,
                                                           mock_workbench, mock_params):
        """Tests handling of API error during scan completion check."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        mock_params.report_type = "html"
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 1)
        mock_wait.side_effect = ApiError("API Error during scan check")
        
        # Mock response object
        mock_response = MagicMock()
        mock_response.content = b"<html>Report content</html>"
        mock_workbench.generate_scan_report.return_value = mock_response
        mock_workbench._save_report_content = MagicMock()
        
        # Execute - should still succeed despite API error
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        mock_workbench.generate_scan_report.assert_called_once()

    @patch('workbench_cli.handlers.download_reports.wait_for_scan_completion')
    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True)
    def test_handle_download_reports_async_process_timeout(self, mock_exists, mock_makedirs, mock_wait,
                                                         mock_workbench, mock_params):
        """Tests handling of process timeout during async report generation."""
        # Configure params
        mock_params.command = 'download-reports'
        mock_params.project_name = "TestProject"
        mock_params.scan_name = "TestScan"
        mock_params.report_type = "xlsx"  # Async report type
        mock_params.report_scope = "scan"
        mock_params.report_save_path = "reports"
        mock_params.scan_number_of_tries = 60
        
        # Setup workbench report types
        mock_workbench.SCAN_REPORT_TYPES = self.scan_report_types
        mock_workbench.ASYNC_REPORT_TYPES = self.async_report_types
        mock_workbench.resolve_project.return_value = "PROJ_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CODE", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        
        # Mock async process
        process_id = 12345
        mock_workbench.generate_scan_report.return_value = process_id
        mock_workbench._wait_for_process.side_effect = ProcessTimeoutError("Process timed out")
        
        # Execute - should return False due to timeout
        result = handle_download_reports(mock_workbench, mock_params)
        
        # Verify - should return False as no reports succeeded
        assert result is False
        mock_workbench._wait_for_process.assert_called_once() 