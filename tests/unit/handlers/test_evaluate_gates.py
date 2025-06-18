# tests/unit/handlers/test_evaluate_gates.py

import pytest
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_cli.handlers.evaluate_gates import handle_evaluate_gates
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError, 
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError
)


class TestEvaluateGatesHandler:
    """Test cases for the evaluate-gates handler."""

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_pass(self, mock_wait, mock_workbench, mock_params):
        """Test passing gate check with all conditions in good state."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "ProjB"
        mock_params.scan_name = "ScanClean"
        mock_params.fail_on_pending = True
        mock_params.fail_on_policy = True
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PROJ_B_CODE"
        mock_workbench.resolve_scan.return_value = ("SCAN_CLEAN_CODE", 456)
        mock_wait.return_value = (True, True, {})  # scan and DA completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0, 
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is True  # Should return True for PASS

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_fail_pending(self, mock_wait, mock_workbench, mock_params):
        """Test failing gate check due to pending files."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = True  # Fail on pending
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {"1": "/file/a"}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL because of pending files

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_fail_policy(self, mock_wait, mock_workbench, mock_params):
        """Test failing gate check due to policy violations."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = True  # Fail on policy
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 5, 
            "identified_files_with_warnings": 2, 
            "dependencies_with_warnings": 3
        }
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL because of policy violations

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_fail_vulnerabilities(self, mock_wait, mock_workbench, mock_params):
        """Test failing gate check due to vulnerabilities."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = "high"  # Fail on high severity
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = [
            {"severity": "critical", "id": "vuln1"},
            {"severity": "high", "id": "vuln2"}
        ]

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL because of high severity vulnerabilities

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_pass_low_vulnerabilities(self, mock_wait, mock_workbench, mock_params):
        """Test passing gate check with only low severity vulnerabilities."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = "high"  # Only fail on high or above
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = [
            {"severity": "medium", "id": "vuln1"},
            {"severity": "low", "id": "vuln2"}
        ]

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is True  # Should PASS with only medium/low vulnerabilities

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_warn_vulnerabilities_no_fail_flag(self, mock_wait, mock_workbench, mock_params):
        """Test gate passes with vulnerabilities when no fail flag is set."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = None  # No fail flag
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = [
            {"severity": "critical", "id": "vuln1"},
            {"severity": "high", "id": "vuln2"}
        ]

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is True  # Should PASS despite vulnerabilities when no fail flag

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_scan_not_completed(self, mock_wait, mock_workbench, mock_params):
        """Test gate fails when scan has not completed."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = None
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (False, False, {})  # scan NOT completed

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL when scan not completed

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_api_error_pending(self, mock_wait, mock_workbench, mock_params):
        """Test handling of ApiError from get_pending_files."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = True
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.side_effect = ApiError("API Error")
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL due to API error when fail_on_pending is True

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_api_error_policy(self, mock_wait, mock_workbench, mock_params):
        """Test handling of ApiError from get_policy_warnings_counter."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = True
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.side_effect = ApiError("Policy API Error")
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL due to API error when fail_on_policy is True

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_api_error_vulnerabilities(self, mock_wait, mock_workbench, mock_params):
        """Test handling of ApiError from list_vulnerabilities."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = "high"
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.side_effect = ApiError("Vuln API Error")

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL due to API error when fail_on_vuln_severity is set

    def test_handle_evaluate_gates_project_resolve_fails(self, mock_workbench, mock_params):
        """Test gate fails when project resolution fails."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "NonExistent"
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")
        
        # Execute and verify
        with pytest.raises(ProjectNotFoundError):
            handle_evaluate_gates(mock_workbench, mock_params)

    def test_handle_evaluate_gates_scan_resolve_fails(self, mock_workbench, mock_params):
        """Test gate fails when scan resolution fails."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "NonExistent"
        mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
        
        # Execute and verify
        with pytest.raises(ScanNotFoundError):
            handle_evaluate_gates(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_show_pending_files(self, mock_wait, mock_workbench, mock_params):
        """Test showing pending files when requested."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = False
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = True  # Enable showing pending files
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {
            "1": "/file/a.py",
            "2": "/file/b.py",
            "3": "/file/c.py"
        }
        mock_workbench.get_policy_warnings_counter.return_value = {
            "policy_warnings_total": 0,
            "identified_files_with_warnings": 0, 
            "dependencies_with_warnings": 0
        }
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is True  # Should PASS when not failing on pending files

    @patch('workbench_cli.handlers.evaluate_gates.wait_for_scan_completion')
    def test_handle_evaluate_gates_policy_data_format_nested(self, mock_wait, mock_workbench, mock_params):
        """Test handling of nested policy data format."""
        mock_params.command = 'evaluate-gates'
        mock_params.project_name = "P"
        mock_params.scan_name = "S"
        mock_params.fail_on_pending = False
        mock_params.fail_on_policy = True
        mock_params.fail_on_vuln_severity = None
        mock_params.show_pending_files = False
        
        # Setup mocks
        mock_workbench.resolve_project.return_value = "PC"
        mock_workbench.resolve_scan.return_value = ("SC", 1)
        mock_wait.return_value = (True, True, {})  # scan completed
        mock_workbench.get_pending_files.return_value = {}
        # Test nested data format
        mock_workbench.get_policy_warnings_counter.return_value = {
            "data": {
                "policy_warnings_total": 3,
                "identified_files_with_warnings": 1, 
                "dependencies_with_warnings": 2
            }
        }
        mock_workbench.list_vulnerabilities.return_value = []

        # Run handler
        result = handle_evaluate_gates(mock_workbench, mock_params)
        assert result is False  # Should FAIL because of nested policy warnings 