# tests/unit/handlers/test_export_sarif.py

import pytest
import argparse
from unittest.mock import Mock, patch, MagicMock
import json
import tempfile
import os

from workbench_cli.handlers.export_sarif import handle_export_sarif
from workbench_cli.exceptions import (
    ApiError,
    NetworkError,
    ProcessError,
    ProjectNotFoundError,
    ScanNotFoundError
)


class TestExportSarif:
    """Test cases for the export-sarif handler."""

    @pytest.fixture
    def mock_workbench(self):
        """Create a mock Workbench API client."""
        workbench = Mock()
        workbench.resolve_project.return_value = "TEST_PROJECT_123"
        workbench.resolve_scan.return_value = ("TEST_SCAN_456", 456)
        workbench.ensure_scan_is_idle.return_value = None
        workbench.list_vulnerabilities.return_value = [
            {
                "id": 1,
                "cve": "CVE-2023-1234",
                "severity": "HIGH",
                "base_score": "7.5",
                "component_name": "test-component",
                "component_version": "1.0.0",
                "vuln_exp_id": None
            },
            {
                "id": 2,
                "cve": "CVE-2023-5678",
                "severity": "MEDIUM",
                "base_score": "5.0",
                "component_name": "another-component",
                "component_version": "2.0.0",
                "vuln_exp_id": 123
            }
        ]
        return workbench

    @pytest.fixture
    def mock_params(self):
        """Create mock command line parameters."""
        params = argparse.Namespace()
        params.command = "export-sarif"
        params.project_name = "TestProject"
        params.scan_name = "TestScan"
        params.output = "test_output.sarif"
        params.include_vex = True
        params.severity_threshold = None
        params.include_scan_metadata = True
        params.enrich_nvd = True
        params.enrich_epss = True
        params.enrich_cisa_kev = True
        params.external_timeout = 30
        params.skip_enrichment = False
        params.suppress_vex_mitigated = True
        params.suppress_accepted_risk = True
        params.suppress_false_positives = True
        params.group_by_component = True
        params.quiet = False
        params.validate = False
        params.scan_number_of_tries = 960
        params.scan_wait_time = 30
        return params

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_successful_export(self, mock_save_sarif, mock_workbench, mock_params):
        """Test successful SARIF export with vulnerabilities."""
        # Execute the handler
        result = handle_export_sarif(mock_workbench, mock_params)
        
        # Verify result
        assert result is True
        
        # Verify API calls
        mock_workbench.resolve_project.assert_called_once_with("TestProject", create_if_missing=False)
        mock_workbench.resolve_scan.assert_called_once_with(
            scan_name="TestScan",
            project_name="TestProject", 
            create_if_missing=False,
            params=mock_params
        )
        mock_workbench.ensure_scan_is_idle.assert_called_once_with("TEST_SCAN_456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
        mock_workbench.list_vulnerabilities.assert_called_once_with("TEST_SCAN_456")
        
        # Verify SARIF export
        mock_save_sarif.assert_called_once_with(
            filepath="test_output.sarif",
            vulnerabilities=mock_workbench.list_vulnerabilities.return_value,
            scan_code="TEST_SCAN_456",
            include_cve_descriptions=True,
            include_epss_scores=True,
            include_exploit_info=True,
            api_timeout=30,
            include_vex=True,
            include_scan_metadata=True,
            suppress_vex_mitigated=True,
            suppress_accepted_risk=True,
            suppress_false_positives=True,
            group_by_component=True,
            quiet=False
        )

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_export_with_no_vulnerabilities(self, mock_save_sarif, mock_workbench, mock_params):
        """Test SARIF export when no vulnerabilities are found."""
        # Setup
        mock_workbench.list_vulnerabilities.return_value = []
        
        # Execute
        result = handle_export_sarif(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        mock_save_sarif.assert_called_once_with(
            filepath="test_output.sarif",
            vulnerabilities=[],
            scan_code="TEST_SCAN_456",
            include_cve_descriptions=True,
            include_epss_scores=True,
            include_exploit_info=True,
            api_timeout=30,
            include_vex=True,
            include_scan_metadata=True,
            suppress_vex_mitigated=True,
            suppress_accepted_risk=True,
            suppress_false_positives=True,
            group_by_component=True,
            quiet=False
        )

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_export_with_custom_options(self, mock_save_sarif, mock_workbench, mock_params):
        """Test SARIF export with custom enrichment options."""
        # Modify params
        mock_params.enrich_nvd = False
        mock_params.enrich_epss = False
        mock_params.enrich_cisa_kev = False
        mock_params.external_timeout = 60
        mock_params.output = "custom_output.sarif"
        
        # Execute
        result = handle_export_sarif(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        mock_save_sarif.assert_called_once_with(
            filepath="custom_output.sarif",
            vulnerabilities=mock_workbench.list_vulnerabilities.return_value,
            scan_code="TEST_SCAN_456",
            include_cve_descriptions=False,
            include_epss_scores=False,
            include_exploit_info=False,
            api_timeout=60,
            include_vex=True,
            include_scan_metadata=True,
            suppress_vex_mitigated=True,
            suppress_accepted_risk=True,
            suppress_false_positives=True,
            group_by_component=True,
            quiet=False
        )

    def test_project_not_found_error(self, mock_workbench, mock_params):
        """Test handling of project not found error."""
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")
        
        with pytest.raises(ProjectNotFoundError):
            handle_export_sarif(mock_workbench, mock_params)

    def test_scan_not_found_error(self, mock_workbench, mock_params):
        """Test handling of scan not found error."""
        mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
        
        with pytest.raises(ScanNotFoundError):
            handle_export_sarif(mock_workbench, mock_params)

    def test_api_error_during_fetch(self, mock_workbench, mock_params):
        """Test handling of API error during vulnerability fetch."""
        mock_workbench.list_vulnerabilities.side_effect = ApiError("API Error")
        
        with pytest.raises(ApiError):
            handle_export_sarif(mock_workbench, mock_params)

    def test_network_error_during_fetch(self, mock_workbench, mock_params):
        """Test handling of network error during vulnerability fetch."""
        mock_workbench.list_vulnerabilities.side_effect = NetworkError("Network Error")
        
        with pytest.raises(NetworkError):
            handle_export_sarif(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_generic_error_during_export(self, mock_save_sarif, mock_workbench, mock_params):
        """Test handling of generic error during SARIF export."""
        mock_save_sarif.side_effect = Exception("Generic export error")
        
        with pytest.raises(ProcessError) as exc_info:
            handle_export_sarif(mock_workbench, mock_params)
        
        assert "Failed to export vulnerability data to SARIF format" in str(exc_info.value)

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_vulnerability_summary_display(self, mock_save_sarif, mock_workbench, mock_params, capsys):
        """Test that vulnerability summary is properly displayed."""
        # Setup vulnerabilities with different severities and VEX status
        mock_workbench.list_vulnerabilities.return_value = [
            {"id": 1, "cve": "CVE-2023-1", "severity": "HIGH", "vuln_exp_id": None},
            {"id": 2, "cve": "CVE-2023-2", "severity": "HIGH", "vuln_exp_id": 123},
            {"id": 3, "cve": "CVE-2023-3", "severity": "MEDIUM", "vuln_exp_id": None},
            {"id": 4, "cve": "CVE-2023-4", "severity": "LOW", "vuln_exp_id": 456}
        ]
        
        # Execute
        result = handle_export_sarif(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        captured = capsys.readouterr()
        assert "Found 4 vulnerabilities to export" in captured.out
        assert "HIGH: 2" in captured.out
        assert "MEDIUM: 1" in captured.out
        assert "LOW: 1" in captured.out
        assert "With VEX assessments: 2" in captured.out
        assert "Without VEX assessments: 2" in captured.out

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_configuration_display(self, mock_save_sarif, mock_workbench, mock_params, capsys):
        """Test that export configuration is properly displayed."""
        # Execute
        result = handle_export_sarif(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        captured = capsys.readouterr()
        assert "SARIF Export Configuration:" in captured.out
        assert "Output file: test_output.sarif" in captured.out
        assert "Include CVE descriptions: True" in captured.out
        assert "Include EPSS scores: True" in captured.out
        assert "Include exploit information: True" in captured.out
        assert "Apply VEX suppression: True" in captured.out
        assert "API timeout: 30s" in captured.out

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_integration_tips_display(self, mock_save_sarif, mock_workbench, mock_params, capsys):
        """Test that integration tips are displayed after successful export."""
        # Execute
        result = handle_export_sarif(mock_workbench, mock_params)
        
        # Verify
        assert result is True
        captured = capsys.readouterr()
        assert "Integration Tips:" in captured.out
        assert "Upload to GitHub" in captured.out
        assert "CI/CD Integration" in captured.out
        assert "Security Tools" in captured.out

    @patch('workbench_cli.handlers.export_sarif.save_vulns_to_sarif')
    def test_default_output_file(self, mock_save_sarif, mock_workbench):
        """Test that default output file is used when not specified."""
        # Create params without output specified
        params = argparse.Namespace()
        params.command = "export-sarif"
        params.project_name = "TestProject"
        params.scan_name = "TestScan"
        params.output = "vulns.sarif"  # This would be the default from CLI
        params.include_vex = True
        params.severity_threshold = None
        params.include_scan_metadata = True
        params.enrich_nvd = True
        params.enrich_epss = True
        params.enrich_cisa_kev = True
        params.external_timeout = 30
        params.skip_enrichment = False
        params.suppress_vex_mitigated = True
        params.suppress_accepted_risk = True
        params.suppress_false_positives = True
        params.group_by_component = True
        params.quiet = False
        params.validate = False
        params.scan_number_of_tries = 960
        params.scan_wait_time = 30
        
        # Execute
        result = handle_export_sarif(mock_workbench, params)
        
        # Verify
        assert result is True
        mock_save_sarif.assert_called_once()
        # Check that filepath was passed correctly
        mock_save_sarif.assert_called_with(
            filepath="vulns.sarif",
            vulnerabilities=mock_workbench.list_vulnerabilities.return_value,
            scan_code="TEST_SCAN_456",
            include_cve_descriptions=True,
            include_epss_scores=True,
            include_exploit_info=True,
            api_timeout=30,
            include_vex=True,
            include_scan_metadata=True,
            suppress_vex_mitigated=True,
            suppress_accepted_risk=True,
            suppress_false_positives=True,
            group_by_component=True,
            quiet=False
        ) 