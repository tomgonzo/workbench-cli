"""Test main() function orchestration and exception handling."""

import pytest
from unittest.mock import MagicMock, patch
import os
import sys

# Add src to path  
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from workbench_cli.main import main
from workbench_cli.exceptions import (
    ValidationError, ConfigurationError, AuthenticationError, ApiError,
    NetworkError, ProcessError, ProcessTimeoutError, FileSystemError,
    CompatibilityError, ProjectNotFoundError, ScanNotFoundError
)


class TestMainFunctionSuccess:
    """Test successful main() function execution."""
    
    def test_main_success_with_scan_handler(self, mock_main_dependencies):
        """Test successful main() execution with scan handler."""
        # Setup
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies['handle_scan'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_scan'].assert_called_once()
        mock_main_dependencies['workbench_api'].assert_called_once_with(
            mock_args.api_url, mock_args.api_user, mock_args.api_token
        )
    
    def test_main_success_with_scan_git_handler(self, mock_main_dependencies):
        """Test successful main() execution with scan-git handler."""
        mock_args = MagicMock(command="scan-git", log="INFO")
        mock_main_dependencies['handle_scan_git'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_scan_git'].assert_called_once()
    
    def test_main_success_with_import_da_handler(self, mock_main_dependencies):
        """Test successful main() execution with import-da handler."""
        mock_args = MagicMock(command="import-da", log="INFO")
        mock_main_dependencies['handle_import_da'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_import_da'].assert_called_once()
    
    def test_main_success_with_import_sbom_handler(self, mock_main_dependencies):
        """Test successful main() execution with import-sbom handler."""
        mock_args = MagicMock(command="import-sbom", log="INFO")
        mock_main_dependencies['handle_import_sbom'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_import_sbom'].assert_called_once()
    
    def test_main_success_with_show_results_handler(self, mock_main_dependencies):
        """Test successful main() execution with show-results handler."""
        mock_args = MagicMock(command="show-results", log="INFO")
        mock_args.path_result = None  # Don't trigger save functionality
        mock_main_dependencies['handle_show_results'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_show_results'].assert_called_once()
    
    def test_main_success_with_download_reports_handler(self, mock_main_dependencies):
        """Test successful main() execution with download-reports handler."""
        mock_args = MagicMock(command="download-reports", log="INFO")
        mock_main_dependencies['handle_download_reports'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_download_reports'].assert_called_once()


class TestMainFunctionExceptionHandling:
    """Test main() function exception handling."""
    
    def test_main_validation_error_during_parsing(self):
        """Test main() handling ValidationError during argument parsing."""
        with patch('workbench_cli.main.parse_cmdline_args', side_effect=ValidationError("Test validation error")):
            result = main()
        
        assert result == 1
    
    def test_main_configuration_error_during_api_init(self, mock_main_dependencies):
        """Test main() handling ConfigurationError during API initialization."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies['workbench_api'].side_effect = ConfigurationError("Test config error")
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 1
        # Handler should not be called if API init fails
        mock_main_dependencies['handle_scan'].assert_not_called()
    
    def test_main_authentication_error_during_api_init(self, mock_main_dependencies):
        """Test main() handling AuthenticationError during API initialization."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies['workbench_api'].side_effect = AuthenticationError("Auth error")
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 1
    
    @pytest.mark.parametrize("exception_class,exception_msg", [
        (ApiError, "API error"),
        (NetworkError, "Network error"),
        (ProcessError, "Process error"),
        (ProcessTimeoutError, "Timeout error"),
        (FileSystemError, "FS error"),
        (CompatibilityError, "Compatibility error"),
        (ProjectNotFoundError, "Project not found"),
        (ScanNotFoundError, "Scan not found"),
    ])
    def test_main_specific_exception_handling(self, mock_main_dependencies, exception_class, exception_msg):
        """Test main() handling of specific exception types."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies['handle_scan'].side_effect = exception_class(exception_msg)
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 1
        mock_main_dependencies['handle_scan'].assert_called_once()
    
    def test_main_unexpected_exception_handling(self, mock_main_dependencies):
        """Test main() handling of unexpected exceptions."""
        mock_args = MagicMock(command="scan", log="INFO")
        mock_main_dependencies['handle_scan'].side_effect = Exception("Unexpected error")
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 1
        mock_main_dependencies['handle_scan'].assert_called_once()


class TestEvaluateGatesSpecialHandling:
    """Test special handling for evaluate-gates command."""
    
    def test_evaluate_gates_success_returns_0(self, mock_main_dependencies):
        """Test that evaluate-gates returning True results in exit code 0."""
        mock_args = MagicMock(command="evaluate-gates", log="INFO")  
        mock_main_dependencies['handle_evaluate_gates'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0
        mock_main_dependencies['handle_evaluate_gates'].assert_called_once()
    
    def test_evaluate_gates_failure_returns_1(self, mock_main_dependencies):
        """Test that evaluate-gates returning False results in exit code 1."""
        mock_args = MagicMock(command="evaluate-gates", log="INFO")
        mock_main_dependencies['handle_evaluate_gates'].return_value = False
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 1
        mock_main_dependencies['handle_evaluate_gates'].assert_called_once()


class TestHandlerReturnValues:
    """Test how main() handles different handler return values."""
    
    @pytest.mark.parametrize("command,handler_name", [
        ("scan", "handle_scan"),
        ("scan-git", "handle_scan_git"), 
        ("import-da", "handle_import_da"),
        ("show-results", "handle_show_results"),
        ("download-reports", "handle_download_reports"),
    ])
    def test_non_evaluate_gates_handlers_ignore_return_value(self, mock_main_dependencies, command, handler_name):
        """Test that non-evaluate-gates handlers' return values don't affect exit code."""
        mock_args = MagicMock(command=command, log="INFO")
        mock_main_dependencies[handler_name].return_value = False  # Simulate "failure"
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        # Should still return 0 since no exception was raised
        assert result == 0
        mock_main_dependencies[handler_name].assert_called_once()


class TestLoggingConfiguration:
    """Test logging configuration in main()."""
    
    def test_main_handles_log_level(self, mock_main_dependencies):
        """Test that main() handles different log levels without error."""
        mock_args = MagicMock(command="scan", log="DEBUG")
        mock_main_dependencies['handle_scan'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        assert result == 0


class TestMainIntegration:
    """Integration tests for main() function behavior."""
    
    def test_main_full_success_flow(self, mock_main_dependencies):
        """Test complete successful flow through main()."""
        # Setup a realistic args object
        mock_args = MagicMock()
        mock_args.command = "scan"
        mock_args.log = "INFO"
        mock_args.api_url = "https://test.com/api.php"
        mock_args.api_user = "testuser"
        mock_args.api_token = "testtoken"
        
        mock_main_dependencies['handle_scan'].return_value = True
        
        with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
            result = main()
        
        # Verify the complete flow
        assert result == 0
        mock_main_dependencies['workbench_api'].assert_called_once_with(
            "https://test.com/api.php", "testuser", "testtoken"
        )
        mock_main_dependencies['handle_scan'].assert_called_once_with(
            mock_main_dependencies['workbench_instance'], mock_args
        )
    
    def test_main_handles_system_exit_during_parsing(self):
        """Test that main() handles SystemExit from argparse gracefully."""
        # SystemExit from argparse (e.g., --help, invalid args) should not be caught
        with patch('workbench_cli.main.parse_cmdline_args', side_effect=SystemExit(2)):
            with pytest.raises(SystemExit):
                main()
    
    def test_main_command_dispatch_logic(self, mock_main_dependencies):
        """Test that main() correctly dispatches to the right handler based on command."""
        command_handler_mapping = [
            ("scan", "handle_scan"),
            ("scan-git", "handle_scan_git"),
            ("import-da", "handle_import_da"),
            ("show-results", "handle_show_results"),
            ("download-reports", "handle_download_reports"),
            ("evaluate-gates", "handle_evaluate_gates"),
        ]
        
        for command, expected_handler in command_handler_mapping:
            # Reset all mocks
            for handler in mock_main_dependencies.values():
                if hasattr(handler, 'reset_mock'):
                    handler.reset_mock()
            
            mock_args = MagicMock(command=command, log="INFO")
            mock_main_dependencies[expected_handler].return_value = True
            
            with patch("workbench_cli.main.parse_cmdline_args", return_value=mock_args):
                result = main()
            
            assert result == 0
            mock_main_dependencies[expected_handler].assert_called_once()
            
            # Verify other handlers were not called
            for handler_name, handler_mock in mock_main_dependencies.items():
                if handler_name != expected_handler and handler_name not in ['workbench_api', 'workbench_instance']:
                    if hasattr(handler_mock, 'assert_not_called'):
                        handler_mock.assert_not_called() 