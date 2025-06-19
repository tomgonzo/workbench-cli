"""Test argument validation logic."""

import pytest
from unittest.mock import patch
import os
import sys
import re

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from workbench_cli.cli import parse_cmdline_args
from workbench_cli.exceptions import ValidationError


class TestValidationRules:
    """Test argument validation rules."""
    
    def test_id_reuse_missing_source_project(self, args, arg_parser, mock_path_exists):
        """Test validation when ID reuse source is missing for project type."""
        cmd_args = (args()
                   .scan()
                   .id_reuse(reuse_type='project', source=None)  # Missing source
                   .build())
        
        with pytest.raises(ValidationError, match="ID reuse source project/scan name is required"):
            arg_parser(cmd_args)
    
    def test_id_reuse_missing_source_scan(self, args, arg_parser, mock_path_exists):
        """Test validation when ID reuse source is missing for scan type."""
        cmd_args = (args()
                   .scan()
                   .id_reuse(reuse_type='scan', source=None)  # Missing source
                   .build())
        
        with pytest.raises(ValidationError, match="ID reuse source project/scan name is required"):
            arg_parser(cmd_args)
    
    def test_download_reports_missing_project_for_project_scope(self, args, arg_parser):
        """Test validation when project name is missing for project scope reports."""
        cmd_args = (args()
                   .download_reports(scope='project')
                   # Missing project_name
                   .build())
        
        with pytest.raises(ValidationError, match="Project name is required for project scope report"):
            arg_parser(cmd_args)
    
    def test_download_reports_missing_scan_for_scan_scope(self, args, arg_parser):
        """Test validation when scan name is missing for scan scope reports."""
        cmd_args = (args()
                   .download_reports(scope='scan')
                   # Missing scan_name
                   .build())
        
        with pytest.raises(ValidationError, match="Scan name is required for scan scope report"):
            arg_parser(cmd_args)
    
    def test_show_results_missing_show_flags(self, args, arg_parser):
        """Test validation when no show flags are provided for show-results."""
        cmd_args = (args()
                   .show_results(project='P', scan='S')
                   # No show flags added
                   .build())
        
        with pytest.raises(ValidationError, match=re.escape("At least one '--show-*' flag must be provided")):
            arg_parser(cmd_args)
    
    def test_scan_non_existent_path(self, args, arg_parser):
        """Test validation when scan path doesn't exist."""
        with patch('os.path.exists', return_value=False):
            cmd_args = args().scan(path='/non/existent/path').build()
            
            with pytest.raises(ValidationError, match=re.escape("Path does not exist: /non/existent/path")):
                arg_parser(cmd_args)
    
    def test_import_da_non_existent_path(self, args, arg_parser):
        """Test validation when import-da path doesn't exist."""
        with patch('os.path.exists', return_value=False):
            cmd_args = args().import_da(path='/non/existent/file.json').build()
            
            with pytest.raises(ValidationError, match=re.escape("Path does not exist: /non/existent/file.json")):
                arg_parser(cmd_args)


class TestArgparseValidation:
    """Test validation handled by argparse itself (results in SystemExit)."""
    
    def test_scan_git_branch_and_tag_conflict(self, args, arg_parser):
        """Test that specifying both branch and tag raises SystemExit."""
        cmd_args = (args()
                   .scan_git()
                   .git_branch('main')
                   .git_tag('v1.0')  # Conflicting with branch
                   .build())
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_scan_git_branch_and_commit_conflict(self, args, arg_parser):
        """Test that specifying both branch and commit raises SystemExit."""
        cmd_args = (args()
                   .scan_git()
                   .git_branch('main')
                   .git_commit('abc123')  # Conflicting with branch
                   .build())
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_scan_git_tag_and_commit_conflict(self, args, arg_parser):
        """Test that specifying both tag and commit raises SystemExit."""
        cmd_args = (args()
                   .scan_git()
                   .git_tag('v1.0')
                   .git_commit('abc123')  # Conflicting with tag
                   .build())
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_scan_git_missing_reference(self, args, arg_parser):
        """Test that scan-git without branch/tag/commit raises SystemExit."""
        cmd_args = (args()
                   .scan_git()
                   # No git reference specified
                   .build())
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_missing_credentials_raises_system_exit(self, arg_parser, mock_path_exists):
        """Test that missing credentials raise SystemExit."""
        with patch.dict(os.environ, {"WORKBENCH_URL": "", "WORKBENCH_USER": "", "WORKBENCH_TOKEN": ""}, clear=True):
            cmd_args = ['workbench-cli', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.']
            
            with pytest.raises(SystemExit):
                arg_parser(cmd_args)
    
    def test_no_command_raises_system_exit(self, arg_parser):
        """Test that missing command raises SystemExit."""
        cmd_args = ['workbench-cli', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z']
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_scan_missing_path_raises_system_exit(self, arg_parser):
        """Test that scan without path raises SystemExit."""
        cmd_args = ['workbench-cli', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 
                   'scan', '--project-name', 'P', '--scan-name', 'S']
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_scan_git_missing_url_raises_system_exit(self, arg_parser):
        """Test that scan-git without URL raises SystemExit."""
        cmd_args = ['workbench-cli', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 
                   'scan-git', '--project-name', 'P', '--scan-name', 'S', '--git-branch', 'main']
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_import_da_missing_path_raises_system_exit(self, arg_parser):
        """Test that import-da without path raises SystemExit."""
        cmd_args = ['workbench-cli', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 
                   'import-da', '--project-name', 'P', '--scan-name', 'S']
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)
    
    def test_unknown_command_raises_system_exit(self, arg_parser):
        """Test that unknown command raises SystemExit."""
        cmd_args = ['workbench-cli', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'unknown-command']
        
        with pytest.raises(SystemExit):
            arg_parser(cmd_args)


class TestValidationLogic:
    """Test custom validation logic behavior."""
    
    def test_id_reuse_source_ignored_for_any_type(self, args, arg_parser, mock_path_exists):
        """Test that ID reuse source is ignored for 'any' type."""
        cmd_args = (args()
                   .scan()
                   .id_reuse(reuse_type='any', source='UnneededSource')
                   .build())
        
        parsed = arg_parser(cmd_args)
        
        assert parsed.id_reuse is True
        assert parsed.id_reuse_type == 'any'
        assert parsed.id_reuse_source is None  # Should be ignored
    
    def test_id_reuse_source_ignored_for_only_me_type(self, args, arg_parser, mock_path_exists):
        """Test that ID reuse source is ignored for 'only_me' type."""
        cmd_args = (args()
                   .scan()
                   .id_reuse(reuse_type='only_me', source='UnneededSource')
                   .build())
        
        parsed = arg_parser(cmd_args)
        
        assert parsed.id_reuse is True
        assert parsed.id_reuse_type == 'only_me'
        assert parsed.id_reuse_source is None  # Should be ignored


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_environment_variables(self, arg_parser, mock_path_exists):
        """Test behavior with empty environment variables."""
        env_vars = {"WORKBENCH_URL": "", "WORKBENCH_USER": "", "WORKBENCH_TOKEN": ""}
        
        with patch.dict(os.environ, env_vars, clear=True):
            # Should require command-line credentials
            cmd_args = ['workbench-cli', '--api-url', 'https://test.com', '--api-user', 'user', 
                       '--api-token', 'token', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.']
            
            parsed = arg_parser(cmd_args)
            assert parsed.api_url == 'https://test.com/api.php'
            assert parsed.api_user == 'user'
            assert parsed.api_token == 'token'
    
    def test_partial_environment_variables(self, arg_parser, mock_path_exists):
        """Test behavior with partial environment variables."""
        env_vars = {"WORKBENCH_URL": "https://env.com", "WORKBENCH_USER": "", "WORKBENCH_TOKEN": ""}
        
        with patch.dict(os.environ, env_vars, clear=True):
            # Should still require missing credentials via command line
            cmd_args = ['workbench-cli', '--api-user', 'cmduser', '--api-token', 'cmdtoken',
                       'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.']
            
            parsed = arg_parser(cmd_args)
            assert parsed.api_url == 'https://env.com/api.php'  # From env
            assert parsed.api_user == 'cmduser'  # From command line
            assert parsed.api_token == 'cmdtoken'  # From command line 