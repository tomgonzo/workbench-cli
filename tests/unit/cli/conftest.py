import pytest
from unittest.mock import MagicMock, patch
import argparse
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from workbench_cli.cli import parse_cmdline_args


@pytest.fixture
def mock_path_exists():
    """Mock os.path.exists to return True by default."""
    with patch('os.path.exists', return_value=True) as mock:
        yield mock


@pytest.fixture  
def base_args():
    """Base argument list with required credentials."""
    return [
        'workbench-cli', 
        '--api-url', 'https://test.com',
        '--api-user', 'testuser', 
        '--api-token', 'testtoken'
    ]


@pytest.fixture
def arg_parser():
    """Create a fresh argument parser for each test."""
    def _create_parser_with_args(args_list):
        """Parse arguments without affecting sys.argv."""
        # Import inside function to avoid import order issues
        from workbench_cli.cli import parse_cmdline_args
        with patch('sys.argv', args_list):
            return parse_cmdline_args()
    return _create_parser_with_args


@pytest.fixture
def mock_main_dependencies():
    """Mock all main() function dependencies."""
    mocks = {}
    
    # Mock WorkbenchAPI
    with patch("workbench_cli.main.WorkbenchAPI") as mock_wb:
        mocks['workbench_api'] = mock_wb
        mocks['workbench_instance'] = MagicMock()
        mock_wb.return_value = mocks['workbench_instance']
        
        # Set up common API methods that handlers might use
        mocks['workbench_instance'].resolve_project.return_value = "TEST_PROJECT_CODE"
        mocks['workbench_instance'].resolve_scan.return_value = ("TEST_SCAN_CODE", 123)
        mocks['workbench_instance'].ensure_scan_is_idle.return_value = None
        
        # Set up API methods that return empty/simple data to avoid JSON serialization issues
        mocks['workbench_instance'].get_scan_folder_metrics.return_value = {}
        mocks['workbench_instance'].get_dependency_analysis_results.return_value = []
        mocks['workbench_instance'].get_scan_identified_licenses.return_value = []
        mocks['workbench_instance'].get_scan_identified_components.return_value = []
        mocks['workbench_instance'].get_policy_warnings_counter.return_value = {}
        mocks['workbench_instance'].list_vulnerabilities.return_value = []
        
        # Mock all handlers - need to patch them at the main module level where they're imported
        with patch("workbench_cli.main.handle_scan") as mock_scan, \
             patch("workbench_cli.main.handle_scan_git") as mock_scan_git, \
             patch("workbench_cli.main.handle_import_da") as mock_import, \
             patch("workbench_cli.main.handle_import_sbom") as mock_import_sbom, \
             patch("workbench_cli.main.handle_show_results") as mock_show, \
             patch("workbench_cli.main.handle_download_reports") as mock_download, \
             patch("workbench_cli.main.handle_evaluate_gates") as mock_gates:
            
            mocks['handle_scan'] = mock_scan
            mocks['handle_scan_git'] = mock_scan_git
            mocks['handle_import_da'] = mock_import
            mocks['handle_import_sbom'] = mock_import_sbom
            mocks['handle_show_results'] = mock_show
            mocks['handle_download_reports'] = mock_download
            mocks['handle_evaluate_gates'] = mock_gates
            
            yield mocks


class ArgBuilder:
    """Builder pattern for constructing test arguments."""
    
    def __init__(self):
        self.args = [
            'workbench-cli',
            '--api-url', 'https://test.com', 
            '--api-user', 'testuser',
            '--api-token', 'testtoken'
        ]
    
    def scan(self, project='TestProject', scan='TestScan', path='.'):
        self.args.extend(['scan', '--project-name', project, '--scan-name', scan, '--path', path])
        return self
    
    def scan_git(self, project='TestProject', scan='TestScan', git_url='https://git.com/repo.git'):
        self.args.extend(['scan-git', '--project-name', project, '--scan-name', scan, '--git-url', git_url])
        return self
        
    def git_branch(self, branch='main'):
        self.args.extend(['--git-branch', branch])
        return self
        
    def git_tag(self, tag='v1.0'):
        self.args.extend(['--git-tag', tag])
        return self
        
    def git_commit(self, commit='abc123'):
        self.args.extend(['--git-commit', commit])
        return self
    
    def import_da(self, project='TestProject', scan='TestScan', path='results.json'):
        self.args.extend(['import-da', '--project-name', project, '--scan-name', scan, '--path', path])
        return self
    
    def import_sbom(self, project='TestProject', scan='TestScan', path='bom.json'):
        self.args.extend(['import-sbom', '--project-name', project, '--scan-name', scan, '--path', path])
        return self
    
    def download_reports(self, scope='scan'):
        self.args.extend(['download-reports', '--report-scope', scope])
        return self
        
    def project_name(self, name):
        self.args.extend(['--project-name', name])
        return self
        
    def scan_name(self, name):
        self.args.extend(['--scan-name', name])
        return self
    
    def show_results(self, project='TestProject', scan='TestScan'):
        self.args.extend(['show-results', '--project-name', project, '--scan-name', scan])
        return self
        
    def show_licenses(self):
        self.args.append('--show-licenses')
        return self
    
    def id_reuse(self, reuse_type='any', source=None):
        self.args.extend(['--id-reuse', '--id-reuse-type', reuse_type])
        if source:
            self.args.extend(['--id-reuse-source', source])
        return self
    
    def log_level(self, level='INFO'):
        self.args.extend(['--log', level])
        return self
    
    def build(self):
        return self.args.copy()


@pytest.fixture
def args():
    """Fixture providing the ArgBuilder for constructing test arguments."""
    return ArgBuilder 