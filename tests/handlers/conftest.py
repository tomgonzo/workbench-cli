# tests/handlers/conftest.py

import pytest
from unittest.mock import MagicMock, patch, Mock, call
import argparse

# Import dependencies needed for fixtures
from workbench_agent.api import Workbench

# Add a fallback mocker fixture for environments where pytest-mock is not installed
try:
    import pytest_mock
except ImportError:
    @pytest.fixture
    def mocker():
        """Provides a simple mock factory when pytest-mock is not available."""
        class SimpleMocker:
            def MagicMock(self, *args, **kwargs):
                return MagicMock(*args, **kwargs)
            
            def Mock(self, *args, **kwargs):
                return Mock(*args, **kwargs)
                
            def patch(self, *args, **kwargs):
                return patch(*args, **kwargs)
                
            def spy(self, obj, name):
                original = getattr(obj, name)
                mock = MagicMock(wraps=original)
                setattr(obj, name, mock)
                return mock
                
            def patch_object(self, target, attribute, *args, **kwargs):
                return patch.object(target, attribute, *args, **kwargs)
                
            def patch_multiple(self, target, **kwargs):
                return patch.multiple(target, **kwargs)
                
            def call(self, *args, **kwargs):
                return call(*args, **kwargs)
                
            def ANY(self):
                from unittest.mock import ANY
                return ANY
        
        return SimpleMocker()

# Fixture for mock Workbench instance
@pytest.fixture
def mock_workbench(mocker):
    """Provides a mocked Workbench instance for handler tests."""
    # Mock methods used across handlers
    mock = mocker.MagicMock(spec=Workbench)
    mock._is_status_check_supported.return_value = True # Assume supported by default
    mock.list_projects.return_value = [
        {"name": "test_project", "code": "TEST_PROJECT"}
    ]
    mock.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    # Add other commonly mocked methods if needed across multiple handlers
    return mock

# Fixture for mock params object (parsed arguments)
@pytest.fixture
def mock_params(mocker):
    """Provides a mocked argparse.Namespace object for handler tests."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Set common attributes needed by handlers
    params.api_url = "http://dummy.com/api.php"
    params.scan_number_of_tries = 10
    params.scan_wait_time = 1
    # Set defaults for flags often checked
    params.show_licenses = False
    params.show_components = False
    params.show_policy_warnings = False
    params.path_result = None
    params.policy_check = False
    params.show_files = False
    # Set default command-specific attributes (can be overridden in tests)
    params.command = None # Set specifically in tests needing it
    params.project_name = "test_project"
    params.scan_name = "test_scan"
    params.path = "/path/to/files"
    # Add other common params defaults
    params.report_scope = 'scan'
    params.report_type = 'ALL'
    params.report_save_path = '.'
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.recursively_extract_archives = False
    params.jar_file_extraction = False
    return params

