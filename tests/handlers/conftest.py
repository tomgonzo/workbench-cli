# tests/handlers/conftest.py

import pytest
import os
from unittest.mock import MagicMock, patch, Mock, call
import argparse

# Import dependencies needed for fixtures
from workbench_cli.api import WorkbenchAPI

# Add a fallback mocker fixture for environments where pytest-mock is not installed
try:
    from pytest_mock import mocker
except ImportError:
    class SimpleMocker:
        def MagicMock(self, *args, **kwargs):
            return MagicMock(*args, **kwargs)
        
        def patch(self, *args, **kwargs):
            return patch(*args, **kwargs)
        
    @pytest.fixture
    def mocker():
        return SimpleMocker()

# Fixture for mock Workbench instance
@pytest.fixture
def mock_workbench(mocker):
    """Provides a mocked WorkbenchAPI instance for handler tests."""
    # Mock methods used across handlers
    mock = mocker.MagicMock(spec=WorkbenchAPI)
    mock.assert_process_can_start = mocker.MagicMock()
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
    """Provides a mocked argparse.Namespace for handler tests."""
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Set common parameters used across handlers
    params.api_url = "http://localhost/api.php"
    params.api_user = "test_user"
    params.api_token = "test_token"
    params.verbose = False
    params.log = "INFO"
    
    # Set scan parameters (used in scan handler tests)
    params.scan_number_of_tries = 30
    params.scan_wait_time = 5
    params.output_format = "text"
    
    return params

