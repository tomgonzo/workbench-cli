# tests/integration/conftest.py

import pytest
import requests
import json
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_api_post(mocker):
    """
    Fixture to mock requests.Session.post calls made by the Workbench API client.

    Yields a setup function that tests can use to define the sequence of
    expected responses for their specific flow.
    """
    expected_responses = []
    call_log = [] # Optional: Log calls for debugging

    def setup_responses(responses):
        """Sets the sequence of mock responses for the test."""
        expected_responses.clear()
        expected_responses.extend(responses)
        call_log.clear()

    def mock_post_side_effect(*args, **kwargs):
        """The side effect function for the mocked requests.Session.post."""
        if not expected_responses:
            pytest.fail(f"Unexpected API call made! Args: {args}, Kwargs: {kwargs}")

        response_config = expected_responses.pop(0)
        request_payload = kwargs.get('data', {})
        call_log.append({"request": request_payload, "response_config": response_config}) # Log call

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = response_config.get("status_code", 200)
        mock_response.request = MagicMock(body=json.dumps(request_payload) if request_payload else None) # Mock request body if needed

        headers = response_config.get("headers", {'content-type': 'application/json'})
        mock_response.headers = headers

        if headers.get('content-type') == 'application/json':
            json_data = response_config.get("json_data", {"status": "1", "data": {}}) # Default success
            mock_response.json = MagicMock(return_value=json_data)
            # Simulate text attribute for JSON responses if needed by code under test
            mock_response.text = json.dumps(json_data)
            mock_response.content = mock_response.text.encode('utf-8')
        else:
            # Handle non-JSON content (e.g., reports)
            content_data = response_config.get("content", b"")
            mock_response.content = content_data
            mock_response.text = content_data.decode('utf-8', errors='ignore')
            # Make .json() raise an error if called on non-json content
            mock_response.json.side_effect = requests.exceptions.JSONDecodeError("Not JSON", "", 0)

        # Simulate raise_for_status
        if 400 <= mock_response.status_code < 600:
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
                f"{mock_response.status_code} Client/Server Error", response=mock_response
            )
        else:
            mock_response.raise_for_status = MagicMock()

        return mock_response

    # Patch requests.Session.post globally for the test using this fixture
    # Note: Adjust the target if your Workbench class creates its own Session differently
    patcher = patch('requests.Session.post', side_effect=mock_post_side_effect)
    mock_post = patcher.start()

    yield setup_responses  # Provide the setup function to the test

    patcher.stop() # Stop the patch after the test finishes
    # Optional: Check if all expected responses were consumed
    if expected_responses:
        print("\nWarning: Not all expected API responses were consumed.")
        print("Remaining responses:", expected_responses)
        print("Call log:", call_log)

