from typing import Dict, Any

import logging

from ..exceptions import ApiError
from .helpers.api_base import APIBase
from .helpers.component_info_normalizer import normalize_component_response

logger = logging.getLogger("workbench-cli")


class ComponentsAPI(APIBase):
    """Workbench API Component Operations."""

    def get_component_information(self, component_name: str, component_version: str) -> Dict[str, Any]:
        """Retrieve component metadata from Workbench.

        Args:
            component_name: The component or package name (e.g. "ansi-regex").
            component_version: The component version (e.g. "1.1.1").

        Returns:
            Dictionary with the component information as returned by the API.

        Raises:
            ApiError: If the component does not exist or the API request fails.
        """
        logger.debug(
            "Fetching information for component '%s' version '%s'...",
            component_name,
            component_version,
        )

        payload = {
            "group": "components",
            "action": "get_information",
            "data": {
                "component_name": component_name,
                "component_version": component_version,
            },
        }

        response = self._send_request(payload)

        # Successful response
        if response.get("status") == "1" and "data" in response:
            return normalize_component_response(response["data"])

        # Something went wrong – build a helpful error message
        error_msg = response.get("error", f"Unexpected response: {response}")
        raise ApiError(
            f"Failed to fetch information for component '{component_name}' version '{component_version}': {error_msg}",
            details=response,
        )
