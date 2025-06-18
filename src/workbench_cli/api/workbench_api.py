from typing import Dict, List, Optional, Union, Any, Generator, Tuple
import logging
import json
import requests
from .helpers.api_base import APIBase
from .upload_api import UploadAPI
from .helpers.project_scan_resolvers import ResolveWorkbenchProjectScan
from .projects_api import ProjectsAPI
from .scans_api import ScansAPI
from .vulnerabilities_api import VulnerabilitiesAPI
from ..exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)
import json
import requests
import os
import base64
import tempfile
import shutil
import time

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class WorkbenchAPI(UploadAPI, ResolveWorkbenchProjectScan, ProjectsAPI, VulnerabilitiesAPI, ScansAPI):
    """
    Workbench API client class for interacting with the FossID Workbench API.
    This class composes all the individual API parts into a single client.
    """
    pass
