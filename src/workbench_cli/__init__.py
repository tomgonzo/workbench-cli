# workbench_cli/__init__.py
"""
FossID Workbench CLI package
"""

# Re-export API for backwards compatibility
from .api import WorkbenchAPI

# For backward compatibility, we'll still expose the API class under the original name
Workbench = WorkbenchAPI

__all__ = ['WorkbenchAPI', 'Workbench']

# This file marks the directory as a Python package.