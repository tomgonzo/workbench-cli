from typing import Dict, List, Optional, Union, Any, Tuple
import logging
import time
import argparse
from .api_base import APIBase
from ...exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ConfigurationError,
    ValidationError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")


class ResolveWorkbenchProjectScan(APIBase):
    """
    Workbench API Scan Target Resolution Operations - handles resolving project names to codes
    and scan names to codes/IDs, with optional creation functionality.
    """

    def resolve_project(self, project_name: str, create_if_missing: bool = False) -> str:
        """Find a project by name, optionally creating it if not found."""
        # Look for existing project
        projects = self.list_projects()
        project = next((p for p in projects if p.get("project_name") == project_name), None)
        
        if project:
            return project["project_code"]
            
        # Create if requested
        if create_if_missing:
            print(f"Creating project '{project_name}'...")
            try:
                return self.create_project(project_name)
            except ProjectExistsError:
                # Handle race condition
                projects = self.list_projects()
                project = next((p for p in projects if p.get("project_name") == project_name), None)
                if project:
                    return project["project_code"]
                raise ApiError(f"Failed to resolve project '{project_name}' after creation conflict")
                
        raise ProjectNotFoundError(f"Project '{project_name}' not found")

    def resolve_scan(self, scan_name: str, project_name: Optional[str], create_if_missing: bool, params: argparse.Namespace) -> Tuple[str, int]:
        """Find a scan by name, optionally creating it if not found."""
        if project_name:
            # Look in specific project
            project_code = self.resolve_project(project_name, create_if_missing)
            scan_list = self.get_project_scans(project_code)
            
            # Look for exact match only
            scan = next((s for s in scan_list if s.get('name') == scan_name), None)
            if scan:
                return scan['code'], int(scan['id'])
                
            # Create if requested
            if create_if_missing:
                print(f"Creating scan '{scan_name}' in project '{project_name}'...")
                self.create_webapp_scan(project_code=project_code, scan_name=scan_name, **self._get_git_params(params))
                time.sleep(2)  # Brief wait for creation to process
                
                # Get the newly created scan
                scan_list = self.get_project_scans(project_code)
                scan = next((s for s in scan_list if s.get('name') == scan_name), None)
                if scan:
                    return scan['code'], int(scan['id'])
                raise ApiError(f"Failed to retrieve newly created scan '{scan_name}'")
                
            raise ScanNotFoundError(f"Scan '{scan_name}' not found in project '{project_name}'")
            
        else:
            # Global search
            if create_if_missing:
                raise ConfigurationError("Cannot create a scan without specifying a project")
                
            scan_list = self.list_scans()
            found = [s for s in scan_list if s.get('name') == scan_name]
            
            if len(found) == 1:
                scan = found[0]
                return scan['code'], int(scan['id'])
            elif len(found) > 1:
                projects = sorted(set(s.get('project_code', 'Unknown') for s in found))
                raise ValidationError(f"Multiple scans found with name '{scan_name}' in projects: {', '.join(projects)}")
                
            raise ScanNotFoundError(f"Scan '{scan_name}' not found in any project")

    def _get_git_params(self, params: argparse.Namespace) -> Dict[str, Any]:
        """Get git parameters if this is a git scan."""
        if getattr(params, 'command', None) == 'scan-git':
            return {
                'git_url': getattr(params, 'git_url', None),
                'git_branch': getattr(params, 'git_branch', None),
                'git_tag': getattr(params, 'git_tag', None),
                'git_depth': getattr(params, 'git_depth', None)
            }
        return {}
