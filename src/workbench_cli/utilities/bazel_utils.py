# workbench_cli/utilities/bazel_utils.py

import logging
from typing import Set, List, Tuple, Optional, Dict, Any

# Import the refactored modules
from .bazel_utils_modules.bazel_core import BazelCore
from .bazel_utils_modules.target_mapping import TargetMapping
from .bazel_utils_modules.scan_discovery import ScanDiscovery
from .git_utils import GitUtils

logger = logging.getLogger("workbench-cli")

class BazelUtils:
    """
    Simplified wrapper around the refactored Bazel utilities.
    Maintains backwards compatibility while delegating to specialized modules.
    """
    
    # Expose constants from the modules
    WORKSPACE_FILES = BazelCore.WORKSPACE_FILES
    DEFAULT_EXCLUSIONS = ScanDiscovery.DEFAULT_EXCLUSIONS
    
    # Core Bazel interactions (delegate to BazelCore)
    @staticmethod
    def check_bazel_installation() -> Tuple[bool, str]:
        """Check if Bazel is installed and accessible."""
        return BazelCore.check_bazel_installation()
    
    @staticmethod
    def detect_bazel_workspace(directory_path: str) -> Tuple[bool, Optional[str]]:
        """Detect if a directory is a Bazel workspace."""
        return BazelCore.detect_bazel_workspace(directory_path)
    
    @staticmethod
    def get_workspace_name(workspace_path: str) -> str:
        """Extract workspace name from Bazel workspace files."""
        return BazelCore.get_workspace_name(workspace_path)
    
    @staticmethod
    def get_module_version(workspace_path: str) -> Optional[str]:
        """Extract module version from MODULE.bazel file."""
        return BazelCore.get_module_version(workspace_path)
    
    @staticmethod
    def is_development_version(version: str) -> bool:
        """Determine if a module version indicates development/unstable code."""
        return BazelCore.is_development_version(version)
    
    @staticmethod
    def validate_workspace(workspace_path: str) -> None:
        """Validate that the given path is a valid bzlmod Bazel workspace."""
        return BazelCore.validate_workspace(workspace_path)
    
    # Target mapping (delegate to TargetMapping)
    @staticmethod
    def suggest_project_name(workspace_path: str, target: str = "//...") -> str:
        """Suggest a Workbench project name based on Bazel workspace and target."""
        return TargetMapping.suggest_project_name(workspace_path, target)
    
    @staticmethod
    def suggest_scan_name(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> str:
        """Suggest a Workbench scan name based on target and Git context."""
        return TargetMapping.suggest_scan_name(workspace_path, target, baseline_commit)
    
    @staticmethod
    def suggest_scan_name_with_bzlmod(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> str:
        """Enhanced scan name suggestion that prioritizes MODULE.bazel versions."""
        return TargetMapping.suggest_scan_name_with_bzlmod(workspace_path, target, baseline_commit)
    
    @staticmethod
    def generate_project_metadata(workspace_path: str, target: str = "//...") -> Dict[str, str]:
        """Generate Workbench project metadata from Bazel workspace context."""
        return TargetMapping.generate_project_metadata(workspace_path, target)
    
    @staticmethod
    def generate_scan_metadata(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> Dict[str, str]:
        """Generate Workbench scan metadata from Bazel and Git context."""
        return TargetMapping.generate_scan_metadata(workspace_path, target, baseline_commit)
    
    @staticmethod
    def extract_baseline_from_scan_description(description: str) -> Optional[str]:
        """Extract baseline commit hash from a scan description."""
        return TargetMapping.extract_baseline_from_scan_description(description)
    
    @staticmethod
    def find_baseline_commit_from_previous_scans(workbench_api, project_name: str) -> Optional[str]:
        """Find a suitable baseline commit from previous scans."""
        return TargetMapping.find_baseline_commit_from_previous_scans(workbench_api, project_name)
    
    @staticmethod
    def discover_deployable_targets(workspace_path: str, query_options: str = "") -> List[Dict[str, Any]]:
        """Discover deployable targets in the Bazel workspace."""
        return TargetMapping.discover_scannable_targets(workspace_path, query_options)
    
    @staticmethod
    def estimate_scan_scope(workspace_path: str, target: str = "//...", query_options: str = "") -> Dict[str, Any]:
        """Estimate the scope of a Bazel scan before running it."""
        return TargetMapping.estimate_scan_scope(workspace_path, target, query_options)
    
    @staticmethod
    def suggest_project_scan_strategy(workspace_path: str) -> Dict[str, Any]:
        """Analyze workspace and suggest optimal Project and Scan organization strategy."""
        return TargetMapping.suggest_project_scan_strategy(workspace_path)
    
    # File and dependency discovery (delegate to ScanDiscovery)
    @staticmethod
    def get_files_to_scan(
        workspace_path: str, 
        target: str = "//...", 
        baseline_commit: Optional[str] = None, 
        query_options: str = "", 
        include_resolved_deps: bool = True, 
        exclude_dev_deps: bool = False
    ) -> Set[str]:
        """Main entry point to get the set of files to scan."""
        return ScanDiscovery.get_files_to_scan(
            workspace_path, target, baseline_commit, query_options, 
            include_resolved_deps, exclude_dev_deps
        )
    
    @staticmethod
    def get_changed_files(workspace_path: str, baseline_commit: str) -> Set[str]:
        """Get files changed since the baseline commit using Git diff."""
        return GitUtils.get_changed_files_since_commit(workspace_path, baseline_commit)
    
    @staticmethod
    def query_affected_targets(workspace_path: str, changed_files: Set[str], target: str = "//...", query_options: str = "") -> List[str]:
        """Use Bazel query to find targets affected by changed files."""
        return ScanDiscovery.query_affected_targets(workspace_path, changed_files, target, query_options)
    
    @staticmethod
    def query_all_targets(workspace_path: str, target: str = "//...", query_options: str = "") -> List[str]:
        """Query all targets in the workspace."""
        return ScanDiscovery.query_all_targets(workspace_path, target, query_options)
    
    @staticmethod
    def get_target_sources(workspace_path: str, targets: List[str], query_options: str = "") -> Set[str]:
        """Get source files for the given Bazel targets."""
        return ScanDiscovery.get_target_sources(workspace_path, targets, query_options)
    
    @staticmethod
    def get_resolved_dependencies(workspace_path: str, targets: List[str]) -> Set[str]:
        """Get resolved external dependency artifacts."""
        return ScanDiscovery.get_resolved_dependencies(workspace_path, targets)
    
    @staticmethod
    def get_target_specific_dependencies(workspace_path: str, targets: List[str]) -> Set[str]:
        """Get only the external dependencies actually used by the specified targets."""
        return ScanDiscovery.get_target_specific_dependencies(workspace_path, targets)
    
    @staticmethod
    def get_exact_external_dependencies(workspace_path: str, targets: List[str]) -> Set[str]:
        """Get the exact external files referenced by targets using Bazel's build graph."""
        return ScanDiscovery.get_exact_external_dependencies(workspace_path, targets)
    
    @staticmethod
    def get_hybrid_external_dependencies(workspace_path: str, targets: List[str]) -> Set[str]:
        """Hybrid approach: Get target-specific repos but with better file filtering."""
        return ScanDiscovery.get_hybrid_external_dependencies(workspace_path, targets)
    
    @staticmethod
    def get_dependency_manifest_files(workspace_path: str) -> Set[str]:
        """Find Bazel dependency manifest files."""
        return ScanDiscovery.get_dependency_manifest_files(workspace_path)
    
    # Additional helper methods for backwards compatibility
    @staticmethod
    def _get_output_base(workspace_path: str) -> Optional[str]:
        """Get Bazel's output_base directory."""
        return BazelCore.get_output_base(workspace_path)
    
    @staticmethod
    def _has_external_dependencies(workspace_path: str) -> bool:
        """Check if the workspace has external dependencies."""
        return BazelCore.has_external_dependencies(workspace_path)