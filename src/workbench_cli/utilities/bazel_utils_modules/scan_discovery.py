# workbench_cli/utilities/bazel_utils_modules/scan_discovery.py

import os
import subprocess
import logging
import glob
from typing import Set, List, Optional
from pathlib import Path
from .bazel_core import BazelCore
from ...utilities.git_utils import GitUtils
from ...exceptions import ProcessError

logger = logging.getLogger("workbench-cli")

class ScanDiscovery:
    """
    Handles discovery of source files and dependencies for bzlmod Bazel scanning.
    Provides multiple strategies for external dependency resolution focused on MODULE.bazel.
    """
    
    # Common files to exclude from scanning (bzlmod-focused)
    DEFAULT_EXCLUSIONS = {
        'bazel-*',      # Bazel symlinks (bazel-bin, bazel-out, etc.)
        '.git',         # Git directory
        'BUILD',        # BUILD files (metadata, not source)
        'BUILD.bazel',  # BUILD.bazel files (metadata, not source)
        'MODULE.bazel', # MODULE.bazel files (metadata, not source)
        'MODULE.bazel.lock',  # Bzlmod lockfile (metadata, not source)
        '.bazelrc',     # Bazel configuration
        '.bazelversion', # Bazel version file
        # Note: Removed legacy WORKSPACE files from exclusions since we don't support them
    }
    
    @staticmethod
    def get_files_to_scan(
        workspace_path: str, 
        target: str = "//...", 
        baseline_commit: Optional[str] = None, 
        query_options: str = "", 
        include_resolved_deps: bool = True, 
        exclude_dev_deps: bool = False
    ) -> Set[str]:
        """
        Main entry point to get the set of files to scan, including resolved dependencies.
        Implements progressive degradation strategy for robust operation.
        
        Uses a single, robust dependency resolution approach that combines:
        - Lockfile-driven precision when available (bzlmod best practice)
        - Target-specific scoping for safety
        - Progressive fallbacks for reliability
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern to analyze
            baseline_commit: Optional baseline commit for incremental scanning
            query_options: Additional options for bazel query
            include_resolved_deps: Whether to include resolved external dependencies
            exclude_dev_deps: Whether to exclude development-only dependencies (bzlmod best practice)
            
        Returns:
            Set[str]: Set of file paths relative to workspace that should be scanned
            
        Raises:
            ProcessError: If all fallback strategies fail
        """
        # Validate bzlmod workspace
        BazelCore.validate_workspace(workspace_path)

        logger.info(f"Analyzing bzlmod Bazel workspace: {workspace_path}")
        logger.info(f"Target pattern: {target}")
        logger.info(f"Include resolved dependencies: {include_resolved_deps}")
        if exclude_dev_deps:
            logger.info("Excluding development dependencies from scan")

        # Progressive strategy for source file discovery
        source_files = set()
        targets_for_deps = []
        
        if baseline_commit:
            logger.info(f"Incremental scan from baseline: {baseline_commit}")
            source_files, targets_for_deps = ScanDiscovery._get_incremental_files_with_fallbacks(
                workspace_path, baseline_commit, target, query_options
            )
        else:
            logger.info("Full workspace scan")
            source_files, targets_for_deps = ScanDiscovery._get_full_scan_files_with_fallbacks(
                workspace_path, target, query_options
            )
        
        if not source_files and not targets_for_deps:
            logger.warning("No source files or targets found - implementing emergency fallback")
            source_files = ScanDiscovery._emergency_filesystem_scan(workspace_path)
        
        # Add dependency manifest files for dependency analysis (bzlmod-focused)
        manifest_files = ScanDiscovery.get_dependency_manifest_files(workspace_path)
        
        # Add resolved external dependencies with unified approach
        resolved_deps = set()
        if include_resolved_deps:
            logger.info("Resolving external dependencies using unified approach...")
            resolved_deps = ScanDiscovery._get_unified_external_dependencies(
                workspace_path, targets_for_deps, exclude_dev_deps
            )
        
        # Combine all files
        all_files = source_files.union(manifest_files).union(resolved_deps)
        
        # Final safety check
        if not all_files:
            logger.error("All scan strategies failed to find any files")
            raise ProcessError("Unable to find any files to scan in the workspace")
        
        logger.info(f"Selected {len(source_files)} source files, {len(manifest_files)} dependency manifest files, and {len(resolved_deps)} resolved dependencies")
        logger.info(f"Total files for scanning: {len(all_files)}")
        
        return all_files
    
    @staticmethod
    def query_affected_targets(workspace_path: str, changed_files: Set[str], target: str = "//...", query_options: str = "") -> List[str]:
        """
        Use Bazel query to find targets affected by changed files.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            changed_files: Set of changed file paths
            target: Bazel target pattern to query (default: //...)
            query_options: Additional options for bazel query
            
        Returns:
            List[str]: List of affected target labels
            
        Raises:
            ProcessError: If Bazel query fails
        """
        if not changed_files:
            logger.debug("No changed files, querying all targets")
            return ScanDiscovery.query_all_targets(workspace_path, target, query_options)
        
        # Build the query to find reverse dependencies of changed files
        # We need to be careful with the query syntax
        files_list = ','.join(f'"{f}"' for f in changed_files if f)
        if not files_list:
            logger.debug("No valid changed files for query, querying all targets")
            return ScanDiscovery.query_all_targets(workspace_path, target, query_options)
        
        # Use rdeps to find reverse dependencies of changed files
        query = f'rdeps({target}, set({files_list}))'
        
        try:
            cmd = ['bazel', 'query', query]
            if query_options:
                cmd.extend(query_options.split())
            
            logger.debug(f"Running Bazel query: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                # If the query fails, fall back to all targets
                logger.warning(f"Bazel query failed, falling back to all targets: {result.stderr.strip()}")
                return ScanDiscovery.query_all_targets(workspace_path, target, query_options)
            
            targets = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            logger.debug(f"Found {len(targets)} affected targets")
            return targets
            
        except subprocess.TimeoutExpired:
            logger.warning("Bazel query timed out, falling back to all targets")
            return ScanDiscovery.query_all_targets(workspace_path, target, query_options)
        except Exception as e:
            logger.warning(f"Bazel query failed: {e}, falling back to all targets")
            return ScanDiscovery.query_all_targets(workspace_path, target, query_options)
    
    @staticmethod
    def query_all_targets(workspace_path: str, target: str = "//...", query_options: str = "") -> List[str]:
        """
        Query all targets in the bzlmod workspace.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern to query (default: //...)
            query_options: Additional options for bazel query
            
        Returns:
            List[str]: List of all target labels
            
        Raises:
            ProcessError: If Bazel query fails
        """
        try:
            cmd = ['bazel', 'query', target]
            if query_options:
                cmd.extend(query_options.split())
            
            logger.debug(f"Running Bazel query: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                raise ProcessError(f"Bazel query failed: {result.stderr.strip()}")
            
            targets = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            logger.debug(f"Found {len(targets)} total targets")
            return targets
            
        except subprocess.TimeoutExpired:
            raise ProcessError("Bazel query timed out")
        except Exception as e:
            raise ProcessError(f"Bazel query failed: {e}")
    
    @staticmethod
    def get_target_sources(workspace_path: str, targets: List[str], query_options: str = "") -> Set[str]:
        """
        Get source files for the given Bazel targets using proper Bazel queries.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            targets: List of target labels
            query_options: Additional options for bazel query
            
        Returns:
            Set[str]: Set of source file paths relative to workspace
            
        Raises:
            ProcessError: If Bazel query fails
        """
        if not targets:
            return set()
        
        # Try proper Bazel query first (build-aware)
        try:
            return ScanDiscovery._get_target_sources_bazel_query(workspace_path, targets, query_options)
        except ProcessError as e:
            logger.warning(f"Bazel query for source files failed: {e}")
            logger.info("Falling back to filesystem-based approach")
            return ScanDiscovery._get_target_sources_fallback(workspace_path, targets)
    
    @staticmethod
    def _get_target_sources_bazel_query(workspace_path: str, targets: List[str], query_options: str = "") -> Set[str]:
        """
        Get source files using proper Bazel query (build-aware approach).
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            targets: List of target labels
            query_options: Additional options for bazel query
            
        Returns:
            Set[str]: Set of source file paths relative to workspace
            
        Raises:
            ProcessError: If Bazel query fails
        """
        source_files = set()
        
        # Process targets in smaller batches to avoid timeouts
        batch_size = 5  # Process 5 targets at a time
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            batch_files = ScanDiscovery._query_target_batch_sources(workspace_path, batch, query_options)
            source_files.update(batch_files)
        
        logger.info(f"Bazel query found {len(source_files)} workspace source files")
        return source_files
    
    @staticmethod
    def _query_target_batch_sources(workspace_path: str, targets: List[str], query_options: str = "") -> Set[str]:
        """
        Query source files for a batch of targets, filtering out external dependencies.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            targets: List of target labels (batch)
            query_options: Additional options for bazel query
            
        Returns:
            Set[str]: Set of workspace source file paths relative to workspace
            
        Raises:
            ProcessError: If Bazel query fails
        """
        source_files = set()
        
        # Build query for this batch
        targets_query = " + ".join(targets)
        
        # Query for source files that are dependencies of the targets
        # This finds actual source files that Bazel uses to build the targets
        query = f'kind("source file", deps({targets_query}))'
        
        try:
            cmd = ['bazel', 'query', query, '--output=label']
            if query_options:
                cmd.extend(query_options.split())
            
            logger.debug(f"Running Bazel source query for batch: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=120  # Increased timeout for complex queries
            )
            
            if result.returncode != 0:
                logger.debug(f"Batch query failed: {result.stderr.strip()}")
                raise ProcessError(f"Bazel query failed: {result.stderr.strip()}")
            
            # Parse the output and filter workspace files only
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line and line.startswith('//'):
                    # Convert Bazel label to file path
                    # //rest_tokio:src/main.rs -> rest_tokio/src/main.rs
                    if ':' in line:
                        package_part, file_part = line[2:].split(':', 1)
                        if package_part:
                            file_path = f"{package_part}/{file_part}"
                        else:
                            file_path = file_part
                        
                        source_files.add(file_path)
                        logger.debug(f"Found workspace source file: {file_path}")
                # Skip all other lines (external dependencies, build files, etc.)
            
            return source_files
            
        except subprocess.TimeoutExpired:
            logger.debug(f"Batch query timed out for targets: {targets}")
            raise ProcessError("Bazel source query timed out")
        except Exception as e:
            logger.debug(f"Batch query failed for targets: {targets}, error: {e}")
            raise ProcessError(f"Bazel source query failed: {e}")
    
    @staticmethod
    def _get_target_sources_fallback(workspace_path: str, targets: List[str]) -> Set[str]:
        """
        Fallback method to get sources for targets when normal query fails.
        Uses simple file pattern matching instead of complex Bazel queries.
        """
        logger.info("Using fallback source resolution")
        source_files = set()
        
        try:
            # For each target, try to infer source files from the path
            for target in targets:
                if not target.startswith('//'):
                    continue
                    
                # Parse target path (e.g., //apps/frontend:bin -> apps/frontend)
                if ':' in target:
                    package_path = target.split(':')[0][2:]  # Remove // prefix
                else:
                    package_path = target[2:]  # Remove // prefix
                
                # Look for source files in that package directory
                full_package_path = os.path.join(workspace_path, package_path)
                if os.path.exists(full_package_path) and os.path.isdir(full_package_path):
                    # Find source files in the package directory
                    for file in os.listdir(full_package_path):
                        if ScanDiscovery._is_source_file(file):
                            rel_path = os.path.join(package_path, file)
                            source_files.add(rel_path)
                
                # Safety limit
                if len(source_files) > 1000:
                    logger.warning("Fallback source resolution reached 1000 file limit")
                    break
            
            logger.info(f"Fallback source resolution found {len(source_files)} files")
            return source_files
            
        except Exception as e:
            logger.warning(f"Fallback source resolution failed: {e}")
            return set()
    
    @staticmethod
    def _is_source_file(filename: str) -> bool:
        """
        Check if a file is likely a source file based on extension.
        """
        source_extensions = {
            '.c', '.h', '.cpp', '.hpp', '.cc', '.hh', '.cxx', '.hxx',
            '.py', '.rs', '.go', '.java', '.kt', '.scala',
            '.js', '.ts', '.jsx', '.tsx',
            '.cs', '.vb', '.fs',
            '.rb', '.php', '.pl',
            '.swift', '.m', '.mm',
            '.proto', '.bzl'
        }
        
        _, ext = os.path.splitext(filename.lower())
        return ext in source_extensions
    
    @staticmethod
    def _should_exclude_file(file_path: str) -> bool:
        """
        Check if a file should be excluded from scanning.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            bool: True if the file should be excluded
        """
        path_obj = Path(file_path)
        filename = path_obj.name
        
        # Check against default exclusions
        for exclusion in ScanDiscovery.DEFAULT_EXCLUSIONS:
            if exclusion.endswith('*'):
                # Wildcard pattern - only check the filename and immediate parent directory
                prefix = exclusion[:-1]
                if filename.startswith(prefix):
                    return True
                # Check if any direct parent directory starts with the prefix (for bazel-* directories)
                parent_dir = path_obj.parent.name
                if parent_dir.startswith(prefix):
                    return True
            elif filename == exclusion:
                # Exact filename match
                return True
            elif exclusion in path_obj.parts:
                # Directory name in path (for things like .git)
                return True
        
        return False

    @staticmethod
    def get_dependency_manifest_files(workspace_path: str) -> Set[str]:
        """
        Find bzlmod dependency manifest files that should be included for dependency analysis.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            Set[str]: Set of dependency manifest file paths relative to workspace
        """
        manifest_files = set()
        
        # Bzlmod-focused dependency patterns (removed legacy WORKSPACE files)
        dependency_patterns = [
            # Primary bzlmod files
            "MODULE.bazel",           # Bzlmod dependencies (primary)
            "MODULE.bazel.lock",      # Bzlmod lockfile
            
            # Language-specific dependency files that work with bzlmod module extensions
            "Cargo.toml",             # Rust dependencies (rules_rust)
            "Cargo.lock",             # Rust lockfile
            "package.json",           # Node.js dependencies (rules_nodejs)
            "package-lock.json",      # Node.js lockfile
            "yarn.lock",              # Yarn lockfile
            "pnpm-lock.yaml",         # PNPM lockfile (modern Node.js)
            "pom.xml",                # Maven dependencies (rules_jvm_external)
            "requirements.txt",       # Python dependencies (rules_python)
            "requirements*.txt",      # Python requirements variants
            "Pipfile",                # Python Pipenv
            "Pipfile.lock",           # Python Pipenv lockfile
            "pyproject.toml",         # Modern Python project files
            "go.mod",                 # Go dependencies (rules_go)
            "go.sum",                 # Go dependencies checksum
            "build.gradle",           # Gradle build files
            "build.gradle.kts",       # Kotlin Gradle build files
            "settings.gradle",        # Gradle settings
            "gradle.properties",      # Gradle properties
        ]
        
        # Search for manifest files in workspace root and subdirectories
        for pattern in dependency_patterns:
            # Search in workspace root
            root_pattern = os.path.join(workspace_path, pattern)
            for file_path in glob.glob(root_pattern):
                if os.path.isfile(file_path):
                    rel_path = os.path.relpath(file_path, workspace_path)
                    manifest_files.add(rel_path)
                    logger.debug(f"Found dependency manifest in root: {rel_path}")
            
            # Search in all subdirectories (but limit depth to avoid performance issues)
            if not pattern.startswith("*"):  # Skip patterns that already have wildcards
                recursive_pattern = os.path.join(workspace_path, "**", pattern)
                for file_path in glob.glob(recursive_pattern, recursive=True):
                    if os.path.isfile(file_path):
                        rel_path = os.path.relpath(file_path, workspace_path)
                        # Skip files in hidden directories or build outputs
                        if not any(part.startswith('.') or part in ['bazel-out', 'bazel-bin', 'bazel-testlogs'] 
                                  for part in rel_path.split(os.sep)):
                            manifest_files.add(rel_path)
                            logger.debug(f"Found dependency manifest: {rel_path}")
        
        # Include BUILD files that might contain dependency declarations
        # (Keep these as they're still relevant for bzlmod workspaces)
        build_patterns = ["BUILD", "BUILD.bazel"]
        for pattern in build_patterns:
            recursive_pattern = os.path.join(workspace_path, "**", pattern)
            for file_path in glob.glob(recursive_pattern, recursive=True):
                if os.path.isfile(file_path):
                    rel_path = os.path.relpath(file_path, workspace_path)
                    # Skip build outputs and hidden directories
                    if not any(part.startswith('.') or part in ['bazel-out', 'bazel-bin', 'bazel-testlogs'] 
                              for part in rel_path.split(os.sep)):
                        manifest_files.add(rel_path)
                        logger.debug(f"Found BUILD file: {rel_path}")
        
        logger.info(f"Found {len(manifest_files)} dependency manifest files")
        return manifest_files

    @staticmethod
    def _get_unified_external_dependencies(
        workspace_path: str, targets: List[str], exclude_dev_deps: bool
    ) -> Set[str]:
        """
        Unified external dependency resolution:
        - Lockfile-driven precision (MODULE.bazel.lock)
        - Target-specific scoping (MODULE.bazel)
        - Progressive fallbacks
        """
        if not targets:
            logger.info("No targets provided for unified dependency resolution")
            return set()
        
        # Step 1: Try lockfile-driven resolution (most accurate)
        lockfile_deps = ScanDiscovery._get_lockfile_driven_dependencies(workspace_path, targets, exclude_dev_deps)
        if lockfile_deps:
            logger.info(f"Using lockfile-driven dependency resolution: {len(lockfile_deps)} repos")
            return ScanDiscovery._extract_repo_files(workspace_path, lockfile_deps)
        
        # Step 2: Fallback to target-specific resolution (safer)
        target_deps = ScanDiscovery._get_target_specific_external_repos(workspace_path, targets)
        if target_deps:
            logger.info(f"Using target-specific dependency resolution: {len(target_deps)} repos")
            # Filter dev dependencies if requested
            if exclude_dev_deps:
                target_deps = ScanDiscovery._filter_dev_dependencies(workspace_path, target_deps)
            return ScanDiscovery._extract_repo_files(workspace_path, target_deps)
        
        # Step 3: Fallback to manifest-only approach (most basic)
        logger.info("Falling back to manifest-only dependency resolution")
        return ScanDiscovery._get_manifest_only_dependencies(workspace_path)
    
    @staticmethod
    def _extract_repo_files(workspace_path: str, repo_names: Set[str]) -> Set[str]:
        """
        Extract files from external repositories.
        """
        # Get the output_base location where external deps are stored
        output_base = BazelCore.get_output_base(workspace_path)
        logger.debug(f"Bazel output_base: {output_base}")
        
        if not output_base:
            logger.warning("Could not determine Bazel output_base, skipping resolved dependencies")
            return set()
        
        external_dir = os.path.join(output_base, "external")
        logger.debug(f"External directory: {external_dir}")
        
        if not os.path.exists(external_dir):
            logger.warning(f"External directory does not exist: {external_dir}")
            return set()
            
        # List what's actually in the external directory
        try:
            external_contents = os.listdir(external_dir)
            logger.debug(f"External directory contains {len(external_contents)} items: {external_contents[:10]}{'...' if len(external_contents) > 10 else ''}")
        except Exception as e:
            logger.warning(f"Cannot list external directory contents: {e}")
            return set()
        
        dependency_files = set()
        
        # Only process external repos that are actually used by the targets
        for repo_name in repo_names:
            # Strip @ prefix from repository name for directory path construction
            # Bazel query returns "@repo_name" but the directory is just "repo_name"
            dir_name = repo_name.lstrip('@')
            repo_path = os.path.join(external_dir, dir_name)
            
            if not os.path.exists(repo_path) or not os.path.isdir(repo_path):
                logger.debug(f"External repo not found: {repo_name} -> {dir_name} (expected at: {repo_path})")
                continue
                
            logger.debug(f"Processing external repo: {repo_name} -> {dir_name}")
            
            # Include dependency artifacts from this external repo
            # Use the original repo_name (with @) for the external path in the archive
            repo_files = ScanDiscovery._extract_dependency_artifacts(workspace_path, repo_path, dir_name)
            dependency_files.update(repo_files)
        
        logger.info(f"Found {len(dependency_files)} dependency artifacts from {len(repo_names)} external repos")
        return dependency_files
    
    @staticmethod
    def _get_lockfile_driven_dependencies(workspace_path: str, targets: List[str], exclude_dev_deps: bool = False) -> Set[str]:
        """
        Use MODULE.bazel.lock to get precise dependency information.
        This is more accurate than Bazel queries for bzlmod workspaces.
        """
        try:
            lockfile_info = BazelCore.get_lockfile_info(workspace_path)
            if not lockfile_info or not lockfile_info.get("resolved_modules"):
                logger.debug("No lockfile info available")
                return set()
            
            # Get development dependencies to filter out if requested
            dev_deps = set()
            if exclude_dev_deps:
                dev_deps = set(BazelCore.detect_dev_dependencies(workspace_path))
                logger.debug(f"Found {len(dev_deps)} development dependencies to exclude: {dev_deps}")
            
            # Get all resolved modules from lockfile
            resolved_repos = set()
            for module_key, module_data in lockfile_info["resolved_modules"].items():
                repo_name = module_data.get("repo_name", module_key)
                
                # Skip development dependencies if requested
                if exclude_dev_deps and repo_name in dev_deps:
                    logger.debug(f"Excluding dev dependency: {repo_name}")
                    continue
                
                resolved_repos.add(repo_name)
                logger.debug(f"Lockfile resolved repo: {repo_name}")
            
            logger.info(f"Lockfile-driven resolution found {len(resolved_repos)} repositories")
            return resolved_repos
            
        except Exception as e:
            logger.debug(f"Lockfile-driven dependency resolution failed: {e}")
            return set()
    
    @staticmethod
    def _filter_dev_dependencies(workspace_path: str, repo_names: Set[str]) -> Set[str]:
        """
        Filter out development dependencies from a set of repository names.
        """
        try:
            dev_deps = set(BazelCore.detect_dev_dependencies(workspace_path))
            if not dev_deps:
                return repo_names
            
            filtered_repos = repo_names - dev_deps
            excluded_count = len(repo_names) - len(filtered_repos)
            if excluded_count > 0:
                logger.info(f"Excluded {excluded_count} development dependencies from scan")
            
            return filtered_repos
            
        except Exception as e:
            logger.debug(f"Failed to filter dev dependencies: {e}")
            return repo_names
    
    @staticmethod
    def _get_manifest_only_dependencies(workspace_path: str) -> Set[str]:
        """
        Fallback: only include dependency manifest files, no external source code.
        """
        logger.info("Using manifest-only dependency approach")
        # Just return empty set - manifests are handled separately
        return set() 
    
    # Removed methods (simplified to unified approach):
    # - get_exact_external_dependencies (complex, rarely used)
    # - get_hybrid_external_dependencies (complexity without clear benefit)  
    # - get_resolved_dependencies (legacy, cross-contamination risk)
    # 
    # The unified approach combines the best aspects:
    # - Lockfile precision when available
    # - Target-specific scoping for safety  
    # - Progressive fallbacks for reliability

    @staticmethod
    def _force_dependency_resolution(workspace_path: str, targets: List[str]) -> None:
        """
        Force Bazel to resolve and download all dependencies for the given targets.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            targets: List of target labels
        """
        if not targets:
            return
            
        try:
            # Build a query to get all dependencies
            targets_query = " + ".join(targets)
            query = f'deps({targets_query})'
            
            cmd = ['bazel', 'query', query, '--keep_going', '--noshow_progress']
            
            logger.debug(f"Running dependency resolution: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=180  # 3 minutes for dependency resolution
            )
            
            if result.returncode == 0:
                dep_count = len(result.stdout.strip().splitlines())
                logger.info(f"Successfully resolved {dep_count} dependencies")
            else:
                logger.warning(f"Dependency resolution completed with warnings: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            logger.warning("Dependency resolution timed out, some dependencies may not be resolved")
        except Exception as e:
            logger.warning(f"Failed to force dependency resolution: {e}")

    @staticmethod
    def _get_target_specific_external_repos(workspace_path: str, targets: List[str]) -> Set[str]:
        """
        Get the external repository names that are actually used by the specified targets.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            targets: List of target labels
            
        Returns:
            Set[str]: Set of external repository names used by the targets
        """
        external_repos = set()
        
        try:
            # Query for all external dependencies of the targets
            targets_query = " + ".join(targets)
            query = f'filter("^@", deps({targets_query}))'
            
            cmd = ['bazel', 'query', query, '--keep_going', '--noshow_progress']
            
            logger.debug(f"Running target-specific dependency query: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if line.startswith('@') and '//' in line:
                        # Extract repo name from @repo_name//package:target
                        repo_name = line.split('//')[0][1:]  # Remove @ prefix
                        if repo_name and not ScanDiscovery._should_skip_external_repo(repo_name):
                            external_repos.add(repo_name)
                            logger.debug(f"Found target-specific external repo: {repo_name}")
                            
                logger.info(f"Found {len(external_repos)} external repositories used by targets")
            else:
                logger.warning(f"Target-specific dependency query failed: {result.stderr.strip()}")
                logger.warning("Falling back to all external repositories")
                
        except subprocess.TimeoutExpired:
            logger.warning("Target-specific dependency query timed out")
        except Exception as e:
            logger.warning(f"Failed to get target-specific dependencies: {e}")
            
        return external_repos

    @staticmethod
    def _should_skip_external_repo(repo_name: str) -> bool:
        """
        Check if an external repository should be skipped for dependency analysis.
        
        Args:
            repo_name: Name of the external repository
            
        Returns:
            bool: True if repo should be skipped
        """
        # Skip internal Bazel repos and build outputs
        skip_patterns = [
            '_main',           # Main workspace
            'bazel_',          # Bazel internal repos
            'local_config_',   # Local configuration repos
            'remote_config_',  # Remote configuration repos
            'embedded_jdk',    # JDK repos
            'remotejdk',       # Remote JDK repos
        ]
        
        for pattern in skip_patterns:
            if repo_name.startswith(pattern):
                return True
                
        return False

    @staticmethod
    def _extract_dependency_artifacts(workspace_path: str, repo_path: str, repo_name: str) -> Set[str]:
        """
        Extract dependency artifacts from an external repository.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace (for relative paths)
            repo_path: Path to the external repository
            repo_name: Name of the external repository
            
        Returns:
            Set[str]: Set of dependency artifact paths relative to workspace
        """
        dependency_files = set()
        
        logger.debug(f"Extracting artifacts from repo: {repo_name}")
        logger.debug(f"Repo path: {repo_path}")
        
        # Check if repo path exists
        if not os.path.exists(repo_path):
            logger.warning(f"External repo path does not exist: {repo_path}")
            return dependency_files
            
        if not os.path.isdir(repo_path):
            logger.warning(f"External repo path is not a directory: {repo_path}")
            return dependency_files
        
        # List contents of repo for debugging
        try:
            repo_contents = os.listdir(repo_path)
            logger.debug(f"Repo {repo_name} contains {len(repo_contents)} items: {repo_contents[:10]}{'...' if len(repo_contents) > 10 else ''}")
        except Exception as e:
            logger.warning(f"Cannot list contents of {repo_path}: {e}")
            return dependency_files
        
        files_checked = 0
        files_included = 0
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Skip build output directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['bazel-out', 'bazel-bin', 'bazel-testlogs']]
                
                logger.debug(f"Walking directory: {root}, found {len(files)} files, {len(dirs)} subdirs")
                
                for file in files:
                    files_checked += 1
                    if ScanDiscovery._is_dependency_artifact(file):
                        file_path = os.path.join(root, file)
                        
                        # Create a relative path that includes the external repo name
                        # This helps identify which external repo the file came from
                        rel_from_repo = os.path.relpath(file_path, repo_path)
                        external_rel_path = f"external/{repo_name}/{rel_from_repo}"
                        
                        dependency_files.add(external_rel_path)
                        files_included += 1
                        logger.debug(f"Found dependency artifact: {external_rel_path}")
                    else:
                        # Log some examples of excluded files for debugging
                        if files_checked <= 5:  # Only log first few to avoid spam
                            logger.debug(f"Excluded file: {file}")
                        
        except Exception as e:
            logger.warning(f"Failed to extract artifacts from {repo_name}: {e}")
        
        logger.info(f"Repo {repo_name}: checked {files_checked} files, included {files_included} artifacts")
        return dependency_files

    @staticmethod
    def _extract_essential_manifests(workspace_path: str, repo_path: str, repo_name: str) -> Set[str]:
        """
        Extract only essential manifest files from an external repository.
        More selective than _extract_dependency_artifacts.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            repo_path: Path to the external repository  
            repo_name: Name of the external repository
            
        Returns:
            Set[str]: Set of essential manifest file paths
        """
        manifest_files = set()
        
        # Essential manifests only (not source files) - bzlmod focused
        essential_manifests = {
            'MODULE.bazel',               # Bzlmod module files
            'MODULE.bazel.lock',          # Bzlmod lockfiles
            'Cargo.toml', 'Cargo.lock',   # Rust
            'package.json', 'package-lock.json', 'pnpm-lock.yaml',  # Node.js
            'pom.xml', 'build.gradle', 'build.gradle.kts',          # Java
            'go.mod', 'go.sum',           # Go
            'requirements.txt', 'pyproject.toml',  # Python
            'BUILD', 'BUILD.bazel',       # Bazel build files
        }
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Skip deep nested directories to avoid performance issues
                depth = root[len(repo_path):].count(os.sep)
                if depth > 3:  # Only go 3 levels deep
                    dirs.clear()
                    continue
                    
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if file in essential_manifests:
                        file_path = os.path.join(root, file)
                        rel_from_repo = os.path.relpath(file_path, repo_path)
                        external_rel_path = f"external/{repo_name}/{rel_from_repo}"
                        manifest_files.add(external_rel_path)
                        logger.debug(f"Found essential manifest: {external_rel_path}")
                        
        except Exception as e:
            logger.warning(f"Failed to extract essential manifests from {repo_name}: {e}")
        
        return manifest_files

    @staticmethod
    def _convert_external_label_to_path(label: str, output_base: Optional[str]) -> Optional[str]:
        """
        Convert a Bazel external label to a file path for uploading.
        
        Args:
            label: Bazel label like @repo_name//package:file
            output_base: Bazel output_base directory
            
        Returns:
            Optional[str]: File path relative to workspace, or None if not convertible
        """
        if not output_base or not label.startswith('@'):
            return None
            
        try:
            # Parse @repo_name//package:file
            if '//' not in label:
                return None
                
            repo_part, target_part = label.split('//', 1)
            repo_name = repo_part[1:]  # Remove @ prefix
            
            if ':' in target_part:
                package, filename = target_part.rsplit(':', 1)
                if package:
                    external_file_path = f"{package}/{filename}"
                else:
                    external_file_path = filename
            else:
                external_file_path = target_part
            
            # Construct the external path
            full_external_path = os.path.join(output_base, "external", repo_name, external_file_path)
            
            # Check if file exists
            if os.path.exists(full_external_path):
                return f"external/{repo_name}/{external_file_path}"
            else:
                logger.debug(f"External file not found: {full_external_path}")
                return None
                
        except Exception as e:
            logger.debug(f"Failed to convert external label {label}: {e}")
            return None

    @staticmethod
    def _is_dependency_artifact(filename: str) -> bool:
        """
        Check if a file is a dependency artifact worth analyzing (includes actual source code).
        
        This method is more inclusive to ensure we capture the actual source code of 
        third-party dependencies, not just their manifests.
        
        Args:
            filename: Name of the file
            
        Returns:
            bool: True if file is a dependency artifact that should be included in scanning
        """
        # Files to explicitly exclude (binary files, build outputs, etc.)
        exclusion_patterns = {
            # Binary and compiled files
            '.exe', '.dll', '.so', '.dylib', '.a', '.lib', '.obj', '.o',
            '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.pyd',
            '.wasm', '.bin', '.out', '.elf',
            
            # Archive files
            '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
            
            # Image/media files
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wav', '.pdf',
            
            # Build outputs and temporary files
            '.tmp', '.temp', '.cache', '.log', '.lock', '.pid',
            
            # Version control and IDE files
            '.git', '.svn', '.hg', '.bzr',
            '.vscode', '.idea', '.vs', '.suo', '.user',
            
            # OS files
            '.ds_store', 'thumbs.db', 'desktop.ini',
        }
        
        filename_lower = filename.lower()
        
        # Exclude binary and unwanted files
        _, ext = os.path.splitext(filename_lower)
        if ext in exclusion_patterns:
            return False
            
        # Exclude some specific filenames
        excluded_filenames = {
            '.gitignore', '.gitattributes', '.gitmodules',
            '.dockerignore', '.eslintignore', '.npmignore',
            'makefile', 'dockerfile', 'jenkinsfile',
            'changelog', 'changelog.md', 'history', 'history.md',
            'authors', 'contributors', 'maintainers',
            'notice', 'copying', 'license.txt',  # License files are usually not needed for security scanning
        }
        if filename_lower in excluded_filenames:
            return False
        
        # Include README files and documentation that might contain important info
        if filename_lower.startswith('readme'):
            return True
            
        # Include all manifest and configuration files
        manifest_patterns = {
            # Bzlmod and Bazel
            'module.bazel', 'module.bazel.lock', 'workspace', 'workspace.bazel',
            'build', 'build.bazel', '.bazelrc', '.bazelversion',
            
            # Package managers and build tools
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'cargo.toml', 'cargo.lock', 'go.mod', 'go.sum',
            'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
            'requirements.txt', 'setup.py', 'setup.cfg', 'pyproject.toml',
            'pipfile', 'pipfile.lock', 'poetry.lock',
            'gemfile', 'gemfile.lock', 'composer.json', 'composer.lock',
            'packages.config', 'project.json',
            
            # Configuration files
            'makefile', 'cmake', 'cmakelist.txt', 'meson.build',
            'configure', 'configure.ac', 'configure.in', 'makefile.am',
            'sconscript', 'sconstruct', 'wscript', 'wscript_build',
        }
        
        if filename_lower in manifest_patterns:
            return True
            
        # Pattern-based manifest detection
        if (filename_lower.startswith('requirements') and filename_lower.endswith('.txt')):
            return True
        if filename_lower.endswith('.csproj') or filename_lower.endswith('.fsproj') or filename_lower.endswith('.vbproj'):
            return True
        if filename_lower.startswith('cmake') and (filename_lower.endswith('.txt') or filename_lower.endswith('.cmake')):
            return True
            
        # Now include source code files - be more inclusive with extensions
        source_extensions = {
            # Common programming languages
            '.c', '.h', '.cpp', '.hpp', '.cc', '.hh', '.cxx', '.hxx', '.c++', '.h++',
            '.m', '.mm',  # Objective-C
            '.swift',     # Swift
            '.rs',        # Rust
            '.go',        # Go
            '.py', '.pyx', '.pyi',  # Python
            '.java', '.kt', '.scala', '.groovy',  # JVM languages
            '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',  # JavaScript/TypeScript
            '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',  # PHP
            '.rb', '.rbw',  # Ruby
            '.cs', '.vb', '.fs',  # .NET languages
            '.pl', '.pm', '.t',  # Perl
            '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',  # Shell scripts
            '.lua',       # Lua
            '.dart',      # Dart
            '.elm',       # Elm
            '.ex', '.exs', # Elixir
            '.erl', '.hrl', # Erlang
            '.clj', '.cljs', '.cljc', # Clojure
            '.hs', '.lhs', # Haskell
            '.ml', '.mli', # OCaml
            '.nim',       # Nim
            '.cr',        # Crystal
            '.zig',       # Zig
            '.v',         # V
            '.odin',      # Odin
            '.d',         # D
            '.pas', '.pp', # Pascal
            '.ada', '.adb', '.ads', # Ada
            '.f', '.f90', '.f95', '.f03', '.f08', '.for', '.ftn', # Fortran
            '.jl',        # Julia
            '.r', '.rmd', # R
            '.sas',       # SAS
            '.sql',       # SQL
            '.proto',     # Protocol Buffers
            '.thrift',    # Thrift
            '.capnp',     # Cap'n Proto
            '.avsc',      # Avro Schema
            
            # Web and markup
            '.html', '.htm', '.xhtml',
            '.css', '.scss', '.sass', '.less', '.styl',
            '.xml', '.xsd', '.xsl', '.xslt',
            '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
            '.md', '.markdown', '.rst', '.txt', '.text',
            
            # Mobile development
            '.smali',     # Android
            '.dex',       # Android
            
            # Game development
            '.hlsl', '.glsl', '.cg', '.fx',  # Shaders
            '.gdscript', '.gd',              # Godot
            
            # Data and config formats
            '.properties', '.env', '.envrc',
            '.gitignore', '.gitattributes',
            '.editorconfig', '.clang-format',
            
            # Build and CI files
            '.dockerfile', '.containerfile',
            '.jenkinsfile',
            '.travis.yml', '.appveyor.yml', '.circleci',
            '.github', '.gitlab-ci.yml',
        }
        
        if ext in source_extensions:
            return True
            
        # Include files without extensions that might be source files
        # (common in some languages like Go, or configuration files)
        if '.' not in filename:
            # Be more selective for files without extensions
            # Include if it looks like a source file based on common patterns
            source_file_patterns = [
                'makefile', 'dockerfile', 'jenkinsfile', 'vagrantfile',
                'rakefile', 'gemfile', 'podfile', 'fastfile', 'appfile',
                'brewfile', 'snapfile', 'gymfile', 'matchfile', 'scanfile',
                'deliverfile', 'spacefile'
            ]
            if filename_lower in source_file_patterns:
                return True
                
            # Include files that look like they might be source code
            # (This is a heuristic - might need adjustment based on feedback)
            if len(filename) > 1 and filename.isalnum():
                return True
        
        # Default: exclude unknown file types
        # This is conservative - we can adjust based on what we're missing
        return False 
    
    @staticmethod
    def _get_incremental_files_with_fallbacks(
        workspace_path: str, baseline_commit: str, target: str, query_options: str
    ) -> tuple[set, list]:
        """
        Get incremental scan files with progressive fallbacks.
        
        Returns:
            tuple[set, list]: (source_files, targets_for_deps)
        """
        try:
            # Try Git-based incremental approach
            changed_files = GitUtils.get_changed_files_since_commit(workspace_path, baseline_commit)
            if not changed_files:
                logger.info("No files changed since baseline commit")
                return set(), []
            
            # Try to find affected targets
            try:
                affected_targets = ScanDiscovery.query_affected_targets(workspace_path, changed_files, target, query_options)
                if affected_targets:
                    source_files = ScanDiscovery.get_target_sources(workspace_path, affected_targets, query_options)
                    return source_files, affected_targets
                else:
                    logger.warning("No targets affected by changes, falling back to changed files only")
                    return changed_files, []
            except Exception as e:
                logger.warning(f"Target-based incremental scan failed: {e}")
                logger.info("Falling back to all changed files")
                return changed_files, []
                
        except Exception as e:
            logger.warning(f"Incremental scan failed: {e}")
            logger.info("Falling back to full scan")
            return ScanDiscovery._get_full_scan_files_with_fallbacks(workspace_path, target, query_options)
    
    @staticmethod
    def _get_full_scan_files_with_fallbacks(
        workspace_path: str, target: str, query_options: str
    ) -> tuple[set, list]:
        """
        Get full scan files with progressive fallbacks.
        
        Returns:
            tuple[set, list]: (source_files, targets_for_deps)
        """
        # Strategy 1: Query-based approach (most accurate)
        try:
            all_targets = ScanDiscovery.query_all_targets(workspace_path, target, query_options)
            if all_targets:
                source_files = ScanDiscovery.get_target_sources(workspace_path, all_targets, query_options)
                return source_files, all_targets
        except Exception as e:
            logger.warning(f"Query-based full scan failed: {e}")
        
        # Strategy 2: Simplified query approach
        try:
            logger.info("Trying simplified query approach")
            simplified_targets = ScanDiscovery._get_simplified_targets(workspace_path)
            if simplified_targets:
                source_files = ScanDiscovery._get_target_sources_fallback(workspace_path, simplified_targets)
                return source_files, simplified_targets
        except Exception as e:
            logger.warning(f"Simplified query approach failed: {e}")
        
        # Strategy 3: Filesystem-based approach (most basic but reliable)
        logger.info("Falling back to filesystem-based approach")
        try:
            source_files = ScanDiscovery._emergency_filesystem_scan(workspace_path)
            return source_files, []
        except Exception as e:
            logger.error(f"Emergency filesystem scan failed: {e}")
            return set(), []
    
    @staticmethod
    def _get_simplified_targets(workspace_path: str) -> List[str]:
        """
        Get targets using the simplest possible approach.
        """
        try:
            # Just try to query for any targets without complex patterns
            cmd = ['bazel', 'query', '//...', '--keep_going']
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=30  # Short timeout for fallback
            )
            
            if result.returncode == 0:
                targets = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
                logger.info(f"Simplified query found {len(targets)} targets")
                return targets[:10]  # Limit to first 10 for safety
            else:
                logger.debug(f"Simplified query failed: {result.stderr}")
                return []
                
        except Exception as e:
            logger.debug(f"Simplified target query failed: {e}")
            return []
    
    @staticmethod
    def _emergency_filesystem_scan(workspace_path: str) -> Set[str]:
        """
        Emergency fallback: scan filesystem directly for source files.
        This is the most basic approach but should always work.
        """
        logger.info("Using emergency filesystem scan")
        source_files = set()
        
        # Common source file extensions
        source_extensions = {
            '.c', '.h', '.cpp', '.hpp', '.cc', '.hh', '.cxx', '.hxx',
            '.py', '.rs', '.go', '.java', '.kt', '.scala',
            '.js', '.ts', '.jsx', '.tsx',
            '.cs', '.vb', '.fs',
            '.rb', '.php', '.pl',
            '.swift', '.m', '.mm'
        }
        
        try:
            for root, dirs, files in os.walk(workspace_path):
                # Skip Bazel output directories and hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('bazel-') and not d.startswith('.')]
                
                # Limit depth to prevent performance issues
                depth = root[len(workspace_path):].count(os.sep)
                if depth > 5:  # Max 5 levels deep
                    dirs.clear()
                    continue
                
                for file in files:
                    _, ext = os.path.splitext(file.lower())
                    if ext in source_extensions:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, workspace_path)
                        source_files.add(rel_path)
                        
                        # Safety limit to prevent memory issues
                        if len(source_files) > 10000:
                            logger.warning("Emergency scan reached 10k file limit")
                            break
                
                if len(source_files) > 10000:
                    break
            
            logger.info(f"Emergency filesystem scan found {len(source_files)} source files")
            return source_files
            
        except Exception as e:
            logger.error(f"Emergency filesystem scan failed: {e}")
            return set() 