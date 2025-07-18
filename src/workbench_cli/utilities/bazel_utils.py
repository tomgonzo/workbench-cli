# workbench_cli/utilities/bazel_utils.py

import os
import subprocess
import logging
from typing import Set, List, Tuple, Optional, Dict, Any
from pathlib import Path
from ..exceptions import ValidationError, WorkbenchCLIError, ProcessError

logger = logging.getLogger("workbench-cli")

class BazelUtils:
    """
    Utility class for Bazel workspace operations, query execution, and file detection.
    Inspired by Black Duck's Bazel analysis approach but tailored for Workbench's scanning workflow.
    """
    
    # Bazel workspace marker files
    WORKSPACE_FILES = ['WORKSPACE', 'WORKSPACE.bazel', 'MODULE.bazel']
    
    # Common files to exclude from scanning
    DEFAULT_EXCLUSIONS = {
        'bazel-*',      # Bazel symlinks (bazel-bin, bazel-out, etc.)
        '.git',         # Git directory
        'BUILD',        # BUILD files (metadata, not source)
        'BUILD.bazel',  # BUILD.bazel files (metadata, not source)
        'WORKSPACE',    # WORKSPACE files (metadata, not source)
        'MODULE.bazel', # MODULE.bazel files (metadata, not source)
        '.bazelrc',     # Bazel configuration
        '.bazelversion', # Bazel version file
    }
    
    @staticmethod
    def check_bazel_installation() -> Tuple[bool, str]:
        """
        Check if Bazel is installed and accessible.
        
        Returns:
            Tuple[bool, str]: (is_available, version_or_error_message)
        """
        try:
            result = subprocess.run(
                ['bazel', '--version'], 
                capture_output=True, 
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.debug(f"Bazel found: {version}")
                return True, version
            else:
                error_msg = f"Bazel command failed: {result.stderr.strip()}"
                logger.error(error_msg)
                return False, error_msg
        except subprocess.TimeoutExpired:
            error_msg = "Bazel command timed out"
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = "Bazel not found in PATH. Please install Bazel and ensure it's in your PATH."
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error checking Bazel: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    @staticmethod
    def detect_bazel_workspace(directory_path: str) -> Tuple[bool, Optional[str]]:
        """
        Detect if a directory is a Bazel workspace.
        
        Args:
            directory_path: Path to check for Bazel workspace
            
        Returns:
            Tuple[bool, Optional[str]]: (is_workspace, workspace_file_found)
        """
        if not os.path.isdir(directory_path):
            return False, None
            
        for workspace_file in BazelUtils.WORKSPACE_FILES:
            workspace_path = os.path.join(directory_path, workspace_file)
            if os.path.exists(workspace_path):
                logger.debug(f"Found Bazel workspace file: {workspace_path}")
                return True, workspace_file
                
        return False, None
    
    @staticmethod
    def get_workspace_name(workspace_path: str) -> str:
        """
        Extract workspace name from Bazel workspace files.
        
        Args:
            workspace_path: Path to the Bazel workspace directory
            
        Returns:
            str: Workspace name (falls back to directory name if not found)
        """
        workspace_dir = Path(workspace_path).resolve()
        
        # Try to find workspace name from MODULE.bazel first (modern Bazel)
        module_bazel = workspace_dir / "MODULE.bazel"
        if module_bazel.exists():
            try:
                with open(module_bazel, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('module('):
                            # Extract name from module(name = "...", ...)
                            if 'name' in line:
                                parts = line.split('name')
                                if len(parts) > 1:
                                    name_part = parts[1].split('=', 1)
                                    if len(name_part) > 1:
                                        name_value = name_part[1].strip()
                                        # Remove quotes and extract the name
                                        name_value = name_value.strip('",\'').split(',')[0].strip('",\'')
                                        if name_value:
                                            return name_value
            except Exception as e:
                logger.debug(f"Could not parse MODULE.bazel: {e}")
        
        # Try WORKSPACE file
        for workspace_file in ['WORKSPACE', 'WORKSPACE.bazel']:
            workspace_file_path = workspace_dir / workspace_file
            if workspace_file_path.exists():
                try:
                    with open(workspace_file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('workspace('):
                                # Extract name from workspace(name = "...")
                                if 'name' in line:
                                    parts = line.split('name')
                                    if len(parts) > 1:
                                        name_part = parts[1].split('=', 1)
                                        if len(name_part) > 1:
                                            name_value = name_part[1].strip()
                                            # Remove quotes and extract the name
                                            name_value = name_value.strip('",\'').split(',')[0].strip('",\'')
                                            if name_value:
                                                return name_value
                except Exception as e:
                    logger.debug(f"Could not parse {workspace_file}: {e}")
        
        # Fall back to directory name
        return workspace_dir.name
    
    @staticmethod
    def get_changed_files(workspace_path: str, baseline_commit: str) -> Set[str]:
        """
        Get files changed since the baseline commit using git diff.
        
        Args:
            workspace_path: Path to the Bazel workspace
            baseline_commit: Git commit hash to compare against
            
        Returns:
            Set[str]: Set of changed file paths relative to workspace
            
        Raises:
            ProcessError: If git command fails
        """
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', baseline_commit],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                raise ProcessError(f"Git diff failed: {result.stderr.strip()}")
            
            changed_files = set(result.stdout.strip().splitlines())
            logger.debug(f"Found {len(changed_files)} changed files since {baseline_commit}")
            return changed_files
            
        except subprocess.TimeoutExpired:
            raise ProcessError("Git diff command timed out")
        except FileNotFoundError:
            raise ProcessError("Git not found in PATH")
        except Exception as e:
            raise ProcessError(f"Failed to get changed files: {e}")
    
    @staticmethod
    def query_affected_targets(workspace_path: str, changed_files: Set[str], target: str = "//...", query_options: str = "") -> List[str]:
        """
        Use Bazel query to find targets affected by changed files.
        
        Args:
            workspace_path: Path to the Bazel workspace
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
            return BazelUtils.query_all_targets(workspace_path, target, query_options)
        
        # Build the query to find reverse dependencies of changed files
        # We need to be careful with the query syntax
        files_list = ','.join(f'"{f}"' for f in changed_files if f)
        if not files_list:
            logger.debug("No valid changed files for query, querying all targets")
            return BazelUtils.query_all_targets(workspace_path, target, query_options)
        
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
                return BazelUtils.query_all_targets(workspace_path, target, query_options)
            
            targets = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            logger.debug(f"Found {len(targets)} affected targets")
            return targets
            
        except subprocess.TimeoutExpired:
            logger.warning("Bazel query timed out, falling back to all targets")
            return BazelUtils.query_all_targets(workspace_path, target, query_options)
        except Exception as e:
            logger.warning(f"Bazel query failed: {e}, falling back to all targets")
            return BazelUtils.query_all_targets(workspace_path, target, query_options)
    
    @staticmethod
    def query_all_targets(workspace_path: str, target: str = "//...", query_options: str = "") -> List[str]:
        """
        Query all targets in the workspace.
        
        Args:
            workspace_path: Path to the Bazel workspace
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
        Get source files for the given Bazel targets.
        
        Args:
            workspace_path: Path to the Bazel workspace
            targets: List of target labels
            query_options: Additional options for bazel query
            
        Returns:
            Set[str]: Set of source file paths relative to workspace
            
        Raises:
            ProcessError: If Bazel query fails
        """
        if not targets:
            return set()
        
        # For better results, let's use the fallback approach directly
        # which focuses on actual workspace source files
        return BazelUtils._get_target_sources_fallback(workspace_path, targets)
    
    @staticmethod
    def _get_target_sources_fallback(workspace_path: str, targets: List[str]) -> Set[str]:
        """
        Fallback method to get source files by walking the filesystem.
        
        Args:
            workspace_path: Path to the Bazel workspace
            targets: List of target labels (used to determine directories to scan)
            
        Returns:
            Set[str]: Set of source file paths relative to workspace
        """
        source_files = set()
        
        # Extract package paths from targets
        packages = set()
        for target in targets:
            logger.debug(f"Processing target: {target}")
            if '//' in target:
                package_part = target.split('//')[1].split(':')[0]
                if package_part:
                    packages.add(package_part)
                    logger.debug(f"Added package: {package_part}")
                else:
                    packages.add('.')  # Root package
                    logger.debug("Added root package (.)")
        
        # If no specific packages, scan everything
        if not packages:
            packages.add('.')
            logger.debug("No packages found, adding root package (.)")
        
        logger.debug(f"Scanning packages: {packages}")
        
        for package in packages:
            package_path = os.path.join(workspace_path, package) if package != '.' else workspace_path
            logger.debug(f"Scanning package path: {package_path}")
            
            if os.path.exists(package_path) and os.path.isdir(package_path):
                files_found_in_package = 0
                for root, dirs, files in os.walk(package_path):
                    # Skip Bazel output directories
                    dirs[:] = [d for d in dirs if not d.startswith('bazel-')]
                    logger.debug(f"Walking directory: {root}, found {len(files)} files")
                    
                    for file in files:
                        files_found_in_package += 1
                        file_path = os.path.join(root, file)
                        logger.debug(f"Checking file: {file_path}")
                        
                        if not BazelUtils._should_exclude_file(file_path):
                            rel_path = os.path.relpath(file_path, workspace_path)
                            source_files.add(rel_path)
                            logger.debug(f"Added source file: {rel_path}")
                        else:
                            logger.debug(f"Excluded file: {file_path}")
                
                logger.debug(f"Package {package}: found {files_found_in_package} total files")
            else:
                logger.debug(f"Package path does not exist or is not a directory: {package_path}")
        
        logger.info(f"Fallback method found {len(source_files)} source files: {list(source_files)[:10]}")
        return source_files
    
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
        for exclusion in BazelUtils.DEFAULT_EXCLUSIONS:
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
    def get_files_to_scan(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None, query_options: str = "") -> Set[str]:
        """
        Main entry point to get the set of files to scan.
        
        Args:
            workspace_path: Path to the Bazel workspace
            target: Bazel target pattern to analyze
            baseline_commit: Optional baseline commit for incremental scanning
            query_options: Additional options for bazel query
            
        Returns:
            Set[str]: Set of file paths relative to workspace that should be scanned
            
        Raises:
            ProcessError: If Bazel operations fail
            ValidationError: If workspace is invalid
        """
        # Validate workspace
        is_workspace, workspace_file = BazelUtils.detect_bazel_workspace(workspace_path)
        if not is_workspace:
            raise ValidationError(f"Not a valid Bazel workspace: {workspace_path}")
        
        logger.info(f"Analyzing Bazel workspace: {workspace_path}")
        logger.info(f"Target pattern: {target}")
        
        if baseline_commit:
            logger.info(f"Incremental scan from baseline: {baseline_commit}")
            # Get changed files and affected targets
            changed_files = BazelUtils.get_changed_files(workspace_path, baseline_commit)
            if not changed_files:
                logger.info("No files changed since baseline commit")
                return set()
            
            affected_targets = BazelUtils.query_affected_targets(workspace_path, changed_files, target, query_options)
            if not affected_targets:
                logger.info("No targets affected by changes")
                return set()
            
            source_files = BazelUtils.get_target_sources(workspace_path, affected_targets, query_options)
        else:
            logger.info("Full workspace scan")
            # Get all targets and their sources
            all_targets = BazelUtils.query_all_targets(workspace_path, target, query_options)
            source_files = BazelUtils.get_target_sources(workspace_path, all_targets, query_options)
        
        logger.info(f"Selected {len(source_files)} files for scanning")
        return source_files 
    
    @staticmethod
    def suggest_project_name(workspace_path: str, target: str = "//...") -> str:
        """
        Suggest a Workbench project name based on Bazel workspace and target.
        
        Args:
            workspace_path: Path to the Bazel workspace
            target: Bazel target pattern being scanned
            
        Returns:
            str: Suggested project name
        """
        workspace_name = BazelUtils.get_workspace_name(workspace_path)
        
        # For specific target patterns, derive application name
        if target != "//...":
            # Extract application name from target pattern
            # //apps/frontend/... -> "frontend"
            # //services/api/... -> "api"
            target_clean = target.replace("//", "").replace("/...", "").replace(":", "-")
            if "/" in target_clean:
                # Take the last part as the application name
                app_name = target_clean.split("/")[-1]
                if app_name:
                    return f"{workspace_name}-{app_name}"
            elif target_clean:
                return f"{workspace_name}-{target_clean}"
        
        # For full workspace scans, just use workspace name
        return workspace_name
    
    @staticmethod
    def suggest_scan_name(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> str:
        """
        Suggest a Workbench scan name based on target and Git context.
        
        Args:
            workspace_path: Path to the Bazel workspace
            target: Bazel target pattern being scanned
            baseline_commit: Optional baseline commit for incremental scanning
            
        Returns:
            str: Suggested scan name
        """
        try:
            # Try to get Git version info
            git_version = BazelUtils._get_git_version(workspace_path)
        except Exception:
            git_version = "unknown"
        
        # Extract target name for scan name
        target_name = "workspace"
        if target != "//...":
            target_clean = target.replace("//", "").replace("/...", "").replace(":", "-")
            if "/" in target_clean:
                target_name = target_clean.split("/")[-1]
            elif target_clean:
                target_name = target_clean
        
        # Build scan name based on scan type
        if baseline_commit:
            return f"{target_name}-incremental-{git_version}"
        else:
            return f"{target_name}-{git_version}"
    
    @staticmethod
    def _get_git_version(workspace_path: str) -> str:
        """
        Get a version string from Git context.
        
        Args:
            workspace_path: Path to the workspace
            
        Returns:
            str: Version string derived from Git
        """
        try:
            # Try to get a Git tag first
            result = subprocess.run(
                ['git', 'describe', '--tags', '--exact-match', 'HEAD'],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        try:
            # Fall back to commit hash
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                commit_hash = result.stdout.strip()
                
                # Try to get branch name for context
                try:
                    branch_result = subprocess.run(
                        ['git', 'branch', '--show-current'],
                        cwd=workspace_path,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if branch_result.returncode == 0:
                        branch = branch_result.stdout.strip()
                        if branch and branch != "main" and branch != "master":
                            return f"{branch}-{commit_hash}"
                except Exception:
                    pass
                
                return commit_hash
        except Exception:
            pass
        
        # Last resort: timestamp
        import time
        return f"scan-{int(time.time())}"
    
    @staticmethod
    def discover_deployable_targets(workspace_path: str, query_options: str = "") -> List[Dict[str, Any]]:
        """
        Discover deployable targets in the Bazel workspace.
        These are good candidates for initial scanning.
        
        Args:
            workspace_path: Path to the Bazel workspace
            query_options: Additional options for bazel query
            
        Returns:
            List[Dict[str, Any]]: List of discovered targets with metadata
        """
        deployable_kinds = [
            "py_binary", "java_binary", "go_binary", "cc_binary", "rust_binary",
            "sh_binary", "scala_binary", "kt_jvm_binary", "nodejs_binary",
            "container_image", "oci_image", "docker_image",
            "py_image", "java_image", "go_image", "cc_image", "rust_image",
            "k8s_deploy", "helm_chart", "android_binary", "ios_application"
        ]
        
        discovered_targets = []
        
        for kind in deployable_kinds:
            try:
                cmd = ['bazel', 'query', f'kind("{kind}", //...)']
                if query_options:
                    cmd.extend(query_options.split())
                
                result = subprocess.run(
                    cmd,
                    cwd=workspace_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    targets = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
                    for target in targets:
                        discovered_targets.append({
                            "target": target,
                            "kind": kind,
                            "category": BazelUtils._categorize_target_kind(kind),
                            "suggested_project": BazelUtils.suggest_project_name(workspace_path, target),
                            "suggested_scan": BazelUtils.suggest_scan_name(workspace_path, target)
                        })
                        
            except Exception as e:
                logger.debug(f"Failed to query kind {kind}: {e}")
                continue
        
        # Sort by category and target name for better presentation
        discovered_targets.sort(key=lambda x: (x["category"], x["target"]))
        return discovered_targets
    
    @staticmethod
    def _categorize_target_kind(kind: str) -> str:
        """
        Categorize a Bazel target kind for better organization.
        
        Args:
            kind: Bazel rule kind
            
        Returns:
            str: Category name
        """
        if "binary" in kind:
            return "application"
        elif "image" in kind:
            return "container"
        elif kind in ["k8s_deploy", "helm_chart"]:
            return "deployment"
        elif kind in ["android_binary", "ios_application"]:
            return "mobile"
        else:
            return "other"
    
    @staticmethod
    def estimate_scan_scope(workspace_path: str, target: str = "//...", query_options: str = "") -> Dict[str, Any]:
        """
        Estimate the scope of a Bazel scan before running it.
        Useful for onboarding and planning.
        
        Args:
            workspace_path: Path to the Bazel workspace
            target: Bazel target pattern to analyze
            query_options: Additional options for bazel query
            
        Returns:
            Dict[str, Any]: Estimation results
        """
        estimation = {
            "target_pattern": target,
            "targets_found": 0,
            "estimated_files": 0,
            "estimated_size_mb": 0,
            "packages_involved": set(),
            "external_deps_found": False,
            "recommended_approach": "full_scan"
        }
        
        try:
            # Count targets
            targets = BazelUtils.query_all_targets(workspace_path, target, query_options)
            estimation["targets_found"] = len(targets)
            
            # Estimate packages involved
            for target in targets:
                if "//" in target:
                    package = target.split("//")[1].split(":")[0]
                    if package:
                        estimation["packages_involved"].add(package)
            
            estimation["packages_involved"] = list(estimation["packages_involved"])
            
            # Quick file count estimation using fallback method
            source_files = BazelUtils._get_target_sources_fallback(workspace_path, targets[:10])  # Sample first 10 targets
            if source_files:
                # Extrapolate based on sample
                avg_files_per_target = len(source_files) / min(10, len(targets))
                estimation["estimated_files"] = int(avg_files_per_target * len(targets))
                
                # Rough size estimation (assume 10KB average file size)
                estimation["estimated_size_mb"] = round((estimation["estimated_files"] * 10) / 1024, 1)
            
            # Check for external dependencies
            estimation["external_deps_found"] = BazelUtils._has_external_dependencies(workspace_path)
            
            # Recommend approach based on size
            if estimation["targets_found"] > 100 or estimation["estimated_files"] > 10000:
                estimation["recommended_approach"] = "staged_onboarding"
            elif estimation["targets_found"] > 20:
                estimation["recommended_approach"] = "targeted_scan"
            
        except Exception as e:
            logger.warning(f"Failed to estimate scan scope: {e}")
            estimation["error"] = str(e)
        
        return estimation
    
    @staticmethod
    def _has_external_dependencies(workspace_path: str) -> bool:
        """
        Check if the workspace has external dependencies.
        
        Args:
            workspace_path: Path to the Bazel workspace
            
        Returns:
            bool: True if external dependencies are detected
        """
        # Check for WORKSPACE file with http_archive, git_repository, etc.
        for workspace_file in BazelUtils.WORKSPACE_FILES:
            workspace_file_path = os.path.join(workspace_path, workspace_file)
            if os.path.exists(workspace_file_path):
                try:
                    with open(workspace_file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if any(keyword in content for keyword in [
                            'http_archive', 'git_repository', 'maven_install', 
                            'go_repository', 'npm_install', 'pip_install'
                        ]):
                            return True
                except Exception:
                    pass
        
        return False 
    
    @staticmethod
    def generate_project_metadata(workspace_path: str, target: str = "//...") -> Dict[str, str]:
        """
        Generate Workbench project metadata from Bazel workspace context.
        
        Args:
            workspace_path: Path to the Bazel workspace
            target: Bazel target pattern being scanned
            
        Returns:
            Dict[str, str]: Metadata dictionary with product_code, product_name, description
        """
        workspace_name = BazelUtils.get_workspace_name(workspace_path)
        
        # Product code: Use workspace name as identifier
        product_code = workspace_name
        
        # Product name: Derive human-readable name from target
        if target != "//...":
            # Extract application name from target pattern
            target_clean = target.replace("//", "").replace("/...", "").replace(":", "-")
            if "/" in target_clean:
                app_name = target_clean.split("/")[-1]
                product_name = f"{workspace_name} - {app_name}"
            elif target_clean:
                product_name = f"{workspace_name} - {target_clean}"
            else:
                product_name = workspace_name
        else:
            product_name = f"{workspace_name} workspace"
        
        # Description: Keep minimal for better readability
        description_parts = [
            f"Bazel workspace: {workspace_name}",
            f"Target pattern: {target}"
        ]
        
        description = " | ".join(description_parts)
        
        return {
            "product_code": product_code,
            "product_name": product_name,
            "description": description
        }
    
    @staticmethod
    def generate_scan_metadata(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> Dict[str, str]:
        """
        Generate Workbench scan metadata from Bazel and Git context.
        
        Args:
            workspace_path: Path to the Bazel workspace
            target: Bazel target pattern being scanned
            baseline_commit: Optional baseline commit for incremental scanning
            
        Returns:
            Dict[str, str]: Metadata dictionary with description containing Git context
        """
        description_parts = []
        
        # Add essential context for incremental scanning
        try:
            # Current commit hash (essential for incremental scanning)
            current_commit = BazelUtils._get_current_commit_hash(workspace_path)
            if current_commit:
                description_parts.append(f"commit:{current_commit}")
            
            # Baseline commit for incremental scanning
            if baseline_commit:
                description_parts.append(f"baseline:{baseline_commit}")
                description_parts.append(f"scan_type:incremental")
            else:
                description_parts.append(f"scan_type:full")
            
            # Target pattern
            description_parts.append(f"target:{target}")
            
            # Timestamp for tracking
            import time
            timestamp = int(time.time())
            description_parts.append(f"timestamp:{timestamp}")
            
        except Exception as e:
            logger.debug(f"Error generating scan metadata: {e}")
            description_parts.append(f"target:{target}")
            description_parts.append(f"scan_type:{'incremental' if baseline_commit else 'full'}")
        
        description = " | ".join(description_parts)
        
        return {
            "description": description
        }
    
    @staticmethod
    def extract_baseline_from_scan_description(description: str) -> Optional[str]:
        """
        Extract baseline commit hash from a scan description for incremental scanning.
        
        Args:
            description: Scan description containing metadata
            
        Returns:
            Optional[str]: Baseline commit hash if found, None otherwise
        """
        if not description:
            return None
        
        # Look for commit:hash pattern
        import re
        commit_match = re.search(r'commit:([a-f0-9]+)', description)
        if commit_match:
            return commit_match.group(1)
        
        return None
    
    @staticmethod
    def _get_git_remote_url(workspace_path: str) -> Optional[str]:
        """Get the Git remote URL for the workspace."""
        try:
            result = subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    @staticmethod
    def _get_current_commit_hash(workspace_path: str) -> Optional[str]:
        """Get the current Git commit hash."""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    @staticmethod
    def _get_current_branch(workspace_path: str) -> Optional[str]:
        """Get the current Git branch name."""
        try:
            result = subprocess.run(
                ['git', 'branch', '--show-current'],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                branch = result.stdout.strip()
                return branch if branch else None
        except Exception:
            pass
        return None
    
    @staticmethod
    def find_baseline_commit_from_previous_scans(workbench_api, project_name: str) -> Optional[str]:
        """
        Find a suitable baseline commit from previous scans in the same project.
        Useful for automatic baseline detection in incremental scanning.
        
        Args:
            workbench_api: Workbench API client instance
            project_name: Name of the project to search
            
        Returns:
            Optional[str]: Most recent commit hash from previous scans, None if not found
        """
        try:
            # Get project code
            project_code = workbench_api.resolve_project(project_name, create_if_missing=False)
            
            # Get all scans in the project
            scans = workbench_api.get_project_scans(project_code)
            
            if not scans:
                return None
            
            # Sort scans by creation time (newest first)
            scans_sorted = sorted(scans, key=lambda x: x.get('id', 0), reverse=True)
            
            # Look for the most recent scan with a commit hash
            for scan in scans_sorted:
                description = scan.get('description', '')
                if description:
                    commit_hash = BazelUtils.extract_baseline_from_scan_description(description)
                    if commit_hash:
                        logger.info(f"Found baseline commit from scan '{scan.get('name')}': {commit_hash}")
                        return commit_hash
                        
        except Exception as e:
            logger.debug(f"Error finding baseline commit from previous scans: {e}")
        
        return None