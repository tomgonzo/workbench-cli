# workbench_cli/utilities/bazel_utils_modules/target_mapping.py

import os
import subprocess
import logging
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from .bazel_core import BazelCore
from ...utilities.git_utils import GitUtils
from ...exceptions import ProcessError

logger = logging.getLogger("workbench-cli")

class TargetMapping:
    """
    Handles mapping between Bazel targets and Workbench projects/scans for bzlmod workspaces.
    Provides naming suggestions, metadata generation, and deployment strategies focused on MODULE.bazel versioning.
    """
    
    @staticmethod
    def suggest_project_name(workspace_path: str, target: str = "//...") -> str:
        """
        Suggest a Workbench project name based on bzlmod module and target.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern being scanned
            
        Returns:
            str: Suggested project name
        """
        module_name = BazelCore.get_workspace_name(workspace_path)
        
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
                    return f"{module_name}-{app_name}"
            elif target_clean:
                return f"{module_name}-{target_clean}"
        
        # For full workspace scans, just use module name
        return module_name
    
    @staticmethod
    def suggest_scan_name(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> str:
        """
        Suggest a Workbench scan name using bzlmod-aware versioning.
        Always uses MODULE.bazel version when available, falls back to Git context.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern being scanned
            baseline_commit: Optional baseline commit for incremental scanning
            
        Returns:
            str: Suggested scan name with bzlmod-aware versioning
        """
        return TargetMapping.suggest_scan_name_with_bzlmod(workspace_path, target, baseline_commit)

    @staticmethod
    def suggest_scan_name_with_bzlmod(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> str:
        """
        Enhanced scan name suggestion that prioritizes MODULE.bazel versions for bzlmod projects.
        
        For release versions (e.g., "1.2.3"): Uses module version as primary identifier
        For development versions (e.g., "0.0.0"): Falls back to Git context for differentiation
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern being scanned
            baseline_commit: Optional baseline commit for incremental scanning
            
        Returns:
            str: Suggested scan name with bzlmod-aware versioning
        """
        # Extract target name for scan name
        target_name = "workspace"
        if target != "//...":
            target_clean = target.replace("//", "").replace("/...", "").replace(":", "-")
            if "/" in target_clean:
                target_name = target_clean.split("/")[-1]
            elif target_clean:
                target_name = target_clean
        
        # Always check for MODULE.bazel version first (bzlmod-only approach)
        module_version = BazelCore.get_module_version(workspace_path)
        
        if module_version and not BazelCore.is_development_version(module_version):
            # Use stable module version as primary identifier - most reproducible approach
            if baseline_commit:
                return f"{target_name}-{module_version}-incremental"
            else:
                return f"{target_name}-{module_version}"
        else:
            # For development versions or missing versions, be more MODULE.bazel-centric
            if module_version and BazelCore.is_development_version(module_version):
                # Development version exists - use it as base with Git context for differentiation
                try:
                    git_version = TargetMapping._get_git_version(workspace_path)
                except Exception:
                    # If Git fails, just use the development version itself
                    git_version = "dev"
                
                if baseline_commit:
                    return f"{target_name}-{module_version}-{git_version}-incremental"
                else:
                    return f"{target_name}-{module_version}-{git_version}"
            else:
                # No MODULE.bazel version found - try Git, then fallback to generic
                try:
                    git_version = TargetMapping._get_git_version(workspace_path)
                    if git_version == "dev":  # Our improved fallback
                        # Even with no Git, we can create meaningful names
                        git_version = "workspace"
                except Exception:
                    git_version = "workspace"
                
                if baseline_commit:
                    return f"{target_name}-{git_version}-incremental"
                else:
                    return f"{target_name}-{git_version}"
    
    @staticmethod
    def generate_project_metadata(workspace_path: str, target: str = "//...") -> Dict[str, str]:
        """
        Generate Workbench project metadata from bzlmod module context.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern being scanned
            
        Returns:
            Dict[str, str]: Metadata dictionary with product_code, product_name, description
        """
        module_name = BazelCore.get_workspace_name(workspace_path)
        module_version = BazelCore.get_module_version(workspace_path)
        
        # Product code: Use module name as identifier
        product_code = module_name
        
        # Product name: Derive human-readable name from target
        if target != "//...":
            # Extract application name from target pattern
            target_clean = target.replace("//", "").replace("/...", "").replace(":", "-")
            if "/" in target_clean:
                app_name = target_clean.split("/")[-1]
                product_name = f"{module_name} - {app_name}"
            elif target_clean:
                product_name = f"{module_name} - {target_clean}"
            else:
                product_name = module_name
        else:
            product_name = f"{module_name} module"
        
        # Description: Include bzlmod context
        description_parts = [
            f"Bzlmod module: {module_name}",
            f"Target pattern: {target}"
        ]
        
        if module_version:
            description_parts.insert(1, f"Version: {module_version}")
        
        description = " | ".join(description_parts)
        
        return {
            "product_code": product_code,
            "product_name": product_name,
            "description": description
        }
    
    @staticmethod
    def generate_scan_metadata(workspace_path: str, target: str = "//...", baseline_commit: Optional[str] = None) -> Dict[str, str]:
        """
        Generate Workbench scan metadata from bzlmod and Git context.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern being scanned
            baseline_commit: Optional baseline commit for incremental scanning
            
        Returns:
            Dict[str, str]: Metadata dictionary with description containing Git and module context
        """
        description_parts = []
        
        # Add essential context for incremental scanning
        try:
            # Module version (if available)
            module_version = BazelCore.get_module_version(workspace_path)
            if module_version:
                description_parts.append(f"module_version:{module_version}")
            
            # Current commit hash (essential for incremental scanning)
            current_commit = GitUtils.get_current_commit_hash(workspace_path)
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
            
            # Remove timestamp - not reproducible and not meaningful
            # timestamp = int(time.time())
            # description_parts.append(f"timestamp:{timestamp}")
            
            # Bzlmod marker
            description_parts.append("bzlmod:true")
            
        except Exception as e:
            logger.debug(f"Error generating scan metadata: {e}")
            description_parts.append(f"target:{target}")
            description_parts.append(f"scan_type:{'incremental' if baseline_commit else 'full'}")
            description_parts.append("bzlmod:true")
        
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
                    commit_hash = TargetMapping.extract_baseline_from_scan_description(description)
                    if commit_hash:
                        logger.info(f"Found baseline commit from scan '{scan.get('name')}': {commit_hash}")
                        return commit_hash
                        
        except Exception as e:
            logger.debug(f"Error finding baseline commit from previous scans: {e}")
        
        return None

    @staticmethod
    def discover_scannable_targets(workspace_path: str, query_options: str = "") -> List[Dict[str, Any]]:
        """
        Discover scannable targets in the bzlmod Bazel workspace.
        Includes deployable targets, libraries, tests, and other important code targets.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            query_options: Additional options for bazel query
            
        Returns:
            List[Dict[str, Any]]: List of discovered targets with metadata
        """
        # First try target-agnostic approach (inspired by Black Duck)
        agnostic_targets = TargetMapping._discover_targets_agnostic(workspace_path, query_options)
        if agnostic_targets:
            logger.info(f"Target-agnostic discovery found {len(agnostic_targets)} targets")
            return agnostic_targets
        
        logger.info("Target-agnostic discovery failed, falling back to specific target type queries")
        
        # Fallback to specific target type queries (original approach)
        return TargetMapping._discover_targets_by_type(workspace_path, query_options)
    
    @staticmethod
    def _discover_targets_agnostic(workspace_path: str, query_options: str = "") -> List[Dict[str, Any]]:
        """
        Target-agnostic discovery using `bazel query //...` to find ALL targets.
        This approach doesn't depend on hardcoded target types.
        
        Args:
            workspace_path: Path to the Bazel workspace
            query_options: Additional options for bazel query
            
        Returns:
            List[Dict[str, Any]]: List of discovered targets with metadata
        """
        discovered_targets = []
        
        try:
            # Get all targets in the workspace
            cmd = ['bazel', 'query', '//...']
            if query_options:
                cmd.extend(query_options.split())
            
            logger.debug(f"Running target-agnostic query: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.warning(f"Target-agnostic query failed: {result.stderr.strip()}")
                return []
            
            all_targets = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            logger.info(f"Found {len(all_targets)} total targets using agnostic discovery")
            
            # Now get the kind (type) for each target
            for target in all_targets:
                try:
                    # Query the kind of this specific target
                    kind_cmd = ['bazel', 'query', f'kind(".*", {target})']
                    if query_options:
                        kind_cmd.extend(query_options.split())
                    
                    kind_result = subprocess.run(
                        kind_cmd,
                        cwd=workspace_path,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if kind_result.returncode == 0 and kind_result.stdout.strip():
                        # Parse target kind from output like "kt_android_library rule //app:lib"
                        output_line = kind_result.stdout.strip()
                        if ' rule ' in output_line:
                            kind = output_line.split(' rule ')[0].strip()
                        else:
                            # Fallback parsing
                            parts = output_line.split()
                            kind = parts[0] if parts else "unknown"
                        
                        category = TargetMapping._categorize_target_kind_agnostic(kind)
                        
                        discovered_targets.append({
                            "target": target,
                            "kind": kind,
                            "category": category,
                            "suggested_project": TargetMapping.suggest_project_name(workspace_path, target),
                            "suggested_scan": TargetMapping.suggest_scan_name(workspace_path, target)
                        })
                        
                        logger.debug(f"Discovered target: {target} ({kind}) -> {category}")
                    else:
                        logger.debug(f"Could not determine kind for target: {target}")
                        
                except Exception as e:
                    logger.debug(f"Failed to get kind for target {target}: {e}")
                    continue
            
            # Sort by category priority
            category_priority = {
                "executable": 1, "library": 2, "test": 3, "container": 4,
                "proto": 5, "web": 6, "tool": 7, "platform": 8, "other": 9
            }
            
            discovered_targets.sort(key=lambda x: (
                category_priority.get(x["category"], 99),
                x["target"]
            ))
            
            return discovered_targets
            
        except subprocess.TimeoutExpired:
            logger.warning("Target-agnostic discovery timed out")
            return []
        except Exception as e:
            logger.warning(f"Target-agnostic discovery failed: {e}")
            return []
    
    @staticmethod
    def _categorize_target_kind_agnostic(kind: str) -> str:
        """
        Categorize a target kind using heuristics rather than hardcoded lists.
        This is more flexible for unknown/custom target types.
        
        Args:
            kind: Target kind/rule name
            
        Returns:
            str: Category name
        """
        kind_lower = kind.lower()
        
        # Heuristic-based categorization
        if any(keyword in kind_lower for keyword in ['binary', 'application', 'app', 'main', 'executable']):
            return "executable"
        elif any(keyword in kind_lower for keyword in ['library', 'lib']):
            return "library"
        elif any(keyword in kind_lower for keyword in ['test', 'spec']):
            return "test"
        elif any(keyword in kind_lower for keyword in ['image', 'container', 'docker', 'oci']):
            return "container"
        elif any(keyword in kind_lower for keyword in ['proto', 'grpc']):
            return "proto"
        elif any(keyword in kind_lower for keyword in ['web', 'js', 'ts', 'html', 'css']):
            return "web"
        elif any(keyword in kind_lower for keyword in ['platform', 'config', 'constraint']):
            return "platform"
        elif any(keyword in kind_lower for keyword in ['tool', 'gen', 'rule']):
            return "tool"
        else:
            return "other"
    
    @staticmethod
    def _discover_targets_by_type(workspace_path: str, query_options: str = "") -> List[Dict[str, Any]]:
        """
        Original target discovery approach using specific target type queries.
        Kept as fallback when agnostic approach fails.
        """
        # Comprehensive target kinds that contain source code worth scanning
        target_categories = {
            # Deployable/Executable targets (highest priority)
            "executable": [
                "py_binary", "java_binary", "go_binary", "cc_binary", "rust_binary",
                "sh_binary", "scala_binary", "kt_jvm_binary", "nodejs_binary",
                "android_binary", "kt_android_binary", "ios_application",
            ],
            
            # Container and deployment targets
            "container": [
                "container_image", "oci_image", "docker_image",
                "py_image", "java_image", "go_image", "cc_image", "rust_image",
                "k8s_deploy", "helm_chart",
            ],
            
            # Library targets (very important for security scanning)
            "library": [
                "cc_library", "py_library", "java_library", "go_library", "rust_library",
                "scala_library", "kt_jvm_library", "kt_android_library", "ts_library", "js_library",
                "objc_library", "swift_library", "android_library", "ios_framework",
                "py_extension", "pyx_library",
            ],
            
            # Test targets (contain important code)
            "test": [
                "cc_test", "py_test", "java_test", "go_test", "rust_test",
                "scala_test", "kt_jvm_test", "kt_android_test", "kt_android_local_test", 
                "sh_test", "nodejs_test", "android_instrumentation_test", "ios_unit_test",
            ],
            
            # Proto and data definition targets
            "proto": [
                "proto_library", "cc_proto_library", "py_proto_library",
                "java_proto_library", "go_proto_library", "rust_proto_library",
                "grpc_proto_library",
            ],
            
            # Web and frontend targets
            "web": [
                "ts_project", "js_binary", "web_bundle", "rollup_bundle",
                "webpack_bundle", "ng_module", "sass_binary",
            ],
            
            # Build and tooling targets
            "tool": [
                "genrule", "sh_binary", "py_binary", "java_binary",
                # Include custom rules that might contain source
                "_*_binary", "_*_library", "_*_test",  # Custom rule patterns
            ]
        }
        
        discovered_targets = []
        
        # Query each category of targets
        for category, kinds in target_categories.items():
            for kind in kinds:
                try:
                    # Handle wildcard patterns for custom rules
                    if "*" in kind:
                        # For custom rule patterns, we'd need a more sophisticated query
                        # Skip for now, but could be enhanced later
                        continue
                    
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
                                "category": category,
                                "suggested_project": TargetMapping.suggest_project_name(workspace_path, target),
                                "suggested_scan": TargetMapping.suggest_scan_name(workspace_path, target)
                            })
                            
                except Exception as e:
                    logger.debug(f"Failed to query kind {kind}: {e}")
                    continue
        
        # Sort by priority: executable > library > test > container > proto > web > tool
        category_priority = {
            "executable": 1,
            "library": 2, 
            "test": 3,
            "container": 4,
            "proto": 5,
            "web": 6,
            "tool": 7
        }
        
        discovered_targets.sort(key=lambda x: (
            category_priority.get(x["category"], 99),  # Priority by category
            x["target"]  # Then alphabetically
        ))
        
        return discovered_targets
    
    @staticmethod
    def estimate_scan_scope(workspace_path: str, target: str = "//...", query_options: str = "") -> Dict[str, Any]:
        """
        Estimate the scope of a Bazel scan before running it.
        Useful for onboarding and planning.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            target: Bazel target pattern to analyze
            query_options: Additional options for bazel query
            
        Returns:
            Dict[str, Any]: Estimation results
        """
        from .scan_discovery import ScanDiscovery  # Avoid circular import
        
        estimation = {
            "target_pattern": target,
            "targets_found": 0,
            "estimated_files": 0,
            "estimated_size_mb": 0,
            "packages_involved": set(),
            "external_deps_found": False,
            "recommended_approach": "full_scan",
            "bzlmod": True  # Always true for this bzlmod-only tool
        }
        
        try:
            # Count targets
            targets = ScanDiscovery.query_all_targets(workspace_path, target, query_options)
            estimation["targets_found"] = len(targets)
            
            # Estimate packages involved
            for target in targets:
                if "//" in target:
                    package = target.split("//")[1].split(":")[0]
                    if package:
                        estimation["packages_involved"].add(package)
            
            estimation["packages_involved"] = list(estimation["packages_involved"])
            
            # Quick file count estimation using fallback method
            source_files = ScanDiscovery._get_target_sources_fallback(workspace_path, targets[:10])  # Sample first 10 targets
            if source_files:
                # Extrapolate based on sample
                avg_files_per_target = len(source_files) / min(10, len(targets))
                estimation["estimated_files"] = int(avg_files_per_target * len(targets))
                
                # Rough size estimation (assume 10KB average file size)
                estimation["estimated_size_mb"] = round((estimation["estimated_files"] * 10) / 1024, 1)
            
            # Check for external dependencies
            estimation["external_deps_found"] = BazelCore.has_external_dependencies(workspace_path)
            
            # Add module-specific info
            module_version = BazelCore.get_module_version(workspace_path)
            if module_version:
                estimation["module_version"] = module_version
                estimation["is_development"] = BazelCore.is_development_version(module_version)
            
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
    def suggest_project_scan_strategy(workspace_path: str) -> Dict[str, Any]:
        """
        Analyze bzlmod workspace and suggest optimal Project and Scan organization strategy.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            Dict[str, Any]: Strategy recommendations with project/scan mapping suggestions
        """
        module_name = BazelCore.get_workspace_name(workspace_path)
        module_version = BazelCore.get_module_version(workspace_path)
        is_dev_version = BazelCore.is_development_version(module_version) if module_version else True
        
        # Discover deployable targets to understand workspace structure
        try:
            deployable_targets = TargetMapping.discover_scannable_targets(workspace_path)
            target_count = len(deployable_targets)
        except Exception:
            deployable_targets = []
            target_count = 0
        
        strategy = {
            "workspace_analysis": {
                "name": module_name,
                "module_version": module_version,
                "is_development_version": is_dev_version,
                "deployable_targets": target_count,
                "is_bzlmod": True  # Always true for this tool
            },
            "recommendations": {}
        }
        
        # Determine optimal strategy based on workspace characteristics
        if target_count <= 1:
            # Single application workspace
            strategy["recommendations"] = {
                "strategy": "single_project",
                "description": "Single Workbench Project for the entire module",
                "project_mapping": {
                    "approach": "module_level",
                    "suggested_project_name": module_name,
                    "rationale": "Simple module with one main application"
                },
                "scan_mapping": {
                    "approach": "version_based" if module_version and not is_dev_version else "hybrid",
                    "suggested_scan_pattern": TargetMapping._get_scan_pattern(module_name, module_version, is_dev_version),
                    "rationale": TargetMapping._get_scan_rationale(module_version, is_dev_version)
                }
            }
        elif target_count <= 5:
            # Multi-application workspace (small) - APPLICATION-FOCUSED
            strategy["recommendations"] = {
                "strategy": "per_application_projects",
                "description": "Separate Workbench Project for each logical application",
                "project_mapping": {
                    "approach": "application_based",
                    "suggested_projects": [
                        {
                            "target": target["target"], 
                            "suggested_name": TargetMapping.suggest_project_name(workspace_path, target["target"]),
                            "category": target["category"]
                        } 
                        for target in deployable_targets[:5]  # Limit display
                    ],
                    "rationale": "Each application gets its own project for independent lifecycle management"
                },
                "scan_mapping": {
                    "approach": "version_based" if module_version and not is_dev_version else "hybrid",
                    "suggested_scan_pattern": TargetMapping._get_scan_pattern("APPLICATION", module_version, is_dev_version),
                    "rationale": TargetMapping._get_scan_rationale(module_version, is_dev_version)
                }
            }
        elif target_count <= 20:
            # Medium workspace - MODULE with TARGET GROUPS
            strategy["recommendations"] = {
                "strategy": "module_with_target_groups",
                "description": "Single Project per module, with Scans for logical target groups",
                "project_mapping": {
                    "approach": "module_level",
                    "suggested_project_name": module_name,
                    "rationale": f"Medium-sized module with {target_count} targets - group related targets for manageable scanning"
                },
                "scan_mapping": {
                    "approach": "target_group_based",
                    "suggested_scan_pattern": f"{module_name}-{{TARGET_GROUP}}-{{VERSION}}",
                    "example_groups": [
                        f"{module_name}-executables-{module_version or 'v1.0.0'}",
                        f"{module_name}-libraries-{module_version or 'v1.0.0'}",
                        f"{module_name}-tests-{module_version or 'v1.0.0'}"
                    ],
                    "rationale": "Group similar targets (executables, libraries, tests) for balanced granularity"
                },
                "alternative": {
                    "strategy": "per_target_scans",
                    "description": "If you need maximum granularity, consider individual target scanning",
                    "rationale": "For precise vulnerability tracking and parallel scanning workflows"
                }
            }
        else:
            # Large workspace - MODULE with PER-TARGET SCANS (your proposal!)
            strategy["recommendations"] = {
                "strategy": "module_with_per_target_scans",
                "description": "Single Project per module, with individual Scans per target",
                "project_mapping": {
                    "approach": "module_level",
                    "suggested_project_name": module_name,
                    "rationale": f"Large module with {target_count} targets - requires granular per-target scanning"
                },
                "scan_mapping": {
                    "approach": "per_target",
                    "suggested_scan_pattern": f"{module_name}-{{TARGET_NAME}}-{{VERSION}}",
                    "examples": [
                        f"{module_name}-{TargetMapping._extract_target_name(target['target'])}-{module_version or 'v1.0.0'}"
                        for target in deployable_targets[:3]  # Show examples
                    ] if deployable_targets else [],
                    "rationale": "Maximum granularity for precise vulnerability tracking and parallel scanning",
                    "benefits": [
                        "Precise per-component vulnerability tracking",
                        "Parallel scanning capabilities",
                        "Incremental scanning (only changed targets)",
                        "Clear separation of security concerns"
                    ],
                    "considerations": [
                        f"Will create ~{target_count} scans - ensure your team can manage this scale",
                        "Consider automation for scan creation and monitoring",
                        "May want to start with critical targets and expand gradually"
                    ]
                },
                "alternative": {
                    "strategy": "staged_onboarding",
                    "description": "Alternative: Start with high-priority targets, expand gradually",
                    "rationale": "Reduce initial complexity while building scanning maturity"
                }
            }
        
        # Always include bzlmod-specific recommendations (since this is bzlmod-only)
        strategy["bzlmod_recommendations"] = {
            "version_strategy": "Use MODULE.bazel versions for stable releases" if module_version and not is_dev_version else "Combine MODULE.bazel + Git for development",
            "benefits": [
                "Semantic versioning alignment with Bazel Central Registry",
                "Clear separation between development and release scans", 
                "Reduced re-scanning for stable versions",
                "Better integration with Bazel's dependency resolution",
                "Automatic transitive dependency handling"
            ],
            "implementation": {
                "stable_versions": "Create new scans only when MODULE.bazel version changes",
                "development_versions": "Use Git context for differentiation during development",
                "lockfile_usage": "Leverage MODULE.bazel.lock for reproducible dependency resolution"
            }
        }
        
        return strategy

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
    def _get_git_version(workspace_path: str) -> str:
        """
        Get a version string from Git context.
        
        Args:
            workspace_path: Path to the workspace
            
        Returns:
            str: Version string derived from Git
        """
        git_info = GitUtils.get_git_version_info(workspace_path)
        
        # Try tag first
        if git_info["tag"]:
            return git_info["tag"]
        
        # Fall back to commit hash with branch context
        if git_info["short_commit"]:
            branch = git_info["branch"]
            commit_hash = git_info["short_commit"]
            
            if branch and branch not in ["main", "master"]:
                return f"{branch}-{commit_hash}"
            return commit_hash
        
        # Better fallback: use MODULE.bazel context instead of timestamp
        try:
            module_version = BazelCore.get_module_version(workspace_path)
            if module_version:
                # Even if Git is unavailable, MODULE.bazel version is meaningful
                return module_version
        except Exception:
            pass
        
        # Last resort: generic development indicator (no timestamps)
        return "dev"
    
    @staticmethod
    def _get_scan_pattern(prefix: str, module_version: Optional[str], is_dev_version: bool) -> str:
        """Helper function to generate scan naming pattern examples."""
        if module_version and not is_dev_version:
            return f"{prefix}-{{MODULE_VERSION}} (e.g., {prefix}-{module_version})"
        elif module_version and is_dev_version:
            return f"{prefix}-{{MODULE_VERSION}}-{{GIT_CONTEXT}} (e.g., {prefix}-{module_version}-v1.2.3)"
        else:
            return f"{prefix}-{{GIT_CONTEXT}} (e.g., {prefix}-v1.2.3 or {prefix}-main-abc123)"

    @staticmethod
    def _get_scan_rationale(module_version: Optional[str], is_dev_version: bool) -> str:
        """Helper function to generate scan strategy rationale."""
        if module_version and not is_dev_version:
            return "Stable MODULE.bazel versions provide clear release boundaries"
        elif module_version and is_dev_version:
            return "Development versions need Git context for differentiation between iterations"
        else:
            return "Git context provides version tracking when MODULE.bazel version is not set"
    
    @staticmethod
    def _extract_target_name(target_label: str) -> str:
        """
        Extract a clean target name from a Bazel target label for scan naming.
        
        Examples:
            //apps/frontend:bin -> frontend-bin
            //libs/auth:auth_lib -> auth-auth_lib  
            //:main -> main
            
        Args:
            target_label: Bazel target label (e.g., "//apps/frontend:bin")
            
        Returns:
            str: Clean target name suitable for scan naming
        """
        if not target_label or not target_label.startswith('//'):
            return "unknown-target"
        
        # Remove // prefix
        clean_label = target_label[2:]
        
        if ':' in clean_label:
            # Split package and target name
            package, target_name = clean_label.rsplit(':', 1)
            if package:
                # Convert //apps/frontend:bin -> apps-frontend-bin
                package_clean = package.replace('/', '-')
                return f"{package_clean}-{target_name}"
            else:
                # Root package //:main -> main
                return target_name
        else:
            # No target specified, use package name
            return clean_label.replace('/', '-') 