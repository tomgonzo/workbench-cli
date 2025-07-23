# workbench_cli/utilities/bazel_utils_modules/bazel_core.py

import os
import subprocess
import logging
from typing import Tuple, Optional, Dict, Any, List
from pathlib import Path
from ...exceptions import ValidationError

logger = logging.getLogger("workbench-cli")

class BazelCore:
    """
    Core Bazel interactions focused on modern bzlmod (MODULE.bazel) approach.
    Provides installation checking, workspace detection, and metadata extraction.
    """
    
    # Only support MODULE.bazel for bzlmod workspaces
    WORKSPACE_FILES = ['MODULE.bazel']
    
    # Reasonable defaults and limits for robust operation
    DEFAULT_TIMEOUTS = {
        'quick_check': 10,      # Quick operations like version check
        'standard_query': 30,   # Standard Bazel queries
        'complex_query': 60,    # Complex queries like dependencies
        'resolution': 180,      # Dependency resolution operations
        'emergency': 15         # Emergency fallback operations
    }
    
    DEFAULT_LIMITS = {
        'max_targets': 1000,    # Maximum targets to process in one operation
        'max_files': 10000,     # Maximum files in emergency scan
        'max_depth': 5,         # Maximum directory depth for filesystem scans
        'batch_size': 10,       # Batch size for target processing
        'retry_count': 3        # Number of retries for failed operations
    }
    
    # Environment validation thresholds
    MIN_REQUIREMENTS = {
        'min_free_space_mb': 100,   # Minimum free disk space in MB
        'max_file_size_mb': 50,     # Maximum individual file size in MB  
        'max_workspace_depth': 10   # Maximum workspace nesting depth
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
        Detect if a directory is a bzlmod Bazel workspace by checking for MODULE.bazel.
        
        Args:
            directory_path: Path to check for Bazel workspace
            
        Returns:
            Tuple[bool, Optional[str]]: (is_workspace, workspace_file_found)
        """
        if not os.path.isdir(directory_path):
            return False, None
            
        module_bazel_path = os.path.join(directory_path, 'MODULE.bazel')
        if os.path.exists(module_bazel_path):
            logger.debug(f"Found bzlmod workspace: {module_bazel_path}")
            return True, 'MODULE.bazel'
                
        return False, None
    
    @staticmethod
    def get_workspace_name(workspace_path: str) -> str:
        """
        Extract module name from MODULE.bazel file.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace directory
            
        Returns:
            str: Module name (falls back to directory name if not found)
            
        Raises:
            ValidationError: If MODULE.bazel file is not found
        """
        workspace_dir = Path(workspace_path).resolve()
        module_bazel = workspace_dir / "MODULE.bazel"
        
        if not module_bazel.exists():
            raise ValidationError(f"No MODULE.bazel found in bzlmod workspace: {workspace_path}")
        
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
                                        logger.debug(f"Found module name in MODULE.bazel: {name_value}")
                                        return name_value
        except Exception as e:
            logger.warning(f"Could not parse MODULE.bazel: {e}")
        
        # Fall back to directory name
        fallback_name = workspace_dir.name
        logger.debug(f"Using directory name as fallback: {fallback_name}")
        return fallback_name

    @staticmethod
    def get_module_version(workspace_path: str) -> Optional[str]:
        """
        Extract module version from MODULE.bazel file for bzlmod-based version tracking.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace directory
            
        Returns:
            Optional[str]: Module version if found in MODULE.bazel, None otherwise
        """
        workspace_dir = Path(workspace_path).resolve()
        module_bazel = workspace_dir / "MODULE.bazel"
        
        if not module_bazel.exists():
            logger.debug("No MODULE.bazel file found")
            return None
            
        try:
            with open(module_bazel, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Look for module() declaration with version
                import re
                # Match: module(name = "...", version = "...")
                # Handles multi-line declarations and different quote styles
                module_match = re.search(
                    r'module\s*\(\s*[^)]*?version\s*=\s*["\']([^"\']+)["\']', 
                    content, 
                    re.MULTILINE | re.DOTALL
                )
                
                if module_match:
                    version = module_match.group(1).strip()
                    logger.debug(f"Found MODULE.bazel version: {version}")
                    return version
                else:
                    logger.debug("No version found in MODULE.bazel")
                    
        except Exception as e:
            logger.debug(f"Could not parse MODULE.bazel for version: {e}")
            
        return None

    @staticmethod
    def is_development_version(version: str) -> bool:
        """
        Determine if a module version indicates development/unstable code.
        
        Args:
            version: Version string from MODULE.bazel
            
        Returns:
            bool: True if this appears to be a development version
        """
        if not version:
            return True
            
        # Common patterns for development versions
        dev_patterns = [
            '0.0.0',           # Placeholder version
            '0.0',             # Short placeholder
            'dev',             # Explicit dev marker
            'snapshot',        # Maven-style snapshot
            'alpha',           # Pre-release
            'beta',            # Pre-release
            'rc',              # Release candidate
            'HEAD',            # HEAD pointer
            'main',            # Branch name
            'master',          # Branch name
        ]
        
        version_lower = version.lower()
        
        # Check exact matches
        if version_lower in dev_patterns:
            return True
            
        # Check if version contains development markers
        if any(pattern in version_lower for pattern in dev_patterns):
            return True
            
        # Check for snapshot-style versioning (e.g., "1.2.3-SNAPSHOT")
        if '-' in version_lower and any(suffix in version_lower.split('-')[-1] 
                                       for suffix in ['snapshot', 'dev', 'alpha', 'beta', 'rc']):
            return True
            
        return False
    
    @staticmethod
    def get_output_base(workspace_path: str) -> Optional[str]:
        """
        Get Bazel's output_base directory where external dependencies are stored.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            Optional[str]: Path to output_base, or None if not found
        """
        try:
            result = subprocess.run(
                ['bazel', 'info', 'output_base'],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output_base = result.stdout.strip()
                logger.debug(f"Bazel output_base: {output_base}")
                return output_base
            else:
                logger.warning(f"Failed to get output_base: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            logger.warning("Bazel info output_base timed out")
        except Exception as e:
            logger.warning(f"Failed to get output_base: {e}")
        
        return None

    @staticmethod
    def validate_workspace(workspace_path: str) -> None:
        """
        Validate that the given path is a valid bzlmod Bazel workspace.
        
        Args:
            workspace_path: Path to validate
            
        Raises:
            ValidationError: If workspace is invalid or not bzlmod
        """
        is_workspace, workspace_file = BazelCore.detect_bazel_workspace(workspace_path)
        if not is_workspace:
            # Check if legacy WORKSPACE exists and provide helpful error
            legacy_files = ['WORKSPACE', 'WORKSPACE.bazel']
            for legacy_file in legacy_files:
                if os.path.exists(os.path.join(workspace_path, legacy_file)):
                    raise ValidationError(
                        f"Found legacy {legacy_file} file. This tool only supports modern bzlmod workspaces with MODULE.bazel. "
                        f"Please migrate to bzlmod: https://bazel.build/external/migration"
                    )
            
            raise ValidationError(f"Not a valid bzlmod Bazel workspace: {workspace_path}. Expected MODULE.bazel file.")
        
        logger.debug(f"Validated bzlmod workspace: {workspace_path} (found {workspace_file})")

    @staticmethod
    def has_external_dependencies(workspace_path: str) -> bool:
        """
        Check if the bzlmod workspace has external dependencies.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            bool: True if bzlmod dependencies are detected
        """
        module_bazel_path = os.path.join(workspace_path, "MODULE.bazel")
        if not os.path.exists(module_bazel_path):
            return False
        
        try:
            with open(module_bazel_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Check for bzlmod dependency patterns
                bzlmod_patterns = [
                    'bazel_dep(',           # Direct Bazel module dependencies
                    'use_extension(',       # Module extensions (rules_rust, rules_python, etc.)
                    '.spec(',               # Dependency specifications (crate.spec, pip.parse, etc.)
                    'maven.install(',       # Maven dependencies
                    'npm.npm_translate_lock(',  # NPM dependencies
                    'go_deps.from_file(',   # Go dependencies
                ]
                if any(pattern in content for pattern in bzlmod_patterns):
                    logger.debug("Found bzlmod dependencies in MODULE.bazel")
                    return True
        except Exception as e:
            logger.debug(f"Could not parse MODULE.bazel: {e}")
        
        return False

    @staticmethod
    def get_module_lockfile_info(workspace_path: str) -> Optional[Dict[str, Any]]:
        """
        Parse MODULE.bazel.lock for resolved dependency information.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            Optional[Dict[str, Any]]: Lockfile information if available
        """
        lockfile_path = os.path.join(workspace_path, "MODULE.bazel.lock")
        if not os.path.exists(lockfile_path):
            logger.debug("No MODULE.bazel.lock file found")
            return None
            
        try:
            import json
            with open(lockfile_path, 'r', encoding='utf-8') as f:
                lockfile_data = json.load(f)
                logger.debug(f"Found MODULE.bazel.lock with {len(lockfile_data.get('modules', {}))} resolved modules")
                return lockfile_data
        except Exception as e:
            logger.warning(f"Could not parse MODULE.bazel.lock: {e}")
            return None

    @staticmethod
    def get_module_extensions(workspace_path: str) -> List[str]:
        """
        Extract module extensions used (for dependency analysis).
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            List[str]: List of module extensions found
        """
        module_bazel_path = os.path.join(workspace_path, "MODULE.bazel")
        if not os.path.exists(module_bazel_path):
            return []
        
        extensions = []
        try:
            with open(module_bazel_path, 'r', encoding='utf-8') as f:
                import re
                content = f.read()
                
                # Find use_extension() calls
                extension_matches = re.findall(
                    r'use_extension\s*\(\s*["\']([^"\']+)["\']', 
                    content
                )
                
                extensions.extend(extension_matches)
                logger.debug(f"Found {len(extensions)} module extensions: {extensions}")
                
        except Exception as e:
            logger.warning(f"Could not parse MODULE.bazel for extensions: {e}")
        
        return extensions
    
    @staticmethod
    def get_lockfile_info(workspace_path: str) -> Dict[str, Any]:
        """
        Parse MODULE.bazel.lock for resolved dependency information.
        This provides the exact resolved versions that bzlmod chose.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            Dict[str, Any]: Lockfile information including resolved modules and extensions
        """
        lockfile_path = os.path.join(workspace_path, "MODULE.bazel.lock")
        if not os.path.exists(lockfile_path):
            logger.debug("No MODULE.bazel.lock file found")
            return {}
        
        try:
            import json
            with open(lockfile_path, 'r', encoding='utf-8') as f:
                lockfile_data = json.load(f)
                
            # Extract key information for dependency analysis
            resolved_info = {
                "lockfile_version": lockfile_data.get("lockFileVersion", "unknown"),
                "module_count": 0,
                "extension_count": 0,
                "resolved_modules": {},
                "module_extensions": {}
            }
            
            # Parse resolved modules
            if "moduleDepGraph" in lockfile_data:
                modules = lockfile_data["moduleDepGraph"]
                resolved_info["module_count"] = len(modules)
                
                for module_key, module_data in modules.items():
                    if isinstance(module_data, dict):
                        resolved_info["resolved_modules"][module_key] = {
                            "version": module_data.get("version", "unknown"),
                            "repo_name": module_data.get("repoName", module_key)
                        }
            
            # Parse module extensions
            if "moduleExtensions" in lockfile_data:
                extensions = lockfile_data["moduleExtensions"]
                resolved_info["extension_count"] = len(extensions)
                resolved_info["module_extensions"] = extensions
            
            logger.debug(f"Parsed lockfile: {resolved_info['module_count']} modules, {resolved_info['extension_count']} extensions")
            return resolved_info
            
        except Exception as e:
            logger.warning(f"Could not parse MODULE.bazel.lock: {e}")
            return {}
    
    @staticmethod
    def detect_dev_dependencies(workspace_path: str) -> List[str]:
        """
        Detect development-only dependencies in MODULE.bazel.
        These might be excluded from production scans.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            List[str]: List of development dependency names
        """
        module_bazel_path = os.path.join(workspace_path, "MODULE.bazel")
        if not os.path.exists(module_bazel_path):
            return []
        
        dev_deps = []
        try:
            with open(module_bazel_path, 'r', encoding='utf-8') as f:
                import re
                content = f.read()
                
                # Find bazel_dep() calls with dev_dependency = True
                dev_dep_matches = re.findall(
                    r'bazel_dep\s*\([^)]*?name\s*=\s*["\']([^"\']+)["\'][^)]*?dev_dependency\s*=\s*True[^)]*?\)', 
                    content,
                    re.MULTILINE | re.DOTALL
                )
                
                dev_deps.extend(dev_dep_matches)
                
                # Also check reverse order (dev_dependency before name)
                dev_dep_matches_rev = re.findall(
                    r'bazel_dep\s*\([^)]*?dev_dependency\s*=\s*True[^)]*?name\s*=\s*["\']([^"\']+)["\'][^)]*?\)', 
                    content,
                    re.MULTILINE | re.DOTALL
                )
                
                dev_deps.extend(dev_dep_matches_rev)
                logger.debug(f"Found {len(dev_deps)} development dependencies: {dev_deps}")
                
        except Exception as e:
            logger.warning(f"Could not parse MODULE.bazel for dev dependencies: {e}")
        
        return dev_deps 
    
    @staticmethod
    def validate_environment(workspace_path: str) -> Dict[str, Any]:
        """
        Validate the environment for safe and reliable Bazel operations.
        
        Args:
            workspace_path: Path to the bzlmod Bazel workspace
            
        Returns:
            Dict[str, Any]: Validation results with recommendations
        """
        validation_results = {
            "is_valid": True,
            "warnings": [],
            "errors": [],
            "recommendations": [],
            "resource_status": {}
        }
        
        try:
            # Check disk space
            disk_status = BazelCore._check_disk_space(workspace_path)
            validation_results["resource_status"]["disk"] = disk_status
            
            if disk_status["free_mb"] < BazelCore.MIN_REQUIREMENTS["min_free_space_mb"]:
                validation_results["errors"].append(f"Insufficient disk space: {disk_status['free_mb']}MB available, {BazelCore.MIN_REQUIREMENTS['min_free_space_mb']}MB required")
                validation_results["is_valid"] = False
            elif disk_status["free_mb"] < 500:  # Warning threshold
                validation_results["warnings"].append(f"Low disk space: {disk_status['free_mb']}MB available")
                validation_results["recommendations"].append("Consider freeing up disk space before large scans")
            
            # Check workspace depth
            workspace_depth = BazelCore._check_workspace_depth(workspace_path)
            validation_results["resource_status"]["workspace_depth"] = workspace_depth
            
            if workspace_depth > BazelCore.MIN_REQUIREMENTS["max_workspace_depth"]:
                validation_results["warnings"].append(f"Deep workspace nesting: {workspace_depth} levels")
                validation_results["recommendations"].append("Consider using emergency filesystem scan for performance")
            
            # Check workspace size
            workspace_size = BazelCore._estimate_workspace_size(workspace_path)
            validation_results["resource_status"]["workspace_size"] = workspace_size
            
            if workspace_size["file_count"] > 50000:
                validation_results["warnings"].append(f"Large workspace: {workspace_size['file_count']} files")
                validation_results["recommendations"].append("Consider using target-specific scans instead of full workspace")
            
            # Check Bazel accessibility with retries
            bazel_status = BazelCore._check_bazel_with_retries(workspace_path)
            validation_results["resource_status"]["bazel"] = bazel_status
            
            if not bazel_status["accessible"]:
                validation_results["errors"].append(f"Bazel not accessible: {bazel_status['error']}")
                validation_results["is_valid"] = False
            elif bazel_status["version_mismatch"]:
                validation_results["warnings"].append(f"Bazel version mismatch: {bazel_status['details']}")
                validation_results["recommendations"].append("Consider using emergency filesystem scan if Bazel queries fail")
            
            # Overall health assessment
            if len(validation_results["errors"]) == 0 and len(validation_results["warnings"]) <= 2:
                validation_results["health_score"] = "excellent"
            elif len(validation_results["errors"]) == 0:
                validation_results["health_score"] = "good"
            elif len(validation_results["errors"]) <= 2:
                validation_results["health_score"] = "poor"
            else:
                validation_results["health_score"] = "critical"
                
        except Exception as e:
            validation_results["errors"].append(f"Environment validation failed: {e}")
            validation_results["is_valid"] = False
            validation_results["health_score"] = "unknown"
        
        return validation_results
    
    @staticmethod
    def _check_disk_space(workspace_path: str) -> Dict[str, Any]:
        """Check available disk space in the workspace directory."""
        try:
            import shutil
            total, used, free = shutil.disk_usage(workspace_path)
            return {
                "total_mb": total // (1024 * 1024),
                "used_mb": used // (1024 * 1024),
                "free_mb": free // (1024 * 1024),
                "usage_percent": (used / total) * 100 if total > 0 else 0
            }
        except Exception as e:
            return {"error": str(e), "free_mb": 0}
    
    @staticmethod
    def _check_workspace_depth(workspace_path: str) -> int:
        """Check the maximum nesting depth of the workspace."""
        try:
            max_depth = 0
            for root, dirs, files in os.walk(workspace_path):
                # Skip Bazel output directories
                dirs[:] = [d for d in dirs if not d.startswith('bazel-')]
                
                depth = root[len(workspace_path):].count(os.sep)
                max_depth = max(max_depth, depth)
                
                # Early exit if we hit a reasonable limit
                if max_depth > 15:
                    break
                    
            return max_depth
        except Exception:
            return 0
    
    @staticmethod
    def _estimate_workspace_size(workspace_path: str) -> Dict[str, Any]:
        """Estimate workspace size for performance planning."""
        try:
            file_count = 0
            total_size = 0
            
            for root, dirs, files in os.walk(workspace_path):
                # Skip Bazel output directories and hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('bazel-') and not d.startswith('.')]
                
                for file in files:
                    file_count += 1
                    try:
                        file_path = os.path.join(root, file)
                        total_size += os.path.getsize(file_path)
                    except (OSError, IOError):
                        pass  # Skip files we can't access
                    
                    # Safety limit to prevent long scans
                    if file_count > 100000:
                        break
                        
                if file_count > 100000:
                    break
            
            return {
                "file_count": file_count,
                "total_size_mb": total_size // (1024 * 1024),
                "estimated": file_count >= 100000
            }
        except Exception as e:
            return {"error": str(e), "file_count": 0, "total_size_mb": 0}
    
    @staticmethod
    def _check_bazel_with_retries(workspace_path: str) -> Dict[str, Any]:
        """Check Bazel accessibility with retry logic."""
        result = {
            "accessible": False,
            "version_mismatch": False,
            "details": "",
            "error": ""
        }
        
        for attempt in range(BazelCore.DEFAULT_LIMITS["retry_count"]):
            try:
                # Try basic version check first
                version_result = subprocess.run(
                    ['bazel', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=BazelCore.DEFAULT_TIMEOUTS["quick_check"]
                )
                
                if version_result.returncode == 0:
                    result["accessible"] = True
                    result["details"] = version_result.stdout.strip()
                    
                    # Check for version conflicts in the workspace
                    try:
                        workspace_check = subprocess.run(
                            ['bazel', 'info', 'release'],
                            cwd=workspace_path,
                            capture_output=True,
                            text=True,
                            timeout=BazelCore.DEFAULT_TIMEOUTS["quick_check"]
                        )
                        
                        if workspace_check.returncode != 0:
                            result["version_mismatch"] = True
                            result["details"] += f" | Workspace error: {workspace_check.stderr.strip()[:100]}"
                        
                    except Exception:
                        # Workspace-specific check failed, but Bazel itself works
                        result["version_mismatch"] = True
                        result["details"] += " | Workspace compatibility unknown"
                    
                    return result
                else:
                    result["error"] = version_result.stderr.strip()
                    
            except subprocess.TimeoutExpired:
                result["error"] = f"Bazel command timed out (attempt {attempt + 1})"
            except FileNotFoundError:
                result["error"] = "Bazel not found in PATH"
                break  # No point in retrying this
            except Exception as e:
                result["error"] = f"Unexpected error: {e}"
            
            # Brief pause between retries
            if attempt < BazelCore.DEFAULT_LIMITS["retry_count"] - 1:
                import time
                time.sleep(0.5)
        
        return result 