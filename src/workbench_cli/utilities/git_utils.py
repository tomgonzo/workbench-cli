# workbench_cli/utilities/git_utils.py

import os
import logging
import re
from typing import Set, List, Optional, Dict, Any
from pathlib import Path
from ..exceptions import ValidationError, ProcessError

try:
    from git import Repo, InvalidGitRepositoryError, GitCommandError, BadName
    from git.objects import Commit
except ImportError:
    raise ImportError(
        "GitPython is required but not installed. Please install it with: pip install GitPython"
    )

logger = logging.getLogger("workbench-cli")


class GitUtils:
    """
    Utility class for Git operations using GitPython.
    Provides functionality for commit tracking, file diffing, and scan metadata management.
    """
    
    # Git commit hash patterns
    COMMIT_HASH_PATTERN = re.compile(r'^[a-f0-9]{7,40}$')
    SHORT_COMMIT_LENGTH = 7
    
    @staticmethod
    def is_git_repository(directory_path: str) -> bool:
        """
        Check if a directory is a Git repository.
        
        Args:
            directory_path: Path to check for Git repository
            
        Returns:
            bool: True if directory is a Git repository
        """
        if not os.path.isdir(directory_path):
            return False
        
        try:
            Repo(directory_path)
            return True
        except InvalidGitRepositoryError:
            return False
    
    @staticmethod
    def get_repo(workspace_path: str) -> Repo:
        """
        Get a GitPython Repo object for the workspace.
        
        Args:
            workspace_path: Path to the Git repository
            
        Returns:
            Repo: GitPython repository object
            
        Raises:
            ValidationError: If directory is not a Git repository
        """
        if not GitUtils.is_git_repository(workspace_path):
            raise ValidationError(f"Directory is not a Git repository: {workspace_path}")
        
        try:
            return Repo(workspace_path)
        except InvalidGitRepositoryError as e:
            raise ValidationError(f"Invalid Git repository: {e}")
    
    @staticmethod
    def get_current_commit_hash(workspace_path: str, short: bool = False) -> Optional[str]:
        """
        Get the current Git commit hash.
        
        Args:
            workspace_path: Path to the Git repository
            short: If True, return short commit hash (7 chars)
            
        Returns:
            Optional[str]: Current commit hash, or None if not available
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            commit_hash = repo.head.commit.hexsha
            
            if short:
                commit_hash = commit_hash[:GitUtils.SHORT_COMMIT_LENGTH]
                
            logger.debug(f"Current commit: {commit_hash}")
            return commit_hash
            
        except (ValidationError, GitCommandError) as e:
            logger.warning(f"Failed to get current commit: {e}")
            return None
    
    @staticmethod
    def get_current_branch(workspace_path: str) -> Optional[str]:
        """
        Get the current Git branch name.
        
        Args:
            workspace_path: Path to the Git repository
            
        Returns:
            Optional[str]: Current branch name, or None if in detached HEAD
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            
            # Check if HEAD is detached
            if repo.head.is_detached:
                logger.debug("Repository is in detached HEAD state")
                return None
                
            branch = repo.active_branch.name
            logger.debug(f"Current branch: {branch}")
            return branch
            
        except (ValidationError, GitCommandError) as e:
            logger.debug(f"Could not determine current branch: {e}")
            return None
    
    @staticmethod
    def get_remote_url(workspace_path: str, remote: str = "origin") -> Optional[str]:
        """
        Get the Git remote URL.
        
        Args:
            workspace_path: Path to the Git repository
            remote: Remote name (default: "origin")
            
        Returns:
            Optional[str]: Remote URL, or None if not available
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            
            if remote in repo.remotes:
                url = repo.remotes[remote].url
                logger.debug(f"Remote URL ({remote}): {url}")
                return url
            else:
                logger.debug(f"Remote '{remote}' not found")
                return None
                
        except (ValidationError, GitCommandError) as e:
            logger.warning(f"Failed to get remote URL: {e}")
            return None
    
    @staticmethod
    def validate_commit_hash(commit_hash: str) -> bool:
        """
        Validate if a string is a valid Git commit hash format.
        
        Args:
            commit_hash: String to validate
            
        Returns:
            bool: True if valid commit hash format
        """
        if not commit_hash:
            return False
        return bool(GitUtils.COMMIT_HASH_PATTERN.match(commit_hash.lower()))
    
    @staticmethod
    def commit_exists(workspace_path: str, commit_hash: str) -> bool:
        """
        Check if a commit exists in the repository.
        
        Args:
            workspace_path: Path to the Git repository
            commit_hash: Commit hash to check
            
        Returns:
            bool: True if commit exists
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            repo.commit(commit_hash)  # This will raise an exception if commit doesn't exist
            return True
        except (ValidationError, GitCommandError, BadName):
            return False
    
    @staticmethod
    def get_changed_files_since_commit(
        workspace_path: str, 
        baseline_commit: str, 
        include_untracked: bool = False
    ) -> Set[str]:
        """
        Get files changed since the baseline commit.
        
        Args:
            workspace_path: Path to the Git repository
            baseline_commit: Git commit hash to compare against
            include_untracked: Whether to include untracked files
            
        Returns:
            Set[str]: Set of file paths relative to workspace that have changed
            
        Raises:
            ValidationError: If not a Git repository or invalid commit
            ProcessError: If Git operation fails
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            
            # Validate that the baseline commit exists
            if not GitUtils.commit_exists(workspace_path, baseline_commit):
                raise ValidationError(f"Baseline commit does not exist: {baseline_commit}")
            
            # Get the baseline commit object
            baseline_commit_obj = repo.commit(baseline_commit)
            
            # Get changed files using GitPython's diff
            changed_files = set()
            
            # Compare baseline with current HEAD
            for diff_item in baseline_commit_obj.diff(None):  # None means HEAD
                # Handle renamed files
                if diff_item.a_path:
                    changed_files.add(diff_item.a_path)
                if diff_item.b_path and diff_item.b_path != diff_item.a_path:
                    changed_files.add(diff_item.b_path)
            
            # Include untracked files if requested
            if include_untracked:
                untracked_files = repo.untracked_files
                changed_files.update(untracked_files)
            
            logger.info(f"Found {len(changed_files)} changed files since {baseline_commit}")
            if changed_files:
                logger.debug(f"Changed files: {list(changed_files)[:10]}{'...' if len(changed_files) > 10 else ''}")
            
            return changed_files
            
        except ValidationError:
            raise  # Re-raise validation errors
        except (GitCommandError, BadName) as e:
            raise ProcessError(f"Git operation failed: {e}")
        except Exception as e:
            raise ProcessError(f"Unexpected error during Git diff: {e}")
    
    @staticmethod
    def get_current_tag(workspace_path: str) -> Optional[str]:
        """
        Get the current Git tag if HEAD is at a tagged commit.
        
        Args:
            workspace_path: Path to the Git repository
            
        Returns:
            Optional[str]: Tag name if HEAD is at a tagged commit, None otherwise
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            
            # Get tags that point to the current HEAD
            head_commit = repo.head.commit
            tags_at_head = [tag for tag in repo.tags if tag.commit == head_commit]
            
            if tags_at_head:
                # Return the most recent tag if multiple tags point to HEAD
                tag_name = tags_at_head[-1].name
                logger.debug(f"Current tag: {tag_name}")
                return tag_name
            
            return None
            
        except (ValidationError, GitCommandError) as e:
            logger.debug(f"Could not determine current tag: {e}")
            return None
    
    @staticmethod
    def find_merge_base(workspace_path: str, commit1: str, commit2: str = "HEAD") -> Optional[str]:
        """
        Find the merge base (common ancestor) between two commits.
        
        Args:
            workspace_path: Path to the Git repository
            commit1: First commit hash or ref
            commit2: Second commit hash or ref (default: HEAD)
            
        Returns:
            Optional[str]: Merge base commit hash, or None if not found
        """
        try:
            repo = GitUtils.get_repo(workspace_path)
            
            commit1_obj = repo.commit(commit1)
            commit2_obj = repo.commit(commit2)
            
            # Find merge base using GitPython
            merge_bases = repo.merge_base(commit1_obj, commit2_obj)
            
            if merge_bases:
                merge_base = merge_bases[0].hexsha
                logger.debug(f"Merge base between {commit1} and {commit2}: {merge_base}")
                return merge_base
            
            return None
            
        except (ValidationError, GitCommandError, BadName) as e:
            logger.debug(f"Could not find merge base: {e}")
            return None
    
    @staticmethod
    def get_git_version_info(workspace_path: str) -> Dict[str, Optional[str]]:
        """
        Get comprehensive Git version information for a repository.
        
        Args:
            workspace_path: Path to the Git repository
            
        Returns:
            Dict with keys: commit, short_commit, branch, tag, remote_url
        """
        info = {
            "commit": None,
            "short_commit": None,
            "branch": None,
            "tag": None,
            "remote_url": None
        }
        
        if not GitUtils.is_git_repository(workspace_path):
            return info
        
        try:
            # Get commit information
            info["commit"] = GitUtils.get_current_commit_hash(workspace_path, short=False)
            info["short_commit"] = GitUtils.get_current_commit_hash(workspace_path, short=True)
            
            # Get branch information
            info["branch"] = GitUtils.get_current_branch(workspace_path)
            
            # Get tag information
            info["tag"] = GitUtils.get_current_tag(workspace_path)
            
            # Get remote URL
            info["remote_url"] = GitUtils.get_remote_url(workspace_path)
            
        except Exception as e:
            logger.debug(f"Error gathering Git version info: {e}")
        
        return info
    
    @staticmethod
    def create_scan_description_with_commit(
        current_commit: str,
        baseline_commit: Optional[str] = None,
        target: Optional[str] = None,
        scan_type: str = "incremental",
        additional_info: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Create a scan description that includes commit information for incremental scanning.
        
        Args:
            current_commit: Current commit hash being scanned
            baseline_commit: Optional baseline commit for incremental scans
            target: Optional target pattern or identifier
            scan_type: Type of scan (full, incremental, delta)
            additional_info: Optional additional key-value pairs to include
            
        Returns:
            str: Formatted scan description
        """
        description_parts = []
        
        # Current commit (essential for incremental scanning)
        if current_commit:
            description_parts.append(f"commit:{current_commit}")
        
        # Baseline commit for incremental scanning
        if baseline_commit:
            description_parts.append(f"baseline:{baseline_commit}")
        
        # Target information
        if target:
            description_parts.append(f"target:{target}")
        
        # Scan type
        description_parts.append(f"scan_type:{scan_type}")
        
        # Additional information
        if additional_info:
            for key, value in additional_info.items():
                if value:
                    description_parts.append(f"{key}:{value}")
        
        return " | ".join(description_parts)
    
    @staticmethod
    def extract_commit_from_scan_description(description: str) -> Optional[str]:
        """
        Extract commit hash from a scan description for incremental scanning.
        
        Args:
            description: Scan description to parse
            
        Returns:
            Optional[str]: Commit hash if found, None otherwise
        """
        if not description:
            return None
        
        # Look for commit:hash pattern
        commit_match = re.search(r'commit:([a-f0-9]+)', description)
        if commit_match:
            commit_hash = commit_match.group(1)
            if GitUtils.validate_commit_hash(commit_hash):
                return commit_hash
        
        return None
    
    @staticmethod
    def extract_baseline_from_scan_description(description: str) -> Optional[str]:
        """
        Extract baseline commit hash from a scan description.
        
        Args:
            description: Scan description to parse
            
        Returns:
            Optional[str]: Baseline commit hash if found, None otherwise
        """
        if not description:
            return None
        
        # Look for baseline:hash pattern
        baseline_match = re.search(r'baseline:([a-f0-9]+)', description)
        if baseline_match:
            baseline_hash = baseline_match.group(1)
            if GitUtils.validate_commit_hash(baseline_hash):
                return baseline_hash
        
        return None
    
    # Integration Helper Functions for Scan Handlers
    
    @staticmethod
    def setup_incremental_scan_from_existing(
        workbench_api,
        workspace_path: str,
        scan_code: str,
        target: str = "//..."
    ) -> Optional[str]:
        """
        Setup incremental scan by checking existing scan description for baseline commit.
        
        Args:
            workbench_api: Workbench API instance
            workspace_path: Path to the Git repository  
            scan_code: Existing scan code to check
            target: Target pattern being scanned
            
        Returns:
            Optional[str]: Baseline commit hash if incremental scan is possible, None for full scan
        """
        try:
            # Get existing scan information
            scan_info = workbench_api.get_scan_information(scan_code)
            existing_description = scan_info.get('description', '')
            
            if existing_description:
                # Try to extract commit from existing description
                baseline_commit = GitUtils.extract_commit_from_scan_description(existing_description)
                
                if baseline_commit:
                    logger.info(f"Found previous scan baseline: {baseline_commit}")
                    
                    # Validate that the baseline commit still exists in the repository
                    if GitUtils.commit_exists(workspace_path, baseline_commit):
                        logger.info("Setting up incremental scan from existing baseline")
                        return baseline_commit
                    else:
                        logger.warning(f"Baseline commit {baseline_commit} no longer exists in repository")
                        
            logger.info("No valid baseline found, performing full scan")
            return None
            
        except Exception as e:
            logger.warning(f"Failed to setup incremental scan: {e}")
            logger.info("Falling back to full scan")
            return None
    
    @staticmethod
    def update_scan_with_current_commit(
        workbench_api,
        workspace_path: str,
        scan_code: str,
        target: str = "//...",
        scan_type: str = "incremental",
        baseline_commit: Optional[str] = None
    ) -> bool:
        """
        Update scan description with current commit information after successful scan.
        
        Args:
            workbench_api: Workbench API instance
            workspace_path: Path to the Git repository
            scan_code: Scan code to update
            target: Target pattern that was scanned
            scan_type: Type of scan performed
            baseline_commit: Baseline commit used for incremental scans
            
        Returns:
            bool: True if update was successful
        """
        try:
            current_commit = GitUtils.get_current_commit_hash(workspace_path)
            if not current_commit:
                logger.warning("Could not get current commit hash, skipping scan description update")
                return False
            
            # Get additional Git context
            git_info = GitUtils.get_git_version_info(workspace_path)
            additional_info = {}
            
            if git_info["branch"]:
                additional_info["branch"] = git_info["branch"]
            if git_info["tag"]:
                additional_info["tag"] = git_info["tag"]
            if git_info["remote_url"]:
                additional_info["repo"] = git_info["remote_url"]
            
            # Create updated description
            description = GitUtils.create_scan_description_with_commit(
                current_commit=current_commit,
                baseline_commit=baseline_commit,
                target=target,
                scan_type=scan_type,
                additional_info=additional_info
            )
            
            # Update the scan
            workbench_api.update_scan(scan_code, description=description)
            logger.info(f"Updated scan description with commit: {current_commit}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to update scan with commit information: {e}")
            return False
    
    @staticmethod
    def get_delta_files_for_scan(
        workspace_path: str,
        baseline_commit: Optional[str] = None,
        include_untracked: bool = False
    ) -> Optional[Set[str]]:
        """
        Get changed files for delta scanning. Can be used with --scan-delta flag.
        
        Args:
            workspace_path: Path to the Git repository
            baseline_commit: Optional baseline commit (if None, tries to find suitable default)
            include_untracked: Whether to include untracked files
            
        Returns:
            Optional[Set[str]]: Set of changed files, or None if delta scan not possible
        """
        if not GitUtils.is_git_repository(workspace_path):
            logger.warning("Directory is not a Git repository, delta scan not available")
            return None
        
        # If no baseline provided, try to find a suitable one
        if not baseline_commit:
            # Try to find merge base with common main branch names
            for main_branch in ['origin/main', 'origin/master', 'main', 'master']:
                baseline_commit = GitUtils.find_merge_base(workspace_path, main_branch)
                if baseline_commit:
                    logger.info(f"Using merge base with {main_branch} as baseline: {baseline_commit}")
                    break
        
        if not baseline_commit:
            logger.warning("Could not determine baseline commit for delta scan")
            return None
        
        try:
            changed_files = GitUtils.get_changed_files_since_commit(
                workspace_path, 
                baseline_commit, 
                include_untracked
            )
            
            if not changed_files:
                logger.info("No files changed since baseline, delta scan would be empty")
                
            return changed_files
            
        except (ValidationError, ProcessError) as e:
            logger.warning(f"Failed to get changed files for delta scan: {e}")
            return None 