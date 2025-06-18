import os
import zipfile
import tempfile
from typing import List

try:
    from git import Repo, InvalidGitRepositoryError, GitCommandError
except ImportError:
    raise ImportError("GitPython is required for git operations. Install it with: pip install GitPython")

from ..exceptions import ValidationError, FileSystemError

def get_git_repo_root() -> str:
    """Finds the root of the current git repository."""
    try:
        # Start from current directory and search up for git repo
        repo = Repo(search_parent_directories=True)
        return repo.working_dir
    except InvalidGitRepositoryError:
        raise ValidationError("This command must be run from within a git repository.")

def get_changed_files(base_ref: str, compare_ref: str) -> List[str]:
    """
    Gets a list of added or modified files between two git refs, ignoring deleted files.
    """
    try:
        repo = Repo(search_parent_directories=True)
        
        # Get the diff between the two refs
        # Note: GitPython's diff method returns diff objects, we need to extract changed files
        changed_files = []
        
        # Get all changes between base_ref and compare_ref
        try:
            # Try to get commits for the refs
            base_commit = repo.commit(base_ref)
            compare_commit = repo.commit(compare_ref)
            
            # Get diff between commits
            diff_index = base_commit.diff(compare_commit)
            
            # Extract filenames, excluding deleted files
            for diff_item in diff_index:
                # diff_item.change_type can be 'A' (added), 'D' (deleted), 'M' (modified), 'R' (renamed)
                if diff_item.change_type != 'D':  # Exclude deleted files
                    # Use b_path for the new/current path (a_path for old path in renames)
                    file_path = diff_item.b_path or diff_item.a_path
                    if file_path:
                        changed_files.append(file_path)
                        
        except Exception as e:
            # If commit lookup fails, try using git command through GitPython
            try:
                # Fallback: use GitPython's git command interface
                git_cmd = repo.git
                result = git_cmd.diff("--name-only", "--diff-filter=d", base_ref, compare_ref)
                changed_files = result.splitlines() if result else []
            except GitCommandError as git_e:
                raise ValidationError(
                    f"Could not get git diff. Ensure refs '{base_ref}' and '{compare_ref}' are valid.\nError: {git_e}"
                )
        
        if not changed_files:
            print("No new or modified files detected between the provided refs.")
        return changed_files
        
    except InvalidGitRepositoryError:
        raise ValidationError("This command must be run from within a git repository.")
    except GitCommandError as e:
        raise ValidationError(
            f"Could not get git diff. Ensure refs '{base_ref}' and '{compare_ref}' are valid.\nError: {e}"
        )

def create_diff_archive(files_to_add: List[str], repo_root: str) -> str:
    """
    Creates a temporary zip archive of the provided files.
    
    Returns the path to the temporary zip file. The caller is responsible for cleanup.
    """
    if not files_to_add:
        raise ValidationError("No files to archive.")

    temp_zip_file = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    temp_zip_path = temp_zip_file.name
    temp_zip_file.close()

    try:
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in files_to_add:
                full_path = os.path.join(repo_root, file_path)
                arcname = file_path  # Preserves directory structure relative to repo root

                if os.path.exists(full_path) and os.path.isfile(full_path):
                    zipf.write(full_path, arcname)
                else:
                    print(f"Warning: Skipping file that doesn't exist or isn't a regular file: {full_path}")
    except Exception as e:
        os.remove(temp_zip_path) # Clean up on failure
        raise FileSystemError(f"Failed to create temporary archive: {e}")

    return temp_zip_path
