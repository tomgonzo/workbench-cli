import subprocess
import os
import zipfile
import tempfile
from typing import List

from ..exceptions import ValidationError, FileSystemError

def get_git_repo_root() -> str:
    """Finds the root of the current git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ValidationError("This command must be run from within a git repository.")

def get_changed_files(base_ref: str, compare_ref: str) -> List[str]:
    """
    Gets a list of added or modified files between two git refs, ignoring deleted files.
    """
    try:
        # Using --diff-filter=d to exclude deleted files (Added, Copied, Modified, Renamed, etc. are included)
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=d", base_ref, compare_ref],
            capture_output=True, text=True, check=True
        )
        changed_files = result.stdout.strip().splitlines()
        if not changed_files:
            print("No new or modified files detected between the provided refs.")
        return changed_files
    except subprocess.CalledProcessError as e:
        raise ValidationError(
            f"Could not get git diff. Ensure refs '{base_ref}' and '{compare_ref}' are valid.\nError: {e.stderr}"
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
