import pytest
import zipfile
from unittest.mock import patch, MagicMock, call
from workbench_cli.utilities import git_diff_utils
from workbench_cli.exceptions import ValidationError, FileSystemError

# --- Tests for get_git_repo_root ---

def test_get_git_repo_root_success():
    """
    Should return the correct repo root path on success.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        mock_repo = MagicMock()
        mock_repo.working_dir = '/path/to/repo'
        mock_repo_class.return_value = mock_repo
        
        assert git_diff_utils.get_git_repo_root() == '/path/to/repo'
        mock_repo_class.assert_called_once_with(search_parent_directories=True)

def test_get_git_repo_root_failure():
    """
    Should raise ValidationError if not in a git repository.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        from git import InvalidGitRepositoryError
        mock_repo_class.side_effect = InvalidGitRepositoryError("Not a git repo")
        
        with pytest.raises(ValidationError, match="must be run from within a git repository"):
            git_diff_utils.get_git_repo_root()

# --- Tests for get_changed_files ---

def test_get_changed_files_success():
    """
    Should return a list of changed files using GitPython diff.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        # Setup mock repository
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        # Setup mock commits
        mock_base_commit = MagicMock()
        mock_compare_commit = MagicMock()
        mock_repo.commit.side_effect = [mock_base_commit, mock_compare_commit]
        
        # Setup mock diff items
        mock_diff_item1 = MagicMock()
        mock_diff_item1.change_type = 'M'  # Modified
        mock_diff_item1.b_path = 'file1.py'
        mock_diff_item1.a_path = 'file1.py'
        
        mock_diff_item2 = MagicMock()
        mock_diff_item2.change_type = 'A'  # Added
        mock_diff_item2.b_path = 'path/to/file2.txt'
        mock_diff_item2.a_path = None
        
        # Mock the diff method
        mock_base_commit.diff.return_value = [mock_diff_item1, mock_diff_item2]
        
        changed_files = git_diff_utils.get_changed_files('main', 'HEAD')
        assert changed_files == ['file1.py', 'path/to/file2.txt']

def test_get_changed_files_no_changes():
    """
    Should return an empty list when there are no changes.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_base_commit = MagicMock()
        mock_compare_commit = MagicMock()
        mock_repo.commit.side_effect = [mock_base_commit, mock_compare_commit]
        
        # Empty diff
        mock_base_commit.diff.return_value = []
        
        assert git_diff_utils.get_changed_files('main', 'HEAD') == []

def test_get_changed_files_excludes_deleted():
    """
    Should exclude deleted files from the result.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        mock_base_commit = MagicMock()
        mock_compare_commit = MagicMock()
        mock_repo.commit.side_effect = [mock_base_commit, mock_compare_commit]
        
        # Setup diff items with one deleted file
        mock_modified = MagicMock()
        mock_modified.change_type = 'M'
        mock_modified.b_path = 'modified.py'
        
        mock_deleted = MagicMock()
        mock_deleted.change_type = 'D'  # Deleted - should be excluded
        mock_deleted.b_path = 'deleted.py'
        
        mock_base_commit.diff.return_value = [mock_modified, mock_deleted]
        
        changed_files = git_diff_utils.get_changed_files('main', 'HEAD')
        assert changed_files == ['modified.py']

def test_get_changed_files_failure():
    """
    Should raise ValidationError if git operations fail.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        from git import InvalidGitRepositoryError
        mock_repo_class.side_effect = InvalidGitRepositoryError("Not a git repo")
        
        with pytest.raises(ValidationError, match="must be run from within a git repository"):
            git_diff_utils.get_changed_files('main', 'HEAD')

def test_get_changed_files_bad_refs():
    """
    Should raise ValidationError if refs are invalid.
    """
    with patch('workbench_cli.utilities.git_diff_utils.Repo') as mock_repo_class:
        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo
        
        # Simulate bad ref by making commit() raise an exception, then git.diff also fails
        from git import GitCommandError
        mock_repo.commit.side_effect = GitCommandError("git commit", "bad object main")
        
        # Mock the fallback git command to also fail
        mock_git_cmd = MagicMock()
        mock_repo.git = mock_git_cmd
        mock_git_cmd.diff.side_effect = GitCommandError("git diff", "bad object main")
        
        with pytest.raises(ValidationError, match="Could not get git diff"):
            git_diff_utils.get_changed_files('bad-ref', 'HEAD')

# --- Tests for create_diff_archive ---

@patch('zipfile.ZipFile')
@patch('os.path.exists')
@patch('os.path.isfile')
@patch('tempfile.NamedTemporaryFile')
def test_create_diff_archive_success(mock_tempfile, mock_isfile, mock_exists, mock_zipfile):
    """
    Should create a zip archive with the specified files.
    """
    # Setup mocks
    mock_exists.return_value = True
    mock_isfile.return_value = True
    
    # Mock the temporary file object
    mock_temp_obj = MagicMock()
    mock_temp_obj.name = '/tmp/archive.zip'
    mock_tempfile.return_value = mock_temp_obj
    
    # Mock the ZipFile context manager
    mock_zip_context = MagicMock()
    mock_zipfile.return_value = mock_zip_context

    files_to_add = ['file1.py', 'path/to/file2.txt']
    repo_root = '/repo'
    
    archive_path = git_diff_utils.create_diff_archive(files_to_add, repo_root)

    assert archive_path == '/tmp/archive.zip'
    mock_tempfile.assert_called_once_with(suffix=".zip", delete=False)
    
    # Verify zipfile was opened correctly
    mock_zipfile.assert_called_once_with('/tmp/archive.zip', 'w', zipfile.ZIP_DEFLATED)
    
    # Verify write calls
    expected_calls = [
        call.write('/repo/file1.py', 'file1.py'),
        call.write('/repo/path/to/file2.txt', 'path/to/file2.txt')
    ]
    mock_zip_context.__enter__().write.assert_has_calls(expected_calls, any_order=True)

def test_create_diff_archive_no_files():
    """
    Should raise ValidationError if the file list is empty.
    """
    with pytest.raises(ValidationError, match="No files to archive"):
        git_diff_utils.create_diff_archive([], '/repo')

@patch('zipfile.ZipFile')
@patch('os.remove')
def test_create_diff_archive_zip_failure(mock_remove, mock_zipfile):
    """
    Should raise FileSystemError and clean up temp file if zipping fails.
    """
    mock_zipfile.side_effect = Exception("Zipping failed")
    
    with pytest.raises(FileSystemError, match="Failed to create temporary archive"):
        git_diff_utils.create_diff_archive(['file1.py'], '/repo')
    
    # Check that cleanup was attempted
    assert mock_remove.called
