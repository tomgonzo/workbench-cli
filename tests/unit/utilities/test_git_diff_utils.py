import pytest
import subprocess
import zipfile
from unittest.mock import patch, MagicMock, call
from workbench_cli.utilities import git_diff_utils
from workbench_cli.exceptions import ValidationError, FileSystemError

# --- Tests for get_git_repo_root ---

def test_get_git_repo_root_success():
    """
    Should return the correct repo root path on success.
    """
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            stdout='/path/to/repo\n',
            check=True
        )
        assert git_diff_utils.get_git_repo_root() == '/path/to/repo'
        mock_run.assert_called_once_with(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True
        )

def test_get_git_repo_root_failure():
    """
    Should raise ValidationError if git command fails.
    """
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, 'git')
        with pytest.raises(ValidationError, match="must be run from within a git repository"):
            git_diff_utils.get_git_repo_root()

# --- Tests for get_changed_files ---

def test_get_changed_files_success():
    """
    Should return a list of changed files.
    """
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            stdout='file1.py\npath/to/file2.txt\n',
            check=True
        )
        changed_files = git_diff_utils.get_changed_files('main', 'HEAD')
        assert changed_files == ['file1.py', 'path/to/file2.txt']
        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "--diff-filter=d", "main", "HEAD"],
            capture_output=True, text=True, check=True
        )

def test_get_changed_files_no_changes():
    """
    Should return an empty list when there are no changes.
    """
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='\n', check=True)
        assert git_diff_utils.get_changed_files('main', 'HEAD') == []

def test_get_changed_files_failure():
    """
    Should raise ValidationError if git diff command fails.
    """
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, 'git diff', stderr='fatal: bad object main'
        )
        with pytest.raises(ValidationError, match="Could not get git diff"):
            git_diff_utils.get_changed_files('main', 'HEAD')

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
