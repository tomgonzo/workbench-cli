import pytest
from workbench_cli.utilities.ref_autodetection import autodetect_git_refs

def test_autodetect_github_actions_pr(monkeypatch):
    """
    Should detect GITHUB_BASE_REF and GITHUB_HEAD_REF in a GitHub Actions PR context.
    """
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
    monkeypatch.setenv('GITHUB_BASE_REF', 'main')
    monkeypatch.setenv('GITHUB_HEAD_REF', 'feature-branch')

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref == 'main'
    assert head_ref == 'feature-branch'

def test_autodetect_github_actions_not_pr(monkeypatch):
    """
    Should not detect refs if not in a pull_request event.
    """
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'push')  # Not a pull_request
    # Clear any existing PR-related variables to ensure clean state
    monkeypatch.delenv('GITHUB_BASE_REF', raising=False)
    monkeypatch.delenv('GITHUB_HEAD_REF', raising=False)

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None

def test_autodetect_github_actions_pr_missing_vars(monkeypatch):
    """
    Should return None if essential ref variables are missing in a PR context.
    """
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
    # Explicitly remove GITHUB_BASE_REF and GITHUB_HEAD_REF
    monkeypatch.delenv('GITHUB_BASE_REF', raising=False)
    monkeypatch.delenv('GITHUB_HEAD_REF', raising=False)

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None

def test_autodetect_no_ci_environment(monkeypatch):
    """
    Should return None when not in a recognized CI environment.
    """
    # Ensure no relevant environment variables are set
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    monkeypatch.delenv('GITHUB_EVENT_NAME', raising=False)
    monkeypatch.delenv('GITHUB_BASE_REF', raising=False)
    monkeypatch.delenv('GITHUB_HEAD_REF', raising=False)
    
    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None

def test_autodetect_other_ci_environment(monkeypatch):
    """
    Should return None for an unrecognized CI environment.
    """
    # Clear GitHub Actions environment variables
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    monkeypatch.delenv('GITHUB_EVENT_NAME', raising=False)
    monkeypatch.delenv('GITHUB_BASE_REF', raising=False)
    monkeypatch.delenv('GITHUB_HEAD_REF', raising=False)
    
    # Set different CI environment
    monkeypatch.setenv('CI', 'true')
    monkeypatch.setenv('BUILD_ID', '12345')

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None
