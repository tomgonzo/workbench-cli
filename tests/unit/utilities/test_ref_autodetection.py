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
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'push')
    monkeypatch.setenv('GITHUB_BASE_REF', 'main')
    monkeypatch.setenv('GITHUB_HEAD_REF', 'main')

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None

def test_autodetect_github_actions_pr_missing_vars(monkeypatch):
    """
    Should return None if essential ref variables are missing in a PR context.
    """
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
    # Missing GITHUB_BASE_REF and GITHUB_HEAD_REF

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None

def test_autodetect_no_ci_environment(monkeypatch):
    """
    Should return None when not in a recognized CI environment.
    """
    # Ensure no relevant environment variables are set
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    
    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None

def test_autodetect_other_ci_environment(monkeypatch):
    """
    Should return None for an unrecognized CI environment.
    """
    monkeypatch.setenv('CI', 'true')
    monkeypatch.setenv('BUILD_ID', '12345')

    base_ref, head_ref = autodetect_git_refs()
    assert base_ref is None
    assert head_ref is None
