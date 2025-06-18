import os
import logging
from typing import Tuple, Optional

logger = logging.getLogger("workbench-cli")

def autodetect_git_refs() -> Tuple[Optional[str], Optional[str]]:
    """
    Autodetects base and head git references from common CI/CD environment variables.

    Currently supports:
    - GitHub Actions (for pull requests)

    Returns:
        A tuple containing (base_ref, head_ref).
        Returns (None, None) if not in a recognized CI environment or if refs are not found.
    """
    # GitHub Actions
    if os.getenv('GITHUB_ACTIONS') == 'true' and os.getenv('GITHUB_EVENT_NAME') == 'pull_request':
        logger.debug("Detected GitHub Actions pull request environment.")
        base_ref = os.getenv('GITHUB_BASE_REF')
        head_ref = os.getenv('GITHUB_HEAD_REF')
        if base_ref and head_ref:
            print(f"💡 Auto-detected refs from GitHub Actions: base='{base_ref}', compare='{head_ref}'")
            return base_ref, head_ref
        else:
            logger.warning("In GitHub Actions PR context, but GITHUB_BASE_REF or GITHUB_HEAD_REF not found.")

    # Future CI systems can be added here, for example:
    # elif os.getenv('GITLAB_CI'):
    #     base_ref = os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')
    #     head_ref = os.getenv('CI_MERGE_REQUEST_SOURCE_BRANCH_NAME')
    #     if base_ref and head_ref:
    #         print(f"💡 Auto-detected refs from GitLab CI: base='{base_ref}', compare='{head_ref}'")
    #         return base_ref, head_ref

    logger.debug("No recognized CI/CD environment for ref auto-detection found.")
    return None, None
