"""
Manage a timeline of commits and branches that SEs will be working in and on related to customers' organizations.
"""

from typing import List, Optional

import git
import regex as re


# Regexes to pull info out of upstream Git URLs. This should work with both public and private repos, the latter of
# which requires an access key.
GIT_REPO_RE = re.compile(r'^(https://github.com/|git@github.com:|https://[a-z0-9]+:[a-z0-9A-Z_]+@github.com/)[a-z0-9]+/[a-z0-9]+(.git)$')
GIT_REPO_DIR = re.compile(r'^(https://github.com/|git@github.com:|https://[a-z0-9]+:[a-z0-9A-Z_]+@github.com/)[a-z0-9]+/\K[a-z0-9]+(?=(.git))')


def initialize_repo(state_dir: str, git_url: str) -> Optional[str]:
    """
    Initialize a directory, or set the upstream directory.

    Args:
        state_dir: current state directory in use. If the user changes the Git repo, update the corresponding state
            directory within which we are working.
        git_url: Upstream Git repo to pull down and commit changes on.

    Returns:
        The new state directory path.
    """

    if not re.match(GIT_REPO_RE, git_url):
        return None
    else:
        directory = re.match(GIT_REPO_DIR, git_url).group(0)

    repo_state_subdir = directory + '/'
    repo = git.Git(state_dir)

    try:
        repo.clone(git_url)
    except git.exc.GitCommandError as msg:
        # The repo already exists locally.
        pass

    return repo_state_subdir


def checkout_branch(branch_name: str) -> Optional[str]:
    """
    Check out/create a new branch for the SE to work in.

    Args:
        branch_name: required string name for the branch to be created.

    Returns:
        The current branch's name.
    """
    ...


def push_branch(branch_name: str) -> Optional[List]:
    """


    Args:
        branch_name:

    Returns:

    """


def workspace(org_id: str) -> Optional[str]:
    """
    Checkout a new workspace to query on, checking out another branch.

    Args:
        org_id:

    Returns:
        Optionally,
    """
