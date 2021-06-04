"""
Manage a timeline of commits and branches that SEs will be working in and on related to customers' organizations.
"""

from typing import List, Optional

import git


def initialize_repo(directory: str, git_url: str) -> Optional[List]:
    """
    Initialize a directory, or set the upstream directory.

    Args:
        directory: location to clone the repo into.
        git_url: Upstream Git repo to pull down and commit changes on.

    Returns:
        A list of the files and directories, once it's been completed. Or None.
    """
    repo = git.Git(directory)
    try:
        repo.clone(git_url)
    except git.exc.GitCommandError as msg:
        # The repo already exists locally.
        pass


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


def workspace(name: str) -> Optional[str]:
    """
    Checkout a new workspace to query on, checking out another branch.

    Args:
        name: name of the new workspace to create and switch to.

    Returns:
        Optionally,
    """
