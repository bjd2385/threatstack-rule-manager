"""
Manage a timeline of commits and branches that SEs will be working in and on related to customers' organizations.
"""

from typing import List, Optional

from git import Git


def initialize_repo(directory: str, git_url: str) -> Optional[List]:
    """
    Initialize a directory, or set the upstream directory.

    Args:
        directory: location to clone the repo into.
        upstream_url: location to pull the repo from.

    Returns:
        A list of the files and directories, once it's been completed. Or None.
    """
    repo = Git(directory)
    print(repo.clone(git_url))
