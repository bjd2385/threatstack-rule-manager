from typing import Dict, Optional, Callable, List, Any, Tuple

import json
import logging

from functools import wraps
from settings import env


def lazy(f: Callable, metavars: Optional[Tuple[str, ...]] =None) -> Callable:
    """
    Apply a `push` from local state onto the remote state if the `LAZY_EVAL` environment variable is set to `true`.

    Args:
        f: method on State to apply a push. Again, the push is localized as far as the arguments on `f` indicate.
        metavars: optional list of different arguments to look for on the wrapped function.

    Returns:
        A tuple of `f`'s regular return with the result of the push.
    """
    @wraps(f)
    def _new_f(*args: Any, **kwargs: Any) -> Tuple[Dict, 'State']:
        ...

    return _new_f


class State:
    """
    Manage the local file tree/workspace and answer CLI options.
    """
    def __init__(self, org_id: str, user_id: str, api_key: str, base: str ='~/.threatstack') -> None:
        self._org_id = None
        self.user_id = user_id
        self.api_key = api_key
        self.base = base

        self.__credentials = {
            'user': user_id,
            'api':
        }

    @property
    def org_id(self) -> str:
        """
        Getter on the current workspace/organization's ID.

        Returns:
            The current workspace we've set.
        """
        return self._org_id

    @org_id.setter
    def org_id(self, value: str) -> None:
        """
        Capture the side affect of adjusting the working directory of this class instance through a property setter.

        Args:
            value: ID to set the current workspace to.

        Returns:
            Nothing.
        """
        self._org_id = value

    ## No such thing as deleting the org., so no deleter.

    def lst(self) -> 'State':
        """
        List the ruleset and rule hierarchy under an organization, based on local state.

        Returns:
            A State object.
        """

    @lazy
    def create_ruleset(self, filename: str) -> 'State':
        """
        Create a new ruleset in the current workspace.

        Args:
            filename: name of a file containing the ruleset to create. Must conform to the POST ruleset schema.

        Returns:
            A State object.
        """

    @lazy
    def create_rule(self, ruleset_id: str, filename: str) -> 'State':
        """
        Create a new rule from a JSON file in the current workspace.

        Args:
            ruleset_id: ruleset under which to create the new rule.
            filename: file from which to create the new rule. Must conform the the POST rule schema.

        Returns:
            A State object.
        """

    @lazy
    def copy_rule(self, rule_id: str, ruleset_id: str) -> 'State':
        """
        Copy an existing rule in the current workspace to another ruleset in the current workspace.

        Args:
            rule_id: rule ID to copy.
            ruleset_id: destination ruleset to copy to; must reside in the current organization.

        Returns:
            A State object.
        """

    @lazy
    def copy_rule_out(self, rule_id: str, ruleset_id: str, org_id: str) -> 'State':
        """
        Copy an existing rule in the current workspace to another ruleset in a different workspace. This
        will trip a refresh action against the next workspace prior to copying.

        Args:
            rule_id: rule ID to copy.
            ruleset_id: destination ruleset in a different workspace to copy this rule to.
            org_id: a different workspace to copy this rule to.

        Returns:
            A State object.
        """

    @lazy
    def copy_ruleset(self, ruleset_id: str, newname: str) -> 'State':
        """
        Copy an entire ruleset to a new one, intra-org.

        Args:
            ruleset_id: the ruleset to copy.
            newname: name to give the new ruleset (by default, the "<current name> - COPY").

        Returns:
            A State object.
        """

    @lazy
    def copy_ruleset_out(self, ruleset_id: str, org_id: str) -> 'State':
        """
        Copy an entire ruleset to a new organization.

        Args:
            ruleset_id: ruleset to copy to the new organization.
            org_id: the alertnate

        Returns:
            A State object.
        """

    @lazy
    def update_rule(self, ruleset_id: str, rule_id: str, filename: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    @lazy
    def update_ruleset(self, ruleset_id: str, filename: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    @lazy
    def delete_rule(self, rule_id: str) -> 'State':
        """
        Delete a rule from the current workspace.

        Args:
            rule_id: ID of the rule to delete. If self.lazy is enabled, then the remote copy is deleted

        Returns:

        """

    @lazy
    def delete_ruleset(self, ruleset_id: str) -> 'State':
        """
        Delete an entire ruleset from the current workspace.

        Args:
            ruleset_id:

        Returns:
    
        """


def push(org_id: str, ruleset_id: Optional[str], rule_id: Optional[str]) -> Dict:
    """
    Push the request org.'s local state onto the remote/platform.

    Args:
        org_id: current workspace within which to push changes.
        ruleset_id: optionally, you can narrow the push to a specific ruleset.
        rule_id: optionally, you can narrow the push to a specific rule.

    Returns:
        A dict.
    """


def refresh(self, org_id: str) -> State:
    """
    Effectively `push`'s opposite - instead of pushing local state onto the remote, pull all of the remote
    state and copy it over the local state (effectively deleting the local state).

    Returns:
        A State object.
    """


def diff(self, state: State, org_id: str) -> Dict:
    """
    Output a nicely formatted diff between local state and the remote/platform state for the current workspace.

    Args:
        state:
        org_id:

    Returns:
        A dictionary with the following schema ~
        TODO: complete this schema
    """


def workspace(self, org_id: str) -> State:
    """
    Create a new rule from a JSON file.

    Returns:
        A State object.
    """
