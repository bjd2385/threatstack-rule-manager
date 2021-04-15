"""
Purpose of the state manager is to provide a common API between local filesystem state changes (lazy) and remote,
Threat Stack API-supported app rules' state changes.

Per the above, the state management class is broken down into two major parts. Regardless, the

1) if
"""

from typing import Dict, Optional, Callable, List, Any, Tuple

import json
import logging
import uuid
import configparser

from functools import wraps
from settings import env
from api import API


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
    Manage local and remote organizational state through OS-level calls and API calls.
    """
    def __init__(self, org_id: str, user_id: str, api_key: str, state_dir: str, state_file: str) -> None:
        self.org_id = org_id
        self.user_id = user_id
        self.api_key = api_key
        self.state_dir = state_dir
        self.state_file = state_file

        self.credentials = {
            'user_id': user_id,
            'api_key': api_key,
            'org_id': org_id
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
        self._create_organization(value)

    @org_id.deleter
    def org_id(self) -> None:
        """
        Capture the side affect of deleting the organization's directory in the local filesystem. This is not a change
        that has to be pushed in any way.

        Returns:
            Nothing.
        """
        self._delete_organization(self.org_id)

    def push(self) -> bool:
        """
        Push local state onto remote platform state. This push occurs organization-by-organization according to the local
        state file by creating an API interface to the remote organization, then POSTing or PUTting local tracked changed
        rulesets and rules.

        Returns:
            True if all API calls were successful.
        """

    def refresh(self) -> 'State':
        """
        Effectively `push`'s opposite - instead of pushing local state onto the remote, pull all of the remote
        state and copy it over the local state (effectively deleting the local state).

        Returns:
            A State object.
        """

    ## Local filesystem/state high level API.

    def _create_organization(self, org_id: str) -> bool:
        """
        Create a local organization directory if it doesn't already exist and update the local config to point at
        the new organization.

        Args:
            org_id: organization ID to create in the local state directory if it does not already.

        Returns:
            True if the creation and switch was successful, False otherwise.
        """

    def _delete_organization(self, org_id: str) -> bool:
        """
        Delete a local organization's directory if it doesn't already exist.

        Args:
            org_id: organization ID to delete in the local state directory.

        Returns:
            True if the deletion was successful, False otherwise.
        """

    def _create_ruleset(self, org_id: str, ruleset_id: str, file: str) -> bool:
        """
        Create a local ruleset directory if it doesn't already exist.

        Args:
            org_id: organization within which to create the ruleset directory.
            ruleset_id: ruleset to create in the local organization's directory.

        Returns:
            True if the creation was successful, False otherwise.
        """

    def _edit_ruleset(self, org_id: str, ruleset_id: str, file: str) -> bool:
        """
        Edit a local ruleset.

        Args:
            org_id: organization within which to edit the ruleset directory.
            ruleset_id: ruleset to edit in the local organization's directory.

        Returns:
            True if the edit was successful, False otherwise.
        """

    def _delete_ruleset(self, org_id: str, ruleset_id: str) -> bool:
        """
        Delete a local ruleset directory if it exists.

        Args:
            org_id: organization within which to delete the ruleset directory.
            ruleset_id: ruleset to delete in the local organization's directory.

        Returns:
            True if the local deletion was successful, False otherwise.
        """

    def _create_rule(self, org_id: str, ruleset_id: str, rule_id: str) -> bool:
        """
        Create a local rule directory in a ruleset in an organization's directory.

        Args:
            org_id: organization within which to create the rule's directory.
            ruleset_id: ruleset within which to create the rule.
            rule_id: rule directory to create.

        Returns:
            True if the local creation was successful, False otherwise.
        """

    def _edit_rule(self, org_id: str, ruleset_id: str, rule_id: str) -> bool:
        """
        Modify a local rule in a ruleset in an organization's directory.

        Args:
            org_id: organization within which to edit the rule.
            ruleset_id: ruleset that contains the rule to be edited.
            rule_id:

        Returns:

        """

    def _delete_rule(self, org_id: str, ruleset_id: str, rule_id: str) -> bool:
        """
        Delete a local rule directory in a ruleset in an organization's directory.

        Args:
            org_id:
            ruleset_id:
            rule_id:

        Returns:

        """

    def lst(self) -> 'State':
        """
        List the ruleset and rule hierarchy under an organization, based on local state.

        Returns:
            A State object.
        """

    ## Remote state management API.

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
    def copy_ruleset(self, ruleset_id: str, newname: Optional[str]) -> 'State':
        """
        Copy an entire ruleset to a new one, intra-org.

        Args:
            ruleset_id: the ruleset to copy.
            newname: optional name to give the new ruleset (by default, the "<current name> - COPY"). Rules are
                already assigned unique IDs upon POST request remotely, so

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
