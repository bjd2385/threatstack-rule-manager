"""
Purpose of the state manager is to provide a common API between local filesystem state changes (lazy) and remote,
Threat Stack API-supported app rules' state changes.
"""

from typing import Dict, Optional, Callable, Any, Tuple

import logging
import uuid
import os
import shutil

from functools import wraps
from api import API
from utils import read_json, write_json
from urllib.error import URLError


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
    def __init__(self, state_dir: str, state_file: str, org_id: str, user_id: str, api_key: str) -> None:
        self.state_dir = state_dir
        self.state_file = state_file
        self.user_id = user_id
        self.api_key = api_key

        self.credentials = {
            'user_id': user_id,
            'api_key': api_key,
            'org_id': org_id
        }

        self.org_id = org_id

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

    def push(self) -> bool:
        """
        Push local state onto remote platform state. This push occurs organization-by-organization according to the
        local state file by creating an API interface to the remote organization, then POSTing or PUTting local
        tracked changed rulesets and rules.

        Returns:
            True if all API calls were successful.
        """

    def refresh(self) -> 'State':
        """
        Effectively `push`'s opposite - instead of pushing local state onto the remote platform state, pull all of
        the remote organization state and copy it over the local organization-level state (effectively overwriting
        the local organization's state). Deletes prior local state and clears state file of organization change.

        Args:
            org_id: optionally specify an organization ID to refresh upon. NOTE: Should only be specified in the
                case that you're copying a rule or ruleset from one organization to another and that destination
                organization does not exist in local state.

        Returns:
            Nothing.
        """
        # If there's a former failed run of some kind, let's clear the board to ensure we don't mix local state
        # with now untracked local state.
        remote_dir = self.state_dir + self.org_id + '/.remote/'
        backup_dir = self.state_dir + self.org_id + '/.backup/'

        if os.path.isdir(remote_dir):
            # We can just delete this (likely) partial remote state capture.
            shutil.rmtree(remote_dir)
        if os.path.isdir(backup_dir):
            # I'm going to let this fail if anyone ever comes across trying to copy duplicate files or dirs back
            # over the parent dir, because this should not happen. But, if it does, I will investigate with them
            # how that occurred.
            for ruleset in os.listdir(backup_dir):
                shutil.move(backup_dir + ruleset, self.state_dir + self.org_id)
            os.rmdir(backup_dir)

        os.mkdir(backup_dir)
        os.mkdir(remote_dir)

        for ruleset in os.listdir(self.state_dir + self.org_id):
            if ruleset != '.backup' and ruleset != '.remote':
                shutil.move(self.state_dir + self.org_id + '/' + ruleset, backup_dir + ruleset)

        api = API(**self.credentials)

        # Collect rulesets under this organization and create corresponding directories.
        try:
            rulesets = api.get_rulesets()
            for ruleset in rulesets['rulesets']:
                ruleset_id = ruleset['id']

                for field in ('id', 'createdAt', 'updatedAt'):
                    ruleset.pop(field)

                print(f'Refreshing ruleset ID \'{ruleset_id}\'')

                ruleset_rules = api.get_ruleset_rules(ruleset_id)
                ruleset_dir = remote_dir + ruleset_id + '/'
                os.mkdir(ruleset_dir)
                write_json(ruleset_dir + 'ruleset.json', ruleset)
                
                for rule in ruleset_rules['rules']:
                    rule_id = rule['id']
                    print(f'\tPulling rule and tag JSON on rule ID \'{rule_id}\'')
                    rule_tags = api.get_rule_tags(rule_id)
                    rule_dir = ruleset_dir + rule_id + '/'
                    os.mkdir(rule_dir)
                    write_json(rule_dir + 'rule.json', rule)
                    write_json(rule_dir + 'tags.json', rule_tags)
        except (URLError, KeyboardInterrupt):
            # Restore backup, refresh unsuccessful; delete remote state directory.
            logging.error(f'Could not refresh organization {self.org_id} local state, restoring backup')
            shutil.rmtree(remote_dir)
            for ruleset in os.listdir(backup_dir):
                shutil.move(backup_dir + ruleset, self.state_dir + self.org_id + '/' + ruleset)
            else:
                # backup directory should be clear, so let's remove it.
                os.rmdir(backup_dir)
        else:
            # Clear this organization's local state and delete the backup, refresh successful.
            for ruleset in os.listdir(remote_dir):
                shutil.move(remote_dir + ruleset, self.state_dir + self.org_id + '/' + ruleset)
            shutil.rmtree(backup_dir)
            shutil.rmtree(remote_dir)
            self._clear_organization_state()
            return self

    ## Local filesystem/state high level API.

    def _clear_organization_state(self) -> bool:
        """
        Clear local organization state from the tracking file. This should only be called internally as a side effect
        of another process, such as refreshing the organization's local state (which results in wiping the current
        directory structure and replacing it with the remote state).

        Returns:
            True if a change was made to the local state file on this organization, False otherwise.
        """
        state = read_json(self.state_file)
        if self.org_id in state['organizations']:
            change = state['organizations'].pop(self.org_id)
            write_json(self.state_file, state)
        else:
            change = None
        return bool(change)

    def _create_organization(self, org_id: str) -> Optional['State']:
        """
        Create a local organization directory if it doesn't already exist, in addition to calling a refresh on that
        directory if that's the case.

        Args:
            org_id: organization ID to create in the local state directory if it does not already.

        Returns:
            True if the organization had to be created, False otherwise.
        """
        if not os.path.isdir(self.state_dir + org_id):
            os.mkdir(self.state_dir + org_id)
            return State(self.state_dir, self.state_file, org_id, self.user_id, self.api_key).refresh()
        else:
            return None

    def _delete_organization(self, org_id: str) -> bool:
        """
        Delete a local organization's directory if it doesn't already exist.

        Args:
            org_id: organization ID to delete in the local state directory.

        Returns:
            True if there was a deletion, False otherwise.
        """
        if os.path.isdir(self.state_dir + org_id):
            # TODO: investigate whether it'd be better to call `onerror` here
            shutil.rmtree(self.state_dir + org_id, ignore_errors=True)
            self._clear_organization_state()
            return True
        else:
            return False

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

    def lst(self) -> str:
        """
        List the ruleset and rule hierarchy under an organization, based on local state. This is meant to be
        a more human-readable view of the organization and organization's rules.

        Returns:
            A nicer view of an organization's rulesets and rules.
        """
        view = dict()
        organization_dir = self.state_dir + self.org_id + '/'
        rulesets = os.listdir(organization_dir)
        for ruleset in rulesets:
            rules = os.listdir(organization_dir + ruleset)
            view[ruleset] = rules
        return view

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
