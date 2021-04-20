"""
The State manager class provides a common API between local filesystem state changes (lazy) and remote, Threat Stack
API-supported app rule state changes.
"""

from typing import Dict, Optional, Callable, Any, Tuple, Literal

import logging
import os
import shutil

from functools import wraps
from urllib.error import URLError
from uuid import uuid4
from .api import API
from .utils import read_json, write_json, Color


RuleStatus = Literal['rule', 'tags', 'both', 'del']
RulesetStatus = Literal['true', 'false', 'del']


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
        self.organization_dir = state_dir + org_id + '/'

        # Postfix is set on local-only changes and tracked during pushes to the remote platform so that local
        # directories can be refreshed to their proper assigned UUID.
        self._postfix = '-localonly'

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

    def push(self) -> None:
        """
        Push local state onto remote platform state. This push occurs organization-by-organization according to the
        local state file by creating an API interface to the remote organization, then POSTing or PUTting local
        tracked changed rulesets and rules.

        Returns:
            True if all API calls were successful.
        """


    def refresh(self) -> None:
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
        remote_dir = self.organization_dir + '.remote/'
        backup_dir = self.organization_dir + '.backup/'

        if os.path.isdir(remote_dir):
            # We can just delete this (likely) partial remote state capture.
            shutil.rmtree(remote_dir)
        if os.path.isdir(backup_dir):
            # I'm going to let this fail if anyone ever comes across trying to copy duplicate files or dirs back
            # over the parent dir, because this should not happen. But, if it does, I will investigate with them
            # how that occurred.
            for ruleset in os.listdir(backup_dir):
                shutil.move(backup_dir + ruleset, self.organization_dir)
            os.rmdir(backup_dir)

        os.mkdir(backup_dir)
        os.mkdir(remote_dir)

        for ruleset in os.listdir(self.organization_dir):
            if ruleset != '.backup' and ruleset != '.remote':
                shutil.move(self.organization_dir + ruleset, backup_dir + ruleset)

        api = API(**self.credentials)

        # Collect rulesets under this organization and create corresponding directories.
        try:
            rulesets = api.get_rulesets()
            for ruleset in rulesets['rulesets']:
                ruleset_id = ruleset['id']

                # Remove fields that aren't POSTable from the rulesets' data.
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
                shutil.move(backup_dir + ruleset, self.organization_dir + ruleset)
            else:
                # backup directory should be clear, so let's remove it.
                os.rmdir(backup_dir)
        else:
            # Clear this organization's local state and delete the backup, refresh successful.
            for ruleset in os.listdir(remote_dir):
                shutil.move(remote_dir + ruleset, self.organization_dir + ruleset)
            shutil.rmtree(backup_dir)
            shutil.rmtree(remote_dir)
            self._state_delete_organization(self.org_id)

    # Local state file management API.

    def _state_add_organization(self, state: Optional[Dict] =None) -> Optional[Dict]:
        """
        Add an organization to be tracked in the state file. There should always, however, be a ruleset or rule under
        the organization if it's present, or some work to be done if it's being tracked.

        Args:
            state: Optionally provide an already-opened state file.

        Returns:
            The updated state data if it was provided.
        """
        write_state = not state
        if write_state:
            state = read_json(self.state_file)

        if self.org_id not in state['organizations']:
            state['orgnizations'][self.org_id] = dict()

        if write_state:
            write_json(self.state_file, state)
            return
        else:
            return state

    def _state_delete_organization(self, org_id: str, state: Optional[Dict] =None) -> Optional[Dict]:
        """
        Delete an organization's tracked state in the state file. This method should only ever be called by an
        internal process, such as during a refresh.

        Args:
            org_id: organization ID to pop from the state file's tracking, if it exists.
            state: state file data tp update. If not None, this function will commit changes to disk.

        Returns:
            The updated state data if it was provided.
        """
        write_state = not state
        if write_state:
            state = read_json(self.state_file)

        if org_id in state['organizations']:
            state['orgnizations'].pop(org_id)

        if write_state:
            write_json(self.state_file, state)
            return
        else:
            return state

    def _state_add_ruleset(self, ruleset_id: str, action: RulesetStatus, state: Optional[Dict] =None) -> Optional[Dict]:
        """
        Add a ruleset (and organization, if it's not already being tracked) to the state file.

        Args:
            ruleset_id: ruleset to start tracking.
            action: status to set the ruleset to. It must take one of the Literal values defined above.
            state: state file data to update. If not None, this function will commit changes to disk.

        Returns:
            The updated state data if it was provided.
        """
        write_state = not state
        if write_state:
            state = read_json(self.state_file)

        if self.org_id in state['organizations']:
            if ruleset_id in state['organizations'][self.org_id]:
                if action == 'true' and state['organizations'][self.org_id][ruleset_id]['modified'] == 'false':
                    state['organizations'][self.org_id][ruleset_id]['modified'] = 'true'
                elif action != 'del' and state['organizations'][self.org_id][ruleset_id]['modified'] == 'del':
                    # You can't add a deleted ruleset back; it's already been wiped from the state directory.
                    raise ValueError(f'Cannot add ruleset ID \'{ruleset_id}\' back to state file after being deleted.')
                elif action == 'false' and state['organizations'][self.org_id][ruleset_id]['modified'] == 'true':
                    raise ValueError(f'Cannot unmodify a ruleset once it\'s been marked modified.')
            else:
                state['organizations'][self.org_id][ruleset_id] = {
                    'modified': action,
                    'rules': dict()
                }
        else:
            state = self._state_add_organization(state)
            state['organizations'][self.org_id][ruleset_id] = {
                'modified': action,
                'rules': dict()
            }

        if write_state:
            write_json(self.state_file, state)
            return
        else:
            return state

    def _state_delete_ruleset(self, ruleset_id: str, recursive: bool =False, state: Optional[Dict] =None) -> Optional[Dict]:
        """
        Update the state file to reflect the actions of deleting a ruleset. This method should only be called by
        _delete_ruleset or _state_delete_rule.

        Args:
            ruleset_id: ruleset on which to set 'modified' to False.
            recursive: only caller using recursive deletion should be `_delete_ruleset`.
            state: state file data to update. If not None, this function will commit changes to disk.

        Returns:
            The updated state data if it was provided.
        """
        write_state = not state
        if write_state:
            state = read_json(self.state_file)

        if self.org_id in state['organizations'] and ruleset_id in state['organizations'][self.org_id]:
            if ruleset_id.lower().endswith(self._postfix.lower()):
                # We're dealing with a local-only ruleset.
                if state['organizations'][self.org_id][ruleset_id]['modified'] == 'true':
                    if len(state['organizations'][self.org_id][ruleset_id]['rules']) == 0:
                        state['organizations'][self.org_id].pop(ruleset_id)
                    else:
                        if recursive:
                            state['organizations'][self.org_id].pop(ruleset_id)
                        else:
                            pass
                else:
                    raise ValueError('local-only rulesets should only have a \'true\' modified value.')
            else:
                # We're dealing with a local copy (potentially modified version) of a ruleset that also exists remotely.
                if state['organizations'][self.org_id][ruleset_id]['modified'] == 'true':
                    if len(state['organizations'][self.org_id][ruleset_id]['rules']) == 0:
                        state['organization'][self.org_id].pop(ruleset_id)
                    else:
                        if recursive:
                            state['organizations'][self.org_id][ruleset_id]['modified'] = 'del'
                        else:
                            pass
                elif state['organizations'][self.org_id][ruleset_id]['modified'] == 'false':
                    if len(state['organizations'][self.org_id][ruleset_id]['rules']) == 0:
                        raise ValueError('unmodified rulesets cannot have zero rules.')
                    else:
                        if recursive:
                            state['organizations'][self.org_id][ruleset_id]['modified'] = 'del'
                        else:
                            pass
                elif state['organizations'][self.org_id][ruleset_id]['modified'] == 'del':
                    assert(len(state['organizations'][self.org_id][ruleset_id]['rules']) == 0)
                    pass
        else:
            pass

        if write_state:
            write_json(self.state_file, state)
            return
        else:
            return state

    def _state_add_rule(self, ruleset_id: str, rule_id: str, endpoint: RuleStatus ='both', state: Optional[Dict] =None) -> Optional[Dict]:
        """
        Add a modified rule to the state file for tracking.

        Args:
            ruleset_id: ruleset within the defined organization to add a rule.
            rule_id: rule ID to add to the state file.
            endpoint: you can further define whether you only want one of the two possible requests to be made.
                By default, 'both' is set to push both 'rule' and 'tags' remotely.
            state: state file data to update. If not None, this function will commit changes to disk.

        Returns:
            The updated state data if it was provided.
        """
        write_state = not state
        if write_state:
            state = read_json(self.state_file)

        if self.org_id in state['organizations']:
            if ruleset_id in state['organizations'][self.org_id]:
                if rule_id not in state['organizations'][self.org_id][ruleset_id]['rules'] or state['organizations'][self.org_id][ruleset_id]['rules'][rule_id] != endpoint:
                    state['organizations'][self.org_id][ruleset_id]['rules'][rule_id] = endpoint
            else:
                # Add the ruleset, then the rule thereunder with a recursive call to end up down a different code path.
                state = self._state_add_ruleset(ruleset_id, action='false', state=state)
                state = self._state_add_rule(ruleset_id, rule_id, endpoint, state)
        else:
            # Add the blank organization, then the ruleset and rule thereunder.
            state = self._state_add_organization(state)
            state = self._state_add_ruleset(ruleset_id, action='false', state=state)
            state = self._state_add_rule(ruleset_id, rule_id, endpoint, state)

        if write_state:
            write_json(self.state_file, state)
            return
        else:
            return state

    def _state_delete_rule(self, rule_id: str, state: Optional[Dict] =None) -> Optional[Dict]:
        """
        Delete a modified rule from the state file.

        Args:
            rule_id: rule ID to delete from local state file in the set organization.
            state: state file data to update. If not None, this function will commit changes to disk.

        Returns:
            The updated state data if it was provided.
        """
        write_state = not state
        if write_state:
            state = read_json(self.state_file)

        if self.org_id in state['organizations']:
            for ruleset_id in state['organizations'][self.org_id]:
                if rule_id in state['organizations'][self.org_id][ruleset_id]['rules']:
                    if len(state['organizations'][self.org_id][ruleset_id]['rules']) == 1 and state['organizations'][self.org_id][ruleset_id]['modified'] == False:
                        # This is the only rule on this ruleset and the ruleset has not been modified; remove the
                        # whole tree.
                        state['organizations'][self.org_id].pop(ruleset_id)
                    else:
                        # This is not the only rule or the containing ruleset has been modified; remove just the rule.
                        state['organizations'][self.org_id][ruleset_id]['rules'].pop(rule_id)
                    break

        if write_state:
            write_json(self.state_file, state)
            return
        else:
            return state

    # Local filesystem structure/management API.

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

    def _delete_organization(self, org_id: str) -> None:
        """
        Delete a local organization's directory if it exists.

        Args:
            org_id: organization ID to delete in the local state directory.

        Returns:
            True if there was a deletion, False otherwise.
        """
        if os.path.isdir(self.state_dir + org_id):
            # TODO: investigate whether it'd be better to call `onerror` here
            shutil.rmtree(self.organization_dir, ignore_errors=True)
            self._state_delete_organization(org_id)

        return

    def _create_ruleset(self, ruleset: Dict) -> None:
        """
        Create a local ruleset directory if it doesn't already exist.

        Args:
            ruleset: POSTable formatted ruleset data.

        Returns:
            Nothing.
        """
        # Generate a temporary UUID.
        while True:
            ruleset_id_gen = str(uuid4()) + self._postfix
            if ruleset_id_gen not in os.listdir(self.organization_dir):
                break

        ruleset_dir = f'{self.organization_dir}{ruleset_id_gen}/'
        os.mkdir(ruleset_dir)
        write_json(ruleset_dir + 'ruleset.json', ruleset)

        # Update the state file to track these changes.
        self._state_add_ruleset(ruleset_id_gen, action='true')

        return

    def _edit_ruleset(self, ruleset_id: str, ruleset_data: Dict) -> None:
        """
        Edit a local ruleset that already exists.

        Args
            ruleset_id: ruleset to edit in the local organization's directories.
            ruleset_data: ruleset data to commit to disk.

        Returns:
            Nothing.
        """
        ruleset_dir = f'{self.organization_dir}{ruleset_id}/'
        if not os.path.isdir(ruleset_dir):
            raise ValueError(f'Ruleset {ruleset_id} doesn\'t exist.')
        write_json(ruleset_dir + 'ruleset.json', ruleset_data)

        # Update the state file to track these changes.
        self._state_add_ruleset(ruleset_id, action='true')

        return

    def _delete_ruleset(self, ruleset_id: str) -> None:
        """
        Delete a local ruleset if it exists.

        Args:
            ruleset_id: ruleset to delete in the local organization's directory.

        Returns:
            True if the local deletion was successful, False otherwise.
        """
        ruleset_dir = f'{self.organization_dir}{ruleset_id}/'
        if not os.path.isdir(ruleset_dir):
            raise ValueError(f'Ruleset {ruleset_id} doesn\'t exist.')

        shutil.rmtree(ruleset_dir)
        self._state_delete_ruleset(ruleset_id, recursive=True)

    def _create_rule(self, ruleset_id: str, rule_data: Dict, tags_data: Dict) -> None:
        """
        Create a local rule directory in a ruleset in an organization's directory.

        Args:
            ruleset_id: ruleset within which to create the rule.
            rule_data: JSON rule data to commit to the generated rule ID's path in `ruleset_id`.
            tags_data: JSON tags data to commit to the generated rule ID's path in `ruleset_id`.

        Returns:
            Nothing.
        """
        # Find a suitable (temporary, local) UUID for this rule; will be updated once the state file has been pushed.
        ruleset_dir = f'{self.organization_dir}{ruleset_id}/'

        # FIXME: this should eventually be replaced for a better system of generating a new rule's (temporary) local
        #  UUID until it can be pushed to the platform and assigned a real UUID.
        while True:
            rule_id_gen = str(uuid4()) + self._postfix
            if rule_id_gen not in os.listdir(ruleset_dir):
                break

        rule_dir = f'{ruleset_dir}{rule_id_gen}/'

        write_json(rule_dir + 'rule.json', rule_data)
        write_json(rule_dir + 'tags.json', tags_data)

        # Update the state file to track these changes.
        self._state_add_rule(ruleset_id, rule_id_gen, endpoint='both')

        return

    def _edit_rule(self, ruleset_id: str, rule_id: str) -> bool:
        """
        Modify a local rule in a ruleset in an organization's directory.

        Args:
            ruleset_id: ruleset that contains the rule to be edited.
            rule_id:

        Returns:

        """

    def _delete_rule(self, rule_id: str) -> bool:
        """
        Delete a local rule directory in a ruleset in this organization's directory.

        Args:
            rule_id: rule directory ID to delete from the filesystem.

        Returns:
            True if a rule was deleted (because it existed), False otherwise.
        """
        # Attempt to locate the rule.
        for ruleset in os.listdir(self.organization_dir):
            for rule in os.listdir(self.organization_dir + ruleset):
                if rule == rule_id:
                    # TODO
                    return True
        else:
            return False

    def lst(self, colorful: bool =False) -> None:
        """
        List the ruleset and rule hierarchy under an organization, based on local state. This is meant to be
        a more human-readable view of the organization and organization's rules.

        Returns:
            Nothing.
        """
        rulesets = os.listdir(self.organization_dir)
        for ruleset in rulesets:
            ruleset_data = read_json(self.organization_dir + ruleset + '/ruleset.json')
            rule_ids = ruleset_data['rules']
            print(ruleset_data['name'], end='')
            if colorful:
                with Color.blue():
                    print(f'({ruleset})')
            else:
                print(f'({ruleset})')
            for rule_id in rule_ids:
                rule_data = read_json(self.organization_dir + ruleset + '/' + rule_id + '/rule.json')
                print(f'\t{rule_data["name"]} ({rule_data["type"]}) ', end='')
                if colorful:
                    with Color.blue():
                        print(f'({rule_id})')
                else:
                    print(f'({rule_id})')

    ## Remote state management API.

    @lazy
    def create_ruleset(self, ruleset: Dict) -> 'State':
        """
        Create a new ruleset in the current workspace.

        Args:
            ruleset: ruleset data to commit to local directory. Must be in POSTable format.

        Returns:
            A State object.
        """
        self._create_ruleset(ruleset)

    @lazy
    def create_rule(self) -> 'State':
        """
        Create a new rule from a JSON file in the current workspace.

        Args:
            ruleset_id: ruleset under which to create the new rule.
            rule_data: rule data from which to create the new rule. Must conform the the POST rule schema.
            tags_data: tags data to commit to this rule, if any. If None, the POST request is skipped.

        Returns:
            A State object.
        """

    @lazy
    def copy_rule(self, rule_id: str, ruleset_id: str) -> 'State':
        """
        Copy an existing rule in the current workspace to another ruleset in the same workspace.

        Args:
            rule_id: rule ID to copy.
            ruleset_id: destination ruleset to copy to; must reside in the current organization.

        Returns:
            A State object.
        """
        # Locate the rule in this organization.
        for ruleset in os.listdir(self.organization_dir):
            if rule_id in os.listdir(self.organization_dir + ruleset):
                rule_dir = f'{self.organization_dir}{ruleset}/{rule_id}/'
                break
        else:
            print(f'Rule ID \'{rule_id}\' not found in this organization.')
            return self

        if ruleset_id not in os.listdir(self.organization_dir):
            print(f'Destination ruleset ID \'{ruleset_id}\' not found in this organization.')
            return self
        else:
            ruleset_dir = f'{self.organization_dir}{ruleset}/'

        rule_data = read_json(rule_dir + 'rule.json')
        tags_data = read_json(rule_dir + 'tags.json')
        self._create_rule(self.org_id, ruleset_id, rule_data, tags_data)

        return self

    @lazy
    def copy_rule_out(self, rule_id: str, ruleset_id: str, org_id: str) -> 'State':
        """
        Copy an existing rule in the current workspace to another ruleset in a different workspace. This
        will trip a refresh action against the next workspace prior to copying if it doesn't already exist.

        Args:
            rule_id: rule ID to copy.
            ruleset_id: destination ruleset in a different workspace to copy this rule to.
            org_id: a different workspace to copy this rule to.

        Returns:
            A State object.
        """
        # Locate the rule in this organization.
        for ruleset in os.listdir(self.organization_dir):
            if rule_id in os.listdir(self.organization_dir + ruleset):
                rule_dir = f'{self.organization_dir}{ruleset}/{rule_id}/'
                break
        else:
            print(f'Rule ID \'{rule_id}\' not found in this organization.')
            return self

        alt_org_dir = self.state_dir + org_id + '/'

        if ruleset_id not in os.listdir(alt_org_dir):
            print(f'Destination ruleset ID \'{ruleset_id}\' not found in organization \'{org_id}\'.')
            return self
        else:
            ruleset_dir = f'{alt_org_dir}{ruleset}/'

        rule_data = read_json(rule_dir + 'rule.json')
        tags_data = read_json(rule_dir + 'tags.json')
        self._create_rule(org_id, ruleset_id, rule_data, tags_data)

        return self

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
