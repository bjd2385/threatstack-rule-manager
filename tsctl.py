#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A powerful Threat Stack rule manager for your terminal.
"""

from typing import Tuple, Dict

from argparse import ArgumentParser, MetavarTypeHelpFormatter
from state_manager import State

import logging
import configparser
import os
import json


def initialize_state_directory() -> Tuple[str, str, Dict[str, str]]:
    """
    Initialize the state directory in the user's home directory.

    Returns:
        A tuple of the base state directory path (within which all organization changes will be made) and the state
        file path (where these changes will be tracked).
    """
    home = os.path.expanduser('~') + '/'
    conf = home + '.threatstack.conf'

    parser = configparser.ConfigParser()
    parser.read(conf)

    # Collect default options, such as laziness.
    if parser.default_section in parser.sections():
        ...

    # Set up the local state directory and a default state file, if it doesn't exist.
    if 'STATE' in parser.sections():
        state_section = parser['STATE']
        state_directory = state_section.get('STATE_DIR', fallback='.threatstack')
        state_file = state_section.get('STATE_FILE', fallback='.threatstack.state.json')
    else:
        state_directory = '.threatstack'
        state_file = '.threatstack.state.json'

    state_directory_path = home \
                            + ('/' if not (home.endswith('/') or state_directory.startswith('/')) else '') \
                            + ((state_directory + '/') if not state_directory.endswith('/') else state_directory)
    state_file_path = state_directory_path + state_file

    if not os.path.isdir(state_directory_path):
        logging.debug(f'Making directory \'{state_directory}\' for local state.')
        os.mkdir(state_directory_path)
    else:
        logging.debug(f'Using state directory \'{state_directory_path}\' for local state')

    if not os.path.isfile(state_file_path) or os.path.getsize(state_file_path) < 17:
        # Write the base config to local state.
        logging.debug(f'Initializing state directory tree.')
        with open(state_file_path, 'w+') as f:
            json.dump({'workspace': ''}, f)
    else:
        # TODO: Ensure the existing file at least conforms to the required schema.
        ...

    # Collect credentials from the rest of the conf or from env.
    if 'CREDENTIALS' in parser.sections():
        credentials = parser['CREDENTIALS']
        if 'USER_ID' not in credentials or 'API_KEY' not in credentials:
            logging.error(f'Must set values for \'USER_ID\' and \'API_KEY\' in \'{conf}\' under CREDENTIALS header')
            exit(1)
        else:
            credentials = {
                'user_id': credentials['USER_ID'],
                'api_key': credentials['API_KEY']
            }
    else:
        try:
            assert(all(os.getenv(v) is not None for v in ('USER_ID', 'API_KEY')))
        except AssertionError:
            logging.error(f'Must set environment variables for \'USER_ID\' and \'API_KEY\' or define them in \'{conf}\'')
            exit(1)
        credentials = {
            'user_id': os.getenv('USER_ID'),
            'api_key': os.getenv('API_KEY')
        }

    return state_directory_path, state_file_path, credentials


def workspace(state_file: str, org_id: str, credentials: Dict[str, str]) -> State:
    """
    Change the current workspace by updating the organization ID in the state file.

    Args:
        state_file: location of the state file to be parsed from disk and updated.
        org_id: organization ID to change the current workspace to.

    Returns:
        A State object.
    """
    with open(state_file, 'r+') as f:
        state = json.load(f)
        state['workspace'] = org_id
        f.seek(0)
        json.dump(state, f)

    new_state = State(
        
    )

    new_state.refresh()


def diff(self, file: str) -> Dict:
    """
    Output a nicely formatted diff of local state and the remote/platform state for the current workspace. This
    function essentially allows you to view the local state file that tracks what is to be pushed, based on the
    last refresh's returns at the organizations' level.

    Args:
        file: location of the state file.

    Returns:
        A dictionary with the following schema ~
        TODO: complete this schema
    """


def main() -> None:
    state_directory, state_file, credentials = initialize_state_directory()

    parser = ArgumentParser(description=__doc__,
                            formatter_class=MetavarTypeHelpFormatter,
                            epilog=f'Please remember to commit your changes on \'{state_directory}\' to a git repository to maintain version control.')

    # FIXME: there's probably a bug on calls to `add_mutually_exclusive_group` in that required arguments are evaluated
    #  or parser before discerning that more than one flag in the mutually exclusive group was defined.
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-l', '--list', dest='list', action='store_true',
        help='List rulesets and (view) rules'
    )

    group.add_argument(
        '-a', '--create-ruleset', dest='create_ruleset', nargs=1, type=str, metavar=('FILE',),
        help='(lazy) Create a new ruleset in the configured org.'
    )

    # TODO: update this to accept redirection (say, if you modify a rule with jq and then pipe it into the program)
    group.add_argument(
        '-c', '--create-rule', dest='create', nargs=2, type=str, metavar=('RULESET', 'FILE'),
        help='(lazy) Create a new rule from a JSON file.'
    )

    group.add_argument(
        '-n', '--copy-rule', dest='copy', nargs=2, type=str, metavar=('RULE', 'RULESET'),
        help='(lazy) Copy a rule from one ruleset to another (in the same organization).'
    )

    group.add_argument(
        '-N', '--copy-rule-out', dest='copy_out', nargs=3, type=str, metavar=('RULE', 'RULESET', 'ORGID'),
        help='(lazy) Copy a rule from the current workspace to a ruleset in a different organization.'
    )

    group.add_argument(
        '-m', '--copy-ruleset', dest='copy_ruleset', nargs=2, type=str, metavar=('RULESET', 'NEWNAME'),
        help='(lazy) Copy an entire ruleset with a new name to the same workspace.'
    )

    group.add_argument(
        '-M', '--copy-ruleset-out', dest='copy_ruleset', nargs=2, type=str, metavar=('RULESET', 'ORGID'),
        help='(lazy) Copy an entire ruleset in the current workspace to a different organization.'
    )

    group.add_argument(
        '-u', '--update-rule', dest='update', nargs=3, type=str, metavar=('RULESET', 'RULE', 'FILE'),
        help='(lazy) Update a rule in a ruleset with a rule in a JSON file.'
    )

    group.add_argument(
        '-U', '--update-ruleset', dest='update_ruleset', nargs=2, type=str, metavar=('RULESET', 'FILE'),
        help='(lazy) Update a ruleset from a JSON file.'
    )

    group.add_argument(
        '-d', '--delete-rule', dest='delete_rule', nargs=1, type=str, metavar=('RULE',),
        help='(lazy) Delete a rule from the current workspace.'
    )

    group.add_argument(
        '-D', '--delete-ruleset', dest='delete_ruleset', nargs=1, type=str, metavar=('RULESET',),
        help='(lazy) Delete a ruleset from the current workspace.'
    )

    group.add_argument(
        '-r', '--refresh', dest='refresh', action='store_true',
        help='Refresh our local state of the organization\'s rules.'
    )

    group.add_argument(
        '-p', '--push', dest='push', action='store_true',
        help='Push local state to remote state.'
    )

    group.add_argument(
        '-F', '--diff', dest='diff', action='store_true',
        help='View the state file, or the difference between the local state and remote state.'
    )

    group.add_argument(
        '-w', '--workspace', dest='switch', type=str, metavar=('ORGID',),
        help='Set the organization ID within which you are working, automatically starts a refresh.'
    )

    options = vars(parser.parse_args())
    print(options)

    if options['diff']:
        with open(state_file, 'r') as f:
           print(json.dumps(json.load(f), indent=2))
    elif options['switch']:
        org_id = options['switch']
        workspace(state_file, org_id, credentials)


if __name__ == '__main__':
    main()
