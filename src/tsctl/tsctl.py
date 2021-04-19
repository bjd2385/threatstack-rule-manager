"""
A Threat Stack rule manager for your terminal.
"""

from typing import Tuple, Dict

from argparse import ArgumentParser, MetavarTypeHelpFormatter
from textwrap import dedent
from .state import State
from .utils import read_json, write_json
from . import __version__

import logging
import configparser
import os
import json


def config_parse() -> Tuple[str, str, Dict[str, str]]:
    """
    Initialize the state directory in the user's home directory and parse config options.

    Returns:
        A tuple of the base state directory path (within which all organization changes will be made) and the state
        file path (where these changes will be tracked), as well as API credentials.
    """
    home = os.path.expanduser('~') + '/'
    conf = home + '.threatstack.conf'

    # If this configuration file is not present, write a default one.
    if not os.path.isfile(conf):
        default_conf_file = dedent(
            """
            [DEFAULT]
            LAZY_EVAL = true
            LOGLEVEL = ERROR
            
            [STATE]
            STATE_DIR = .threatstack
            STATE_FILE = .threatstack.state.json
            """
        )[1:]
        with open(conf, 'w') as f:
            f.write(default_conf_file)

    parser = configparser.ConfigParser()
    parser.read(conf)

    # Collect default options, such as laziness and log level.
    try:
        default_section = parser['DEFAULT']
        lazy_evaluation = default_section.get('LAZY_EVAL', fallback=True)
        loglevel = default_section.get('LOGLEVEL', fallback='ERROR')
    except 
    else:
        print(f'Must define DEFAULT section in \'{conf}\'.')
        exit(1)

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

    if not os.path.isfile(state_file_path) or os.path.getsize(state_file_path) < 62:
        # Write the base config to local state.
        logging.debug(f'Initializing state directory tree.')
        write_json(
            state_file_path,
            {
                'workspace': '',
                'organizations': []
            }
        )
    else:
        # TODO: Ensure the existing file at least conforms to the required schema.
        ...

    # Collect credentials from the rest of the conf or from env.
    if 'CREDENTIALS' in parser.sections():
        credentials = parser['CREDENTIALS']
        if 'USER_ID' not in credentials or 'API_KEY' not in credentials:
            logging.error(f'Must set values for \'USER_ID\' and \'API_KEY\' in \'{conf}\' under CREDENTIALS section.')
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
            logging.error(f'Must set environment variables for \'USER_ID\' and \'API_KEY\' or define them in \'{conf}\' under CREDENTIALS section.')
            exit(1)
        credentials = {
            'user_id': os.getenv('USER_ID'),
            'api_key': os.getenv('API_KEY')
        }

    return lazy_evaluation, state_directory_path, state_file_path, credentials


def vcs_gitignore(state_dir: str, state_file_name: str) -> None:
    """
    Drop a default `.gitignore` in the state directory to ignore unimportant files in the event a user wants to start
    using VCS.

    Args:
        state_dir: directory all state is stored within (likely ~/.threatstack/).

    Returns:
        Nothing.
    """
    files = [
        state_file_name
    ]
    with open(state_dir + '.gitignore', 'w+') as f:
        for file in files:
            f.write(file + '\n')


def workspace(state_dir: str, state_file: str, org_id: str, credentials: Dict[str, str]) -> State:
    """
    Change the current workspace by updating the organization ID in the state file.

    Args:
        state_dir: location of the state directory.
        state_file: location of the state file to be parsed from disk and updated.
        org_id: organization ID to change the current workspace to.
        credentials: if lazy evaluation is disabled and live changes are pushed, credentials are necessary.

    Returns:
        A State object.
    """
    state = read_json(state_file)
    state['workspace'] = org_id
    write_json(state_file, state)
    new_state = State(state_dir, state_file, org_id, **credentials)
    return new_state


def plan(state_file: str) -> None:
    """
    Output a nicely formatted plan of local state and the remote/platform state for the current workspace. This
    function basically just allows you to view the local state file that tracks what is to be pushed, based on the
    last refresh's returns at the organizations' level.

    Args:
        state_file: location of the state file.

    Returns:
        Nothing.
    """
    with open(state_file, 'r') as f:
        print(json.dumps(json.load(f), indent=2))


def main() -> None:
    lazy_evaluation, state_directory, state_file, credentials = config_parse()
    vcs_gitignore(state_directory, state_file.split('/')[-1])

    parser = ArgumentParser(description=__doc__,
                            formatter_class=MetavarTypeHelpFormatter,
                            epilog=f'Remember to commit and push your changes on \'{state_directory}\' to a git repository to maintain version control.')

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
        '-t', '--update-tags', dest='create_tag', nargs=2, type=str, metavar=('RULE', 'FILE'),
        help='(lazy) Create or update tags on a rule.'
    )

    group.add_argument(
        '-r', '--refresh', dest='refresh', action='store_true',
        help='Refresh local copy of the organization\'s rules and flush local state.'
    )

    group.add_argument(
        '-p', '--push', dest='push', action='store_true',
        help='Push local state to remote state (across all organizations).'
    )

    group.add_argument(
        '-s', '--plan', dest='plan', action='store_true',
        help=f'View the state file, or the tracked difference between local state and remote state.'
    )

    group.add_argument(
        '-w', '--workspace', dest='switch', type=str, metavar=('ORGID',),
        help='Set the organization ID within which you are working, automatically starts a refresh.'
    )

    parser.add_argument(
        '--colorful', dest='color', action='store_true',
        help='Add xterm coloring to output. Only works on certain commands (--list).'
    )

    group.add_argument(
        '-v', '--version', dest='version', action='store_true',
        help='Print the version of \'tsctl\'.'
    )

    options = vars(parser.parse_args())

    if options['list']:
        state = read_json(state_file)
        org_id = state['workspace']
        if not org_id:
            print('Must set a workspace/organization ID (--workspace) to list rulesets and rules.')
            exit(1)
        organization = State(state_directory, state_file, org_id, **credentials)
        organization.lst(colorful=options['color'])
    elif options['refresh']:
        state = read_json(state_file)
        org_id = state['workspace']
        if not org_id:
            print('Must set a workspace/organization ID (--workspace) to automatically refresh.')
            exit(1)
        organization = State(state_directory, state_file, org_id, **credentials)
        organization.refresh()
    elif options['plan']:
        plan(state_file)
    elif options['switch']:
        org_id = options['switch']
        workspace(state_directory, state_file, org_id, credentials)
    elif options['version']:
        print(f'tsctl v{__version__}')
