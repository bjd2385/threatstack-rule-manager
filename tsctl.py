#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A powerful Threat Stack rule manager for your terminal.
"""


from argparse import ArgumentParser, MetavarTypeHelpFormatter
from settings import env
from state_manager import State

import os


if __name__ == '__main__':
    for key in env:
        if env[key] is None:
            raise ValueError(f'Must set an environment variable for {key}')

    if not os.path.isdir('.threatstack'):
        print('INFO: Making directory \'.threatstack\' for local state.')
        os.mkdir('.threatstack')

    parser = ArgumentParser(description=__doc__,
                            formatter_class=MetavarTypeHelpFormatter,
                            epilog='Please remember to commit your changes to a git repository to maintain version control.')

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-l', '--list', dest='list', nargs=2, type=str, metavar=('RULESET', '[ RULE ]'),
        help='List rulesets and (view) rules'
    )

    group.add_argument(
        '-C', '--create-ruleset', dest='create_ruleset', nargs=1, type=str, metavar=('FILE'),
        help='Create a new ruleset in the configured org.'
    )

    # TODO: update this to accept redirection (say, if you modify a rule with jq and then pipe it into the program)
    group.add_argument(
        '-c', '--create-rule', dest='create', nargs=2, type=str, metavar=('RULESET', 'FILE'),
        help='Create a new rule from a JSON file.'
    )

    group.add_argument(
        '-u', '--update', dest='update', nargs=3, type=str, metavar=('RULESET', 'RULE', 'FILE'),
        help='Update a rule in a ruleset with a rule in a JSON file.'
    )

    group.add_argument(
        '-s', '--update-suppression', dest='suppression', nargs=3, type=str, metavar=('RULESET', 'RULE', 'FILE'),
        help='Update a suppression on a rule.'
    )

    # TODO: explore potentially removing the necessity to add the source ruleset, all rules have unique IDs.
    group.add_argument(
        '-n', '--copy', dest='copy', nargs=2, type=str, metavar=('RULE', 'RULESET'),
        help='Copy a rule from one ruleset to another (in the same organization).'
    )

    group.add_argument(
        '-N', '--copy-out', dest='copy_out', nargs=3, type=str, metavar=('RULE', 'RULESET', )
    )

    group.add_argument(
        '-K', '--copy-ruleset', dest='copy_ruleset', nargs=2, type=str, metavar=('RULESET', 'NEWNAME'),
        help='Copy an entire ruleset with a new name.'
    )

    group.add_argument(
        '-r', '--refresh', dest='refresh', action='store_true',
        help='Refresh our local state of the organization\'s rules.'
    )

    group.add_argument(
        '-p', '--push', dest='restore', type=str, metavar=('SNAPSHOT',),
        help='Push local state to the organization.'
    )

    group.add_argument(
        '-w', '--workspace', dest='switch', type=str, metavar=('ORGID',),
        help='Set the organization ID within which you are working, automatically starts a refresh.'
    )

    options = vars(parser.parse_args())
    print(options)

    manager = State(**options)