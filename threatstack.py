#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A powerful Threat Stack rule manager for your terminal.
"""


from argparse import ArgumentParser, MetavarTypeHelpFormatter
from settings import env

import os


if __name__ == '__main__':
    for key in env:
        if env[key] is None:
            raise ValueError(f'Must set an environment variable for {key}')

    if not os.path.isdir('.threatstack'):
        print('INFO: Making directory \'.threatstack\' for state files and snapshots.')
        os.mkdir('.threatstack')

    parser = ArgumentParser(description=__doc__,
                            formatter_class=MetavarTypeHelpFormatter,
                            epilog='Note that "-" may be substituted in place of SNAPSHOT IDs to query the current local state (or state snapshot history).')

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-l', '--list', dest='list', nargs=3, type=str, metavar=('SNAPSHOT', '[ RULESET', '[ RULE ] ]'),
        help='List snapshots, rulesets and rules'
    )

    # TODO: update this to accept redirection (say, if you modify a rule with jq and then pipe it into the program)
    group.add_argument(
        '-c', '--create', dest='create', nargs=2, type=str, metavar=('RULESET', 'FILE'),
        help='Create a new rule from a JSON file.'
    )

    group.add_argument(
        '-u', '--update', dest='update', nargs=3, type=str, metavar=('RULESET', 'RULE', 'FILE'),
        help='Update a rule in a ruleset with a rule in a JSON file.'
    )

    group.add_argument(
        '-U', '--update-suppression', dest='suppression', nargs=3, type=str, metavar=('RULESET', 'RULE', 'FILE'),
        help='Update a suppression on a rule.'
    )

    group.add_argument(
        '-C', '--copy', dest='copy', nargs=3, type=str, metavar=('RULESET', 'RULE', 'RULESET'),
        help='Copy a rule from one ruleset to another.'
    )

    group.add_argument(
        '-K', '--copy-ruleset', dest='copy_ruleset', nargs=2, type=str, metavar=('RULESET', 'NEWNAME'),
        help='Copy an entire ruleset with a new name.'
    )

    group.add_argument(
        '-s', '--snapshot', dest='snapshot', nargs=2, type=str, metavar=('[ RULESET', '[ RULE ] ]'),
        help='Snapshot a rule, ruleset, or all rulesets and rules therein across an organization'
    )

    group.add_argument(
        '-r', '--refresh', dest='refresh', action='store_true',
        help='Refresh our local state file of the organization\'s rules.'
    )

    group.add_argument(
        '-v', '--view', dest='view', type=str, nargs=3, metavar=('SNAPSHOT', '[ RULESET', '[ RULE ] ]'),
        help='View a rule from a state file.'
    )

    group.add_argument(
        '-R', '--restore', dest='restore', type=str, metavar=('SNAPSHOT',),
        help='Restore an organization\'s rulesets to a captured state file.'
    )

    group.add_argument(
        '-d', '--diff', dest='diff', type=str, nargs=2, metavar=('SNAPSHOT', 'SNAPSHOT'),
        help='Diff two snapshots.'
    )

    group.add_argument(
        '-S', '--switch', dest='switch', type=str, metavar=('ORGID',),
        help='Set the organization ID within which you are working.'
    )

    options = vars(parser.parse_args())
    print(options)
