"""
Unittests related to ensuring the (~private) state file methods on tsctl.state.State._state_* conform to the expected
schema for all potential (expected) inputs. Since these methods have the ability to accept an optional dictionary of
JSON state file data, and they'll return the modified version if called with one, we can test that the output modified
state data is in the expected schema.
"""

import unittest

from tsctl.state import State
from tsctl.tsctl import config_parse
from tsctl.utils import read_json
from random import choice
from string import ascii_lowercase, digits


class TestStateTotality(unittest.TestCase):
    def __init__(self) -> None:
        super().__init__()
        _, state_directory, state_file, credentials = config_parse()
        self.state_directory = state_directory
        self.state_file = state_file
        self.credentials = credentials

        # Generate a test organization ID for local-only tests, we won't be making any actual API calls. Lazy eval.
        self.localonly_org_id = ''.join(choice(ascii_lowercase + digits) for _ in range(0x10))

        # Remote ID (my organization).
        # FIXME: Define a .env in this directory and read it from disk. Not the best work-around, but I'd rather
        #  avoid committing any secrets to git. Will probably change once I have tests running on GitHub.
        with open('.env', 'r') as f:
            self.org_id = f.read()

    # Local-only

    def test_create_ruleset(self) -> None:
        """
        Create a ruleset and ensure the state file conforms to the proper schema, as well as values are what they
        should be.
        """

    def test_delete_ruleset(self) -> None:
        """
        Let's try to delete the ruleset we just created.
        """

    # Local and remote


if __name__ == '__main__':
    unittest.main()
