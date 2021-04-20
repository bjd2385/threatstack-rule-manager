"""
Unittests related to ensuring the (~private) state file methods on tsctl.state.State._state_* conform to the expected
schema for all potential (expected) inputs. Since these methods have the ability to accept an optional dictionary of
JSON state file data, and they'll return the modified version if called with one, we can test that the output modified
state data is in the expected schema.
"""

from unittest import TestCase
from tsctl.state import State


class TestStateTotality(TestCase):
    def test_rule_create(self) -> None:
        ...

    def test_ruleset_create(self) -> None:
        ...


if __name__ == '__main__':
    unittest.main()
