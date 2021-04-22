"""
Unittests that ensure the metastate metaclass is performing as intended.
"""


import unittest

from tsctl.state import MetaState
from random import choice
from string import ascii_lowercase, digits


class _State(metaclass=MetaState):
    """
    Example tester class that accepts a single, required kwarg.
    """
    def __init__(self, *, org_id: str) -> None:
        self.org_id = org_id


class TestMetaState(unittest.TestCase):
    def __init__(self) -> None:
        super().__init__()
        self.chars = ascii_lowercase + digits

    def test_duplicate_state_instances(self) -> None:
        """
        Ensure that we get the same State instance in return under the same org. ID.
        """
        one_org_id = ''.join(choice(self.chars) for _ in range(0x18))
        while (two_org_id := ''.join(choice(self.chars) for _ in range(0x18))) == one_org_id: pass

        # FIXME: I want to test to ensure metastate is working correctly, but I can't without using two legitimate org. IDs. Wonder how I could bypass the org. refreshes.
        self.assertIs(
            _State(org_id=one_org_id),
            _State(org_id=two_org_id)
        )
