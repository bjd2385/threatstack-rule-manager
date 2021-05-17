"""
Test that changes to the state file cause intended results.

This is a good reference for jsonschema in Python -

https://json-schema.org/understanding-json-schema/reference/object.html
"""

import jsonschema
import unittest
import tsctl
import os


state_directory, state_file, credentials = tsctl.tsctl.config_parse()

# Retrieve from GitHub secrets.
my_org_id = os.getenv('BRANDON_ORG_ID')
alt_org_id = os.getenv('SUPPORT_TEAM_ORG_ID')


class TestStateCorrectness(unittest.TestCase):

    def test_refresh(self):
        """
        Ensure that a refresh on an organization actually clears the organization's locally-tracked state.
        """


    def test_workspace(self):
        ...

    def test_create_ruleset(self):
        ...


if __name__ == '__main__':
    unittest.main()
