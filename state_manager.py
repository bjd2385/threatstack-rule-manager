from typing import Dict

import requests
import json
import logging
import csv

from mohawk import Sender
from urllib.error import URLError
from settings import env
from utils import retry


class State:
    """
    Manage the local file tree/workspace and answer CLI options.
    """
    def __init__(self, org_id: str, user_id: str, api_key: str, lazy: bool =False,
                 base: str ='~/.threatstack') -> None:
        self.__org_id = org_id
        self.__user_id = user_id
        self.__api_key = api_key
        self.lazy = lazy
        self.base = base

    def lst(self) -> 'State':
        """
        List the ruleset and rule hierarchy under an organization.

        Returns:
            A State object.
        """

    def create_rulesets(self, filename: str) -> 'State':
        """
        Create a new ruleset in the current workspace.

        Returns:
            A State object.
        """

    def create_rule(self, ruleset_id: str, filename: str) -> 'State':
        """
        Create a new rule from a JSON file in the current workspace.

        Returns:
            A State object.
        """

    def copy_rule(self, rule_id: str, ruleset_id: str) -> 'State':
        """
        Copy an existing rule in the current workspace to a new one (same ruleset or not).

        Returns:
            A State object.
        """

    def copy_rule_out(self, rule_id: str, ruleset_id: str, org_id: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def copy_ruleset(self, ruleset_id: str, newname: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def copy_ruleset_out(self, ruleset_id: str, org_id: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def update_rule(self, ruleset_id: str, rule_id: str, filename: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def update_ruleset(self, ruleset_id: str, filename: str) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def refresh(self) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def push(self) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    def workspace(self) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """