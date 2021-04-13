from typing import Any

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
    def __init__(self, org_id: str, user_id: str, api_key: str):
        self.__org_id = org_id
        self.__user_id = user_id
        self.__api_key = api_key

    @classmethod
    def lst(cls, *args: Any, **kwargs: Any) -> 'State':
        """
        List the ruleset and rule hierarchy under an organization.

        Returns:
            A State object.
        """

    @classmethod
    def create_ruleset(cls) -> 'State':
        """
        Create a new ruleset in the configured org.

        Returns:
            A State object.
        """

    @classmethod
    def create_rule(cls) -> 'State':
        """
        Create a new rule from a JSON file.

        Returns:
            A State object.
        """

    @classmethod
    def update(cls) -> 'State':
        """
        Update a rule in a ruleset with a rule in a JSON file.

        Returns:
            A State object.
        """

    @classmethod
    def update_suppression(cls) -> 'State':
        """
        Update a suppression on a rule.

        Returns:
            A State object.
        """

    @classmethod
    def copy_rule(cls) -> 'State':
        """
        Copy a rule from one rule set to another, either within this organization, or to a new one.

        Returns:
            A State object.
        """

    @classmethod
    def copy_ruleset(cls) -> 'State':
        """
        Copy a ruleset to either a new name in the same organization, or another organization entirely.

        Returns:
            A State object.
        """

    @classmethod
    def workspace(cls) -> 'State':
        """
        Switch or set the org. ID.

        Returns:
            A State object.
        """
