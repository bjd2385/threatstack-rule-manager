from typing import Type, Callable, Any, Dict

import logging
import json
import os

from functools import wraps
from time import sleep


def read_json(file: str) -> Dict:
    """
    Common function for reading JSON from disk into a Python dictionary.

    Args:
        file: location of file to read in from disk.

    Returns:
        The file's contents as a Python Dict.
    """
    with open(file, 'r') as f:
        return json.load(f)


def write_json(file: str, data: Dict) -> None:
    """
    Common function for writing a Python dictionary as JSON to disk; overwrites files if they already exist.

    Args:
        file: location of file to write (or overwrite).
        data: dictionary to write to disk.

    Returns:
        Nothing
    """
    with open(file, 'w') as f:
        json.dump(data, f)
