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


class Color:
    """
    `xterm` colors for coloring fonts written to stdout.
    """
    def __init__(self, color: str, string: str ='') -> None:
        self.color = color
        self.string = string

    ## Colors

    @classmethod
    def red(cls: Type['Color']) -> 'Color':
        return cls('\033[31;1m')

    @classmethod
    def blue(cls: Type['Color']) -> 'Color':
        return cls('\033[34m')

    @classmethod
    def yellow(cls: Type['Color']) -> 'Color':
        return cls('\033[33m')

    @classmethod
    def green(cls: Type['Color']) -> 'Color':
        return cls('\033[32m')

    @classmethod
    def gray(cls: Type['Color']) -> 'Color':
        return cls('\033[8m;1m')

    @classmethod
    def normal(cls: Type['Color']) -> 'Color':
        return cls('\033[0m')

    ## Effects

    @classmethod
    def bold(cls: Type['Color']) -> 'Color':
        return cls('\033[1m')

    @classmethod
    def italicize(cls: Type['Color']) -> 'Color':
        return cls('\033[3m')

    def __enter__(self) -> None:
        print(self.color + self.string, end='', sep='')

    def __exit__(self, *args: Any) -> Any:
        print('\033[0m', end='', sep='')