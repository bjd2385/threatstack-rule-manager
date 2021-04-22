from typing import Type, Any, Dict, Generator, List

import logging
import json
import re

from contextlib import contextmanager
from subprocess import PIPE, Popen
from hashlib import md5


newlines = re.compile(r'\n+')


def _md5_file_hash(path: str) -> str:
    """
    Get the md5 hash of a file.

    Args:
        path: path to the file to hash.

    Returns:
        A hash of the file.
    """
    with open(path, 'r') as f:
        return md5(f.read().encode()).hexdigest()


def edit_file(exe: str, path: str) -> bool:
    """
    Method that calls subprocess to allow a user to edit a file.

    Returns:
        True if the user actually modified the file, False otherwise.
    """
    before_hash = _md5_file_hash(path)
    get_io(f'{exe} {path}')
    return _md5_file_hash(path) == before_hash


@contextmanager
def get_io(command: str) -> Generator[List[str], None, None]:
    """
    Get results from terminal commands as lists of lines of text.
    """
    with Popen(command, shell=True, stdout=PIPE, stderr=PIPE) as proc:
        stdout, stderr = proc.communicate()

    if stderr:
        raise ValueError('Command exited with errors: {}'.format(stderr))

    if stdout:
        stdout = re.split(newlines, stdout.decode())

        # For some reason, `shell=True` likes to yield an empty string.
        if stdout[-1] == '':
            stdout = stdout[:-1]

    yield stdout


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