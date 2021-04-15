"""
Manage API calls to TS.
"""

from typing import Optional, Dict, Callable


class API:
    """
    API object that provides an interface to the remote organizations' state.
    """
    def __init__(self, user: str, key: str, ext: str) -> None:
        self.__user = user
        self.__key = key
        self.__ext = ext

    def _get(self) -> Optional[Dict]:
        ...

    def _put(self) -> Optional[Dict]:
        ...

    def _delete(self) -> Optional[Dict]:
        ...

    def _post(self) -> Optional[Dict]:
        ...

def paginate(f: Callable) -> Optional[Dict]:
    ...