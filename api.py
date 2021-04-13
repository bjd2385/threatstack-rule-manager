"""
Manage API calls to TS.
"""

from typing import Optional, Dict, Callable


def paginate(f: Callable) -> Optional[Dict]:
    ...


def get() -> Optional[Dict]:
    ...



def put() -> Optional[Dict]:
    ...


def delete() -> Optional[Dict]:
    ...


def post() -> Optional[Dict]:
    ...