#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from dotenv import load_dotenv

load_dotenv()

import os

__all__ = [
    'env'
]


log_level = os.getenv('LOGLEVEL')
if not log_level:
    log_level = 'WARNING'


env = {
    'API_KEY': os.getenv('API_KEY'),
    'API_ID': os.getenv('API_ID'),
    'LOGLEVEL': log_level.upper()
}
