# https://www.python.org/dev/peps/pep-0440/
__version__ = '0.0.1a1'

# Defining lazy evaluation here so it may be accessible throughout the module.
lazy_eval = True

from .tsctl import main

import logging

logger = logging.Logger
