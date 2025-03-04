"""
Implements a logger for the fuzzer.
"""

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# set format
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# add console handler
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)
