"""
Implements a logger for the fuzzer.
"""

import logging


class DynamicFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.enabled = True  # Default to logging enabled

    def filter(self, record):
        return self.enabled  # Allow or block log messages

    def set_enabled(self, enabled: bool):
        """Dynamically enable or disable logging"""
        self.enabled = enabled


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# set format
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# add console handler
ch = logging.StreamHandler()
ch.setFormatter(formatter)

# Create and add the dynamic filter
dynamic_filter = DynamicFilter()
ch.addFilter(dynamic_filter)
logger.addHandler(ch)
