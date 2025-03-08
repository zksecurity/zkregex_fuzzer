"""
Implements a logger for the fuzzer using a singleton pattern.
"""

import logging
import os
from datetime import datetime
from pathlib import Path


class DynamicFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.enabled = True  # Default to logging enabled

    def filter(self, record):
        return self.enabled  # Allow or block log messages

    def set_enabled(self, enabled: bool):
        """Dynamically enable or disable logging"""
        self.enabled = enabled


class LoggerSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LoggerSingleton, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize the logger instance (called only once)"""
        # Create logger
        self.logger = logging.getLogger("zkregex_fuzzer")
        self.logger.setLevel(logging.INFO)

        # Create formatter
        self.formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        # Create console handler
        self.console_handler = logging.StreamHandler()
        self.console_handler.setFormatter(self.formatter)

        # Create and add dynamic filter
        self.dynamic_filter = DynamicFilter()
        self.console_handler.addFilter(self.dynamic_filter)

        # Add handler to logger
        self.logger.addHandler(self.console_handler)

        # Set propagate to False to prevent double logging
        self.logger.propagate = False

        # File handler is initially None
        self.file_handler = None

    def enable_file_logging(self, log_path=None, disable_console=True):
        # If file logging is already enabled, remove the old handler
        if self.file_handler is not None:
            self.logger.removeHandler(self.file_handler)

        # Default log file path if none provided
        if log_path is None:
            log_path = f"zkregex_fuzzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        # Create and configure file handler
        self.file_handler = logging.FileHandler(log_path)
        self.file_handler.setFormatter(self.formatter)
        self.file_handler.addFilter(self.dynamic_filter)

        # Add to logger
        self.logger.addHandler(self.file_handler)

        # Disable console if requested
        if disable_console:
            self.console_handler.setLevel(logging.CRITICAL + 1)

        return os.path.abspath(log_path)

    def disable_file_logging(self, enable_console=True):
        if self.file_handler is not None:
            self.logger.info("File logging disabled")
            self.logger.removeHandler(self.file_handler)
            self.file_handler = None

        # Re-enable console if requested
        if enable_console:
            self.console_handler.setLevel(logging.NOTSET)

    def set_logging_enabled(self, enabled):
        self.dynamic_filter.set_enabled(enabled)

    def get_logger(self):
        return self.logger


# Create the singleton instance
_logger_instance = LoggerSingleton()

# Export the logger and functions for module-level access
logger = _logger_instance.get_logger()


def enable_file_logging(log_path=None, disable_console=True):
    return _logger_instance.enable_file_logging(log_path, disable_console)


def disable_file_logging(enable_console=True):
    _logger_instance.disable_file_logging(enable_console)


def set_logging_enabled(enabled):
    _logger_instance.set_logging_enabled(enabled)
