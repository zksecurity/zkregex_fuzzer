"""
Runners for regex implementations.

Supported runners:
- Python re module

TODO:
- Circom runner
- Noir runner
"""

from abc import ABC, abstractmethod


class RegexCompileError(Exception):
    """
    Exception raised when a regex cannot be compiled.
    """
    pass


class RegexRunError(Exception):
    """
    Exception raised when a regex cannot be run.
    """
    pass


class Runner(ABC):
    """
    Abstract base class for regex runners.
    """

    def __init__(self, regex: str, kwargs: dict):
        self._regex = regex
        self._runner = "Abstract runner"
        self._regex_object = self.compile(regex)

    @abstractmethod
    def compile(self, regex: str) -> None:
        """
        Compile a regex.
        """
        pass

    @abstractmethod
    def match(self, input: str) -> tuple[bool, str]:
        """
        Match the regex on an input.
        """
        pass

    @abstractmethod
    def clean(self) -> None:
        """
        Clean any produced temporary files.
        """
        pass

    @abstractmethod
    def save(self, path: str) -> str:
        """
        Save any produced temporary files.
        """
        return ""

