"""
Runner for Python re module.
"""

import re
from zkregex_fuzzer.runner.base_runner import Runner, RegexCompileError, RegexRunError


class PythonReRunner(Runner):
    """
    Runner that uses the Python re module.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)
        self._runner = "Python re module"

    def compile(self, regex: str) -> None:
        """
        Compile the regex.
        """
        try:
            self._compiled_regex = re.compile(regex)
        except re.error as e:
            raise RegexCompileError(f"Error compiling regex: {e}")

    def match(self, input: str) -> bool:
        """
        Match the regex on an input.
        """
        try:
            return self._compiled_regex.match(input) is not None
        except re.error as e:
            raise RegexRunError(f"Error matching regex: {e}")