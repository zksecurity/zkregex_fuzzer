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

    def match(self, input: str) -> tuple[bool, str]:
        """
        Match the regex on an input.
        """
        try:
            match_input = self._compiled_regex.match(input)
            match_success = match_input is not None
            str_result = match_input[0] if match_success else ""
            return (match_success, str_result)
        except re.error as e:
            raise RegexRunError(f"Error matching regex: {e}")
        
    def save(self, path: str) -> str:
        return ""
    
    def clean(self) -> None:
        return None