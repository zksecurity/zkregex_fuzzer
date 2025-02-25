"""
Runners for regex implementations.

Supported runners:
- Python re module

TODO:
- Circom runner
- Noir runner
"""

from abc import ABC, abstractmethod

import re


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

    def __init__(self, regex: str):
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
    def match(self, input: str) -> bool:
        """
        Match the regex on an input.
        """
        pass

    def clean(self) -> None:
        """
        Clean any produced temporary files.
        """
        pass

    def save(self, path: str) -> None:
        """
        Save any produced temporary files.
        """
        pass
    
    
class PythonReRunner(Runner):
    """
    Runner that uses the Python re module.
    """

    def __init__(self, regex: str):
        super().__init__(regex)
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

class CircomRunner(Runner):
    """
    Runner that uses the Circom compiler.
    """

    def __init__(self, regex: str):
        super().__init__(regex)
        self._runner = "Circom"
        self._run_the_prover = True
        self._path = None

    def compile(self, regex: str) -> None:
        """
        Compile the regex.
        """
        # TODO: Implement Circom runner
        # 0. Create JSON for the regex for zk-regex 
        # 1. Call zk-regex to generate the circom code
        # 2. Compile the circom code
        # 3. Save the circom code to a file in a temporary directory
        # 4. Save the circom executable to a field
        raise NotImplementedError("Circom runner not implemented")

    def match(self, input: str) -> bool:
        """
        Match the regex on an input.
        """
        # TODO: Implement Circom runner
        # 1. Call the witness generator
        # 2. Call the prover
        # 3. Call the verifier
        # 4. Check if everything worked
        # 5. Extract from the witness the result of the match
        # 6. Return the result
        raise NotImplementedError("Circom runner not implemented")