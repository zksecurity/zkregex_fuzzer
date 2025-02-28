"""
Valid Input Generator. 

Supported generators:

- Grammar Based Generator
- Existing Python Modules (rstr.xeger, exrex.getone)
- DFA random walk (TODO)
"""

from abc import ABC, abstractmethod
from typing import List

from zkregex_fuzzer.utils import check_if_string_is_valid, grammar_fuzzer
from zkregex_fuzzer.transformers import regex_to_grammar
from zkregex_fuzzer.logger import logger

import rstr
import exrex


class ValidInputGenerator(ABC):
    """
    Generate valid inputs for a regex.
    """

    def __init__(self, regex: str):
        self.regex = regex
        self._max_attempts = 10
        self._generated_strings = set()

    def _generate(self) -> str:
        """
        Generate a valid input for the regex.
        """
        attempts = 0
        while attempts < self._max_attempts:
            string = self.generate_unsafe()
            if string in self._generated_strings:
                attempts += 1
                continue
            self._generated_strings.add(string)
            if check_if_string_is_valid(self.regex, string):
                return string
            attempts += 1
        raise ValueError("Failed to generate a valid input for the regex.")

    def generate_many(self, n: int) -> List[str]:
        """
        Generate n valid inputs for the regex.

        In case the generator fails to generate a valid input, it will raise an error.
        If the generator is able to generate less than n valid inputs, 
        it will silently return the number of valid inputs generated.
        """
        logger.debug("Start generating valid inputs.")
        valid_inputs = []
        attempts = 0
        logger.debug(f"Generating {n} valid inputs for the regex: {self.regex} with {self._max_attempts} attempts using {self.__class__.__name__}.")
        while len(valid_inputs) < n and attempts < self._max_attempts:
            try:
                logger.debug(f"Generating valid input {len(valid_inputs) + 1} of {n}.")
                valid_inputs.append(self._generate())

            except ValueError:
                pass
            attempts += 1
        if len(valid_inputs) == 0:
            raise ValueError("Failed to generate any valid input for the regex.")
        #logger.debug(f"Generated valid inputs for the regex: {valid_inputs}.")
        logger.debug("Finished generating valid inputs.")
        return valid_inputs

    @abstractmethod
    def generate_unsafe(self) -> str:
        """
        Generate a valid input for the regex without checking if it is valid.
        """
        pass

class GrammarBasedGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using a grammar.
    """
    def __init__(self, regex: str):
        super().__init__(regex)
        self.grammar = regex_to_grammar(regex)
        self._start_symbol = "<start>"
        self._max_nonterminals = 10
        self._max_expansion_trials = 100

    def generate_unsafe(self) -> str:
        return grammar_fuzzer(self.grammar,
                           start_symbol=self._start_symbol,
                           max_nonterminals=self._max_nonterminals,
                           max_expansion_trials=self._max_expansion_trials)

class RstrGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using rstr.xeger.
    """
    def __init__(self, regex: str):
        super().__init__(regex)

    def generate_unsafe(self) -> str:
        return rstr.xeger(self.regex)

class ExrexGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using exrex.getone.
    """
    def __init__(self, regex: str):
        super().__init__(regex)

    def generate_unsafe(self) -> str:
        return exrex.getone(self.regex)
