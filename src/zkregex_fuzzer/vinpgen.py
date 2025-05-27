"""
Valid Input Generator.

Supported generators:

- Grammar Based Generator
- Existing Python Modules (rstr.xeger, exrex.getone)
- DFA random walk (TODO)
"""

import random
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import List, Optional

import exrex
import rstr

from zkregex_fuzzer.dfa import dfa_string_matching
from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.transformers import regex_to_grammar
from zkregex_fuzzer.utils import check_if_string_is_valid, grammar_fuzzer, pretty_regex


class MaxStringGenerationAttemptsExceeded(Exception):
    """
    Exception raised when the maximum number of string generation attempts is exceeded.
    """

    pass


class MaxConsecutiveFailuresExceeded(Exception):
    """
    Exception raised when the maximum number of consecutive failures is exceeded.
    """

    pass


class MaxAttemptsExceeded(Exception):
    """
    Exception raised when the maximum number of attempts is exceeded.
    """

    pass


class ValidInputGenerator(ABC):
    """
    Generate valid inputs for a regex.
    """

    def __init__(self, regex: str, kwargs: dict):
        self.regex = regex
        self._max_attempts = 20
        self._max_repeats = 3  # Max times to generate the same string before quitting
        self._max_consecutive_failures = 3  # Max consecutive failures before quitting
        self._string_counts = defaultdict(int)
        self._input_limit = kwargs.get("max_input_size", 600)

    def _generate(self) -> str:
        """
        Generate a valid input for the regex.
        """
        attempts = 0
        consecutive_failures = 0

        while attempts < self._max_attempts:
            string = self.generate_unsafe()
            attempts += 1

            # Handle None result
            if string is None:
                consecutive_failures += 1
                if consecutive_failures >= self._max_consecutive_failures:
                    raise MaxConsecutiveFailuresExceeded(
                        f"Failed to generate any string after {consecutive_failures} consecutive attempts"
                    )
                continue

            # Reset consecutive failures since we got a string
            consecutive_failures = 0

            # If we've generated this string too many times, stop trying
            if self._string_counts[string] >= self._max_repeats:
                logger.warning(
                    f"Generated the same string '{string}' {self._max_repeats} times, moving on"
                )
                raise MaxStringGenerationAttemptsExceeded(
                    f"String '{string}' generated too many times"
                )

            # Skip if we've already added this string
            if self._string_counts[string] > 0:
                self._string_counts[string] += 1
                continue
            self._string_counts[string] += 1

            # TODO: fix me when we can support single input strings
            if len(string) <= 1:
                continue

            # Check if the string is valid for the regex
            if check_if_string_is_valid(self.regex, string):
                return string

        raise MaxAttemptsExceeded(
            f"Failed to generate a valid input for regex after {attempts} attempts"
        )

    def generate_many(self, n: int, max_input_size: int) -> List[str]:
        """
        Generate n valid inputs for the regex.

        In case the generator fails to generate a valid input, it will raise an error.
        If the generator is able to generate less than n valid inputs,
        it will silently return the number of valid inputs generated.
        """
        logger.debug("Start generating valid inputs.")
        valid_inputs = []
        attempts = 0
        consecutive_failures = 0
        max_total_attempts = n + self._max_attempts

        logger.debug(
            f"Generating {n} valid inputs for the regex: {self.regex} with {self._max_attempts} attempts using {self.__class__.__name__}."
        )

        while len(valid_inputs) < n and attempts < max_total_attempts:
            try:
                logger.debug(f"Generating valid input {len(valid_inputs) + 1} of {n}.")
                generated = self._generate()

                # Check size constraint
                if max_input_size and len(generated) > max_input_size:
                    logger.debug(
                        f"Generated string exceeds max size: {len(generated)} > {max_input_size}"
                    )
                    continue

                valid_inputs.append(generated)
                consecutive_failures = 0  # Reset on success

            except (MaxConsecutiveFailuresExceeded, MaxAttemptsExceeded) as e:
                logger.debug(f"Generation attempt failed: {str(e)}")
                consecutive_failures += 1

                # Quit if we've had too many consecutive failures
                if consecutive_failures >= self._max_consecutive_failures:
                    logger.warning(
                        f"Stopping after {consecutive_failures} consecutive failures"
                    )
                    break
            except MaxStringGenerationAttemptsExceeded as e:
                logger.debug(f"Generation attempt failed (max string): {str(e)}")
                # Quit if we've had too many consecutive failures
                logger.warning(
                    f"Stopping after generating {len(valid_inputs)} valid inputs due to same string generation attempts"
                )
                break

            attempts += 1

        if len(valid_inputs) == 0:
            raise ValueError(
                f"Failed to generate any valid input for regex: {pretty_regex(self.regex)}"
            )

        logger.debug(f"Generated {len(valid_inputs)} valid inputs: {valid_inputs}")
        return valid_inputs

    @abstractmethod
    def generate_unsafe(self) -> Optional[str]:
        """
        Generate a valid input for the regex without checking if it is valid.
        """
        pass


class GrammarBasedGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using a grammar.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)
        self.grammar = regex_to_grammar(regex)
        self._start_symbol = "<start>"
        self._max_nonterminals = 10
        self._max_expansion_trials = 100

    def generate_unsafe(self) -> Optional[str]:
        return grammar_fuzzer(
            self.grammar,
            start_symbol=self._start_symbol,
            max_nonterminals=self._max_nonterminals,
            max_expansion_trials=self._max_expansion_trials,
        )


class RstrGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using rstr.xeger.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)

    def generate_unsafe(self) -> Optional[str]:
        try:
            s = rstr.xeger(self.regex)
            if len(s) > self._input_limit:
                temp = s[: self._input_limit]
                if check_if_string_is_valid(self.regex, temp):
                    s = temp
            return s
        except Exception as e:
            logger.warning(f"Error generating valid input with rstr: {e}")
            return None


class ExrexGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using exrex.getone.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)

    def generate_unsafe(self) -> Optional[str]:
        try:
            s = exrex.getone(self.regex, limit=self._input_limit)
            return s
        except Exception as e:
            logger.warning(f"Error generating valid input with exrex: {e}")
            return None


class NFAValidGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using a DFA walker.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)

    def generate_unsafe(self) -> Optional[str]:
        inp = dfa_string_matching(self.regex)
        return inp


class MixedGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using a mixed approach.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)
        self._max_attempts = 50
        self.generators = [
            # TODO: Add grammar based generator
            # Currently, the grammar based generator is not mature enough
            # GrammarBasedGenerator(regex),
            RstrGenerator(regex, kwargs),
            ExrexGenerator(regex, kwargs),
            NFAValidGenerator(regex, kwargs),
        ]

    def generate_unsafe(self) -> Optional[str]:
        return random.choice(self.generators).generate_unsafe()


class PredefinedGenerator(ValidInputGenerator):
    """
    Generate valid inputs for a regex using a predefined list of inputs.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)
        self.predefined_inputs = iter(kwargs.get("predefined_inputs", []))

    def generate_unsafe(self) -> Optional[str]:
        try:
            return next(self.predefined_inputs)
        except StopIteration:
            return None
