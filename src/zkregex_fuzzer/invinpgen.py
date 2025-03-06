"""
Invalid Input Generator.
"""

import random
import exrex
from typing import List

from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.utils import check_if_string_is_valid, pretty_regex
from zkregex_fuzzer.vinpgen import ValidInputGenerator


class InvalidInputGenerator(ValidInputGenerator):

    def _generate(self) -> str:
        """
        Generate an invalid input for the regex.
        """
        attempts = 0
        while attempts < self._max_attempts:
            string = self.generate_unsafe()
            if string in self._generated_strings:
                attempts += 1
                continue
            self._generated_strings.add(string)
            if not check_if_string_is_valid(self.regex, string):
                return string
            attempts += 1
        raise ValueError("Failed to generate an invalid input for the regex.")

    def generate_many(self, n: int, max_input_size: int) -> List[str]:
        """
        Generate n invalid inputs for the regex.

        In case the generator fails to generate an invalid input, it will raise an error.
        If the generator is able to generate less than n invalid inputs,
        it will silently return the number of invalid inputs generated.
        """
        logger.debug("Start generating invalid inputs.")
        invalid_inputs = []
        attempts = 0
        logger.debug(
            f"Generating {n} invalid inputs for the regex: {self.regex} with {self._max_attempts} attempts using {self.__class__.__name__}."
        )
        while len(invalid_inputs) < n and attempts < self._max_attempts:
            try:
                logger.debug(
                    f"Generating invalid input {len(invalid_inputs) + 1} of {n}."
                )
                generated = self._generate()
                if max_input_size:
                    if len(generated) <= max_input_size:
                        invalid_inputs.append(generated)
                else:
                    invalid_inputs.append(generated)
            except ValueError:
                pass
            attempts += 1
        if len(invalid_inputs) == 0:
            raise ValueError(
                f"Failed to generate any invalid input for the regex: {pretty_regex(self.regex)}"
            )
        logger.debug("Finished generating invalid inputs.")
        return invalid_inputs


class MutationBasedGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs by mutating regex.
    """

    def __init__(self, regex: str):
        super().__init__(regex)

    def _mutate_input(self, valid_input: str) -> str:
        """
        Mutate the input.
        """
        invalid_input = valid_input
        for _ in range(10):
            # randomly mutate characters
            invalid_input = list(valid_input)
            for i in range(len(invalid_input)):
                if random.random() < 0.1:
                    invalid_input[i] = chr(random.randint(0, 255))
            invalid_input = "".join(invalid_input)
            if invalid_input != valid_input:
                break

        # randomly add characters at beginning
        invalid_input = (
            chr(random.randint(0, 255)) * random.randint(0, 10) + invalid_input
        )

        # randomly add characters at end
        invalid_input = invalid_input + chr(random.randint(0, 255)) * random.randint(
            0, 10
        )

        return invalid_input

    def generate_unsafe(self) -> str:
        """
        Generate an invalid input by mutating the regex.
        """
        valid_input = exrex.getone(self.regex)
        invalid_input = self._mutate_input(valid_input)
        return invalid_input


class ComplementBasedGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs by complementing the regex.
    """

    def __init__(self, regex: str):
        super().__init__(regex)

    def generate_unsafe(self) -> str:
        """
        Generate an invalid input by complementing the regex.
        """
        raise NotImplementedError
