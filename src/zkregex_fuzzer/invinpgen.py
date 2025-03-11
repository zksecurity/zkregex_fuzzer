"""
Invalid Input Generator.
"""

import random
import re
from typing import List

import exrex

from zkregex_fuzzer.dfa import regex_to_nfa
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
            string = self.generate_unsafe() or ""
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
    Generate invalid inputs by mutating valid inputs at random position
    with random characters.
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self._mutation_attempts = 100
        self._mutation_probability = 0.2

    def _mutate_input(self, valid_input: str) -> str:
        """
        Mutate the input.
        """
        invalid_input = list(valid_input)
        for _ in range(self._mutation_attempts):
            # randomly mutate characters at random positions
            for i in range(len(invalid_input)):
                if random.random() < self._mutation_probability:
                    invalid_input[i] = chr(random.randint(0, 255))

        invalid_input = "".join(invalid_input)

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

    1. If the regex contains a character class, negate the character class, or vice versa.
    eg. [a-z] -> [^a-z]
    2. If the regex contains a capture group, negate all literals inside the capture group.
    eg. (a|b|c) -> [^abc]
    3. If the literal values are present, negate the literal individually at random
    eg. abc -> a[^b]c
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self._mutate_probability = 0.2

    def _negate_character_class(self, regex: str) -> str:
        """
        Negate the character class.
        """

        def toggle_negation(match: re.Match) -> str:
            char_class = match.group(1)
            if random.random() < self._mutate_probability:
                if char_class.startswith("^"):  # Already negated, remove '^'
                    return f"[{char_class[1:]}]"
                else:  # Not negated, add '^'
                    return f"[^{char_class}]"

            return f"[{char_class}]"

        # Match character classes like [abc], [^xyz], [0-9], etc.
        return re.sub(r"\[([^\]]+)\]", toggle_negation, regex)

    def _negate_or_capture(self, regex: str) -> str:
        """
        Negate all literals inside or capture group.
        """

        def toggle_negation(match: re.Match) -> str:
            if random.random() < self._mutate_probability:
                literals = match.group(1).split("|")
                replaced = "[^"
                for literal in literals:
                    replaced += literal

                return replaced + "]"

            return match.group(0)

        # match literals like (a|b|c)
        return re.sub(r"\(([^\)]+)\)", toggle_negation, regex)

    def _extract_parts(self, s: str) -> list[str]:
        """
        Extract regex parts outside () and [].
        """
        result = []
        current_part = []
        in_brackets = False
        in_parentheses = False
        prev_char = ""

        for char in s:
            # Detect start of brackets
            if char == "[" and prev_char != "\\":
                if current_part:
                    result.append("".join(current_part))
                    current_part = []
                in_brackets = True

            elif char == "]" and prev_char != "\\":
                current_part.append(char)
                result.append("".join(current_part))
                current_part = []
                in_brackets = False
                continue

            # Detect start of parentheses
            elif char == "(" and prev_char != "\\":
                if current_part:
                    result.append("".join(current_part))
                    current_part = []
                in_parentheses = True

            elif char == ")" and prev_char != "\\":
                current_part.append(char)
                result.append("".join(current_part))
                current_part = []
                in_parentheses = False
                continue

            # Capture characters inside brackets/parentheses
            if in_brackets or in_parentheses:
                current_part.append(char)
            # Capture outside text
            elif char.isprintable():
                current_part.append(char)
            elif current_part:
                result.append("".join(current_part))
                current_part = []

            prev_char = char

        # Add last captured part if any
        if current_part:
            result.append("".join(current_part))

        return result

    def _mutate_literal(self, regex: str) -> str:
        """
        Mutate the literal outside () and [] at random.
        eg. abc -> a[^b]c
        """
        parts = self._extract_parts(regex)
        final_regex = ""
        for part in parts:
            if part.startswith("[") or part.startswith("("):
                final_regex += part
                continue

            literals = list(part)
            for i in range(len(literals)):
                current_char = literals[i]
                should_mutate = random.random() < self._mutate_probability
                # handle escape char
                if current_char == "\\":
                    current_char = "\\" + literals[i + 1]
                    literals[i] = (
                        "[^" + current_char + "]" if should_mutate else current_char
                    )
                    literals[i + 1] = ""
                    i += 1

                elif current_char.isalnum():
                    literals[i] = (
                        "[^" + current_char + "]" if should_mutate else current_char
                    )

            part = "".join(literals)
            final_regex += part

        return final_regex

    def _mutate_regex(self) -> str:
        """
        Mutate the regex.
        """
        regex = self.regex
        regex = self._negate_character_class(regex)
        regex = self._mutate_literal(regex)
        regex = self._negate_or_capture(regex)

        return regex

    def generate_unsafe(self) -> str:
        """
        Generate an invalid input by complementing the regex.
        """
        complement_regex = self._mutate_regex()
        invalid_input = exrex.getone(complement_regex)
        return invalid_input


class NFAInvalidGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs using NFA.

    At every state transition, NFA will randomly walk into the next state with invalid input
    until arrive at the final state.
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self._mutation_probability = 0.2
        self._early_end_probability = 0.5
        self._max_cycle = 100

    def generate_unsafe(self) -> str:
        nfa = regex_to_nfa(self.regex)
        initial_state = nfa.initial_state
        final_states = nfa.final_states
        transitions = nfa.transitions
        supported_symbols = set(nfa.input_symbols)
        invalid_input = ""

        # Traverse transitions into final state
        is_already_invalid = False
        current_state = initial_state
        max_cycle = self._max_cycle
        while True:
            next_transition = transitions[current_state]
            # Break if next_transition is empty
            if not next_transition:
                break

            all_valid_inputs = set(next_transition.keys())
            all_invalid_inputs = supported_symbols - all_valid_inputs
            selected_next_input = random.choice(list(all_valid_inputs))

            # Use invalid input with some prob., else use valid input
            if all_invalid_inputs and random.random() < self._mutation_probability:
                invalid_input += random.choice(list(all_invalid_inputs))
                is_already_invalid = True
            else:
                invalid_input += random.choice(list(all_valid_inputs))

            # get next transition state
            current_state = random.choice(list(next_transition[selected_next_input]))

            # Break if current state is final state
            if current_state in final_states:
                if is_already_invalid and random.random() < self._early_end_probability:
                    break

            # prevent infinite transition
            max_cycle -= 1
            if max_cycle <= 0:
                break

        return invalid_input
