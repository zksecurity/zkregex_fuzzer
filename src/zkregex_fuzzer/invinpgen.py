"""
Invalid Input Generator.

TODO: Add option to prepend and append invalid inputs
"""

import random
import re
from collections import defaultdict
from typing import List, Optional

import exrex

from zkregex_fuzzer.chars import SUPPORTED_CHARS
from zkregex_fuzzer.dfa import regex_to_nfa
from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.utils import check_if_string_is_valid, extract_parts, pretty_regex
from zkregex_fuzzer.vinpgen import (
    MaxAttemptsExceeded,
    MaxConsecutiveFailuresExceeded,
    MaxStringGenerationAttemptsExceeded,
    ValidInputGenerator,
)


class InvalidInputGenerator(ValidInputGenerator):
    """
    Generate invalid inputs for a regex.
    """

    def __init__(self, regex: str, kwargs: dict):
        super().__init__(regex, kwargs)
        self._string_counts = defaultdict(int)

    def _generate(self) -> str:
        """
        Generate an invalid input for the regex.
        """
        attempts = 0
        consecutive_failures = 0

        while attempts < self._max_attempts:
            string = self.generate_unsafe() or ""
            attempts += 1

            # If we've generated this string too many times, stop trying
            if self._string_counts[string] >= self._max_repeats:
                logger.warning(
                    f"Generated the same string '{string}' {self._max_repeats} times, moving on"
                )
                raise MaxStringGenerationAttemptsExceeded(
                    f"String '{string}' generated too many times"
                )

            # Check if we have already generated this string
            if self._string_counts[string] > 0:
                self._string_counts[string] += 1
                continue
            self._string_counts[string] += 1

            # For invalid inputs, we want strings that DON'T match the regex
            if not check_if_string_is_valid(self.regex, string):
                return string

            consecutive_failures += 1
            if consecutive_failures >= self._max_consecutive_failures:
                raise MaxConsecutiveFailuresExceeded(
                    f"Failed to generate invalid input after {consecutive_failures} consecutive failures"
                )

        raise MaxAttemptsExceeded(
            f"Failed to generate an invalid input for regex after {attempts} attempts"
        )

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
        consecutive_failures = 0
        max_total_attempts = n + self._max_attempts

        logger.debug(
            f"Generating {n} invalid inputs for the regex: {self.regex} with {self._max_attempts} attempts using {self.__class__.__name__}."
        )

        while len(invalid_inputs) < n and attempts < max_total_attempts:
            try:
                logger.debug(
                    f"Generating invalid input {len(invalid_inputs) + 1} of {n}."
                )
                generated = self._generate()

                # Check size constraint
                if max_input_size and len(generated) > max_input_size:
                    logger.debug(
                        f"Generated string exceeds max size: {len(generated)} > {max_input_size}"
                    )
                    continue

                invalid_inputs.append(generated)
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
                    f"Stopping after generating {len(invalid_inputs)} invalid inputs due to same string generation attempts"
                )
                break

            attempts += 1

        if len(invalid_inputs) == 0:
            raise ValueError(
                f"Failed to generate any invalid input for regex: {pretty_regex(self.regex)}"
            )

        logger.debug(f"Generated {len(invalid_inputs)} invalid inputs")
        return invalid_inputs


class MutationBasedGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs by mutating valid inputs at random position
    with random characters.
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self._mutation_attempts = 50
        self._early_end_probability = 0.5
        # some regexes are pretty hard for the random mutator so
        # we set the limit to 20
        self._max_consecutive_failures = 20

    def _mutate_input(self, valid_input: str) -> str:
        """
        Mutate the input.

        # TODO: handle escape characters
        """
        invalid_input = list(valid_input)
        for _ in range(self._mutation_attempts):
            # randomly mutate characters at random positions
            for i in range(len(invalid_input)):
                # We want to mutate more often for shorter strings
                should_mutate = random.random() < (1 / len(invalid_input)) * 2
                if should_mutate:
                    # Note that we can still mutate to a valid character
                    invalid_input[i] = random.choice(
                        list(SUPPORTED_CHARS.difference({invalid_input[i]}))
                    )
                    if (
                        not check_if_string_is_valid(self.regex, "".join(invalid_input))
                        and random.random() < self._early_end_probability
                    ):
                        break

        invalid_input = "".join(invalid_input)

        return invalid_input

    def generate_unsafe(self) -> Optional[str]:
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
        self._mutate_multiple_times_probability = 0.2

    def _negate_character_class(self, regex: str) -> str:
        """
        Negate the character class.

        We find all character classes and we randomly select one or more of them
        and we toggle the negation of the character class.
        eg. [a-z] -> [^a-z] and [^a-z] -> [a-z]
        """
        # Extract all parts
        all_parts = extract_parts(regex)

        positions = []
        # We need a double iteration to first select and the mutate
        for i, part in enumerate(all_parts):
            if part.startswith("[") and part.endswith("]"):
                positions.append(i)

        if len(positions) == 0:
            return regex

        # We want to chose at least one but also we can select multiples (even all)
        num_positions = random.randint(1, len(positions))
        selected_positions = random.sample(positions, num_positions)

        result = []
        for i, part in enumerate(all_parts):
            if i in selected_positions:
                if part[1:2] == "^":
                    result.append(f"[{part[2:]}]")
                else:
                    result.append(f"[^{part[1:]}]")
            else:
                result.append(part)

        return "".join(result)

    def _negate_or_capture(self, regex: str) -> str:
        """
        Negate all literals inside or capture group.

        eg. (a|b|c) -> [^abc]
        """
        # Extract all parts
        all_parts = extract_parts(regex)

        # Process each part
        result = []
        for part in all_parts:
            if part.startswith("(") and part.endswith(")") and "|" in part:
                # This is a capture group with alternation
                # Extract the content inside the parentheses
                content = part[1:-1]

                # Check if it's a simple alternation of literals
                # We're looking for patterns like "a|b|c" without nested groups
                # We don't support escaped () here
                if "(" not in content and ")" not in content:
                    literals = content.split("|")
                    # Create a negated character class
                    negated_class = "[^"
                    for literal in literals:
                        negated_class += literal.strip()
                    negated_class += "]"
                    result.append(negated_class)
                    continue
            # If not transformed, keep the original part
            result.append(part)

        return "".join(result)

    def _mutate_literal(self, regex: str) -> str:
        """
        Mutate the literal outside () and [] at random.
        eg. abc -> a[^b]c
        """
        parts = extract_parts(regex)
        # Remove the ^ and $ if they are the first and last characters in part
        if parts[0][0] == "^":
            if len(parts[0]) == 1:
                parts = parts[1:]
            else:
                parts[0] = parts[0][1:]
        if parts[-1][-1] == "$":
            if len(parts[-1]) == 1:
                parts = parts[:-1]
            else:
                parts[-1] = parts[-1][:-1]
        final_regex = ""
        for part in parts:
            if part.startswith("[") or part.startswith("("):
                final_regex += part
                continue

            literals = list(part)
            for i in range(len(literals)):
                current_char = literals[i]
                # The should_mutate is related to the length of the literal
                # We want to mutate more often for shorter literals
                # We also remove escape characters when computing the length
                should_mutate = random.random() < (
                    1 / len([literal for literal in literals if literal != "\\"])
                )
                # handle escape characters
                if current_char == "\\":
                    current_char = "\\" + literals[i + 1]
                    literals[i] = (
                        "[^" + literals[i + 1] + "]" if should_mutate else current_char
                    )
                    literals[i + 1] = ""
                    i += 1
                elif current_char:
                    literals[i] = (
                        "[^" + current_char + "]" if should_mutate else current_char
                    )

            part = "".join(literals)
            final_regex += part

        if parts[0][0] == "^":
            final_regex = "^" + final_regex
        if parts[-1][-1] == "$":
            final_regex = final_regex + "$"

        return final_regex

    def _mutate_regex(self) -> str:
        """
        Mutate the regex.
        """
        regex = self.regex

        # In a very rare case we could mutate the regex multiple times
        # and produce a valid regex
        mutations = [
            self._negate_character_class,
            self._negate_or_capture,
            self._mutate_literal,
        ]
        max_mutations = 10
        while True:
            mutation = random.choice(mutations)
            regex = mutation(regex)
            if regex == self.regex:
                max_mutations -= 1
                mutations.remove(mutation)
                if len(mutations) == 0:
                    break
                continue
            if random.random() > self._mutate_multiple_times_probability:
                try:
                    re.compile(regex)
                    invalid_input = exrex.getone(regex)
                    if invalid_input:
                        break
                except re.error:
                    pass
            max_mutations -= 1
            if max_mutations <= 0:
                break

        return regex

    def generate_unsafe(self) -> Optional[str]:
        """
        Generate an invalid input by complementing the regex.
        """
        complement_regex = self._mutate_regex()
        try:
            re.compile(complement_regex)
            invalid_input = exrex.getone(complement_regex)
            return invalid_input
        except re.error:
            return ""


class NFAInvalidGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs using NFA.

    At every state transition, NFA will randomly walk into the next state with invalid input
    until arrive at the final state.
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self._mutation_probability = 0.2
        self._early_end_probability = 0.2
        # we need this option to support regexes like [a-z]*
        self._completly_invalid_probability = 1.2
        self._max_cycle = 100

    def generate_unsafe(self) -> Optional[str]:
        nfa = regex_to_nfa(self.regex)
        initial_state = nfa.initial_state
        final_states = nfa.final_states
        transitions = nfa.transitions
        supported_symbols = set(nfa.input_symbols)
        invalid_input = ""

        # Traverse transitions into final state
        current_state = initial_state
        max_cycle = self._max_cycle
        completely_invalid = (
            True if random.random() < self._completly_invalid_probability else False
        )
        completely_invalid_symbols = set()
        if completely_invalid:
            completely_invalid_symbols = supported_symbols - {
                valid_input
                for transition in transitions.values()
                for valid_input in transition.keys()
            }
        while True:
            next_transitions = transitions[current_state]
            # Break if next_transitions is empty and we are in early end probability
            if len(next_transitions) == 0:
                if random.random() > self._early_end_probability:
                    break
                else:
                    # Go to a random state that has at least one transition
                    current_state = random.choice(
                        [
                            state
                            for state in transitions.keys()
                            if len(transitions[state]) > 0
                        ]
                    )

            all_valid_inputs = set(next_transitions.keys())
            all_invalid_inputs = supported_symbols - all_valid_inputs

            selected_valid_input = random.choice(list(all_valid_inputs))
            selected_invalid_input = (
                random.choice(list(all_invalid_inputs))
                if len(all_invalid_inputs) > 0
                else None
            )

            selected_valid_transition = False
            # If adding valid input would keep the string valid, always add invalid input
            # There could be the case where we don't have any invalid input to add so we need to add a valid input
            # e.g., .
            if completely_invalid:
                if len(completely_invalid_symbols) == 0:
                    break
                selected_invalid_input = random.choice(list(completely_invalid_symbols))
                invalid_input += selected_invalid_input
            elif (
                not check_if_string_is_valid(
                    self.regex, invalid_input + selected_valid_input
                )
                and random.random() > self._mutation_probability
            ) or selected_invalid_input is None:
                invalid_input += selected_valid_input
                selected_valid_transition = True
            elif selected_invalid_input is not None:
                invalid_input += selected_invalid_input

            # get next transition state
            if selected_valid_transition:
                available_transitions = list(
                    transitions[current_state][selected_valid_input]
                )
                current_state = (
                    random.choice(available_transitions)
                    if len(available_transitions) > 0
                    else None
                )
            else:
                # Just pick any valid transitions
                available_transitions = [
                    state
                    for value in transitions[current_state].values()
                    for state in value
                ]
                current_state = (
                    random.choice(available_transitions)
                    if len(available_transitions) > 0
                    else None
                )

            # if current state is None we can either exit or go to a random state
            if current_state is None and random.random() > self._early_end_probability:
                current_state = random.choice(list(transitions.keys()))
            elif current_state in final_states:
                if random.random() < self._early_end_probability:
                    break
                # there is a chance that we are in a final state and we can't transition to any other state
                # but we want to continue the generation. In this case we will go to a random state
                # that has at least one transition
                if len(transitions[current_state]) == 0:
                    current_state = random.choice(
                        [
                            state
                            for state in transitions.keys()
                            if len(transitions[state]) > 0
                        ]
                    )

            # prevent infinite transition
            max_cycle -= 1
            if max_cycle <= 0:
                break

        if len(invalid_input) == 0:
            return None
        return invalid_input


class MixedGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs for a regex using a mixed approach.
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self._max_attempts = 50
        self.generators = [
            # TODO: Add grammar based generator
            # Currently, the grammar based generator is not mature enough
            # GrammarBasedGenerator(regex),
            MutationBasedGenerator(regex, kwargs),
            ComplementBasedGenerator(regex, kwargs),
            NFAInvalidGenerator(regex, kwargs),
        ]

    def generate_unsafe(self) -> Optional[str]:
        return random.choice(self.generators).generate_unsafe()


class PredefinedGenerator(InvalidInputGenerator):
    """
    Generate invalid inputs for a regex using a predefined list of inputs.
    """

    def __init__(self, regex: str, kwargs: dict = {}):
        super().__init__(regex, kwargs)
        self.predefined_inputs = iter(kwargs.get("predefined_inputs", []))

    def generate_unsafe(self) -> Optional[str]:
        try:
            return next(self.predefined_inputs)
        except StopIteration:
            return None
