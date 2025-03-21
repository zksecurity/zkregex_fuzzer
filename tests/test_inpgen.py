import random
import re
from typing import List, Type

import pytest

from zkregex_fuzzer.chars import SupportedCharsManager
from zkregex_fuzzer.invinpgen import (
    ComplementBasedGenerator,
    InvalidInputGenerator,
    MutationBasedGenerator,
    NFAInvalidGenerator,
)
from zkregex_fuzzer.utils import check_if_string_is_valid
from zkregex_fuzzer.vinpgen import ExrexGenerator, NFAValidGenerator, RstrGenerator

# (regex, limit_valid, limit_invalid)
REGEXES = [
    (r"1", 1, 10, "ascii"),
    (r"^[a-z]+[0-9]{7}$", 10, 10, "ascii"),
    (r"\($", 1, 10, "ascii"),
    (r"(A|4|V|p)+", 10, 10, "ascii"),
    (r"[a-z]+[0-9]{7}", 10, 10, "ascii"),
    (r"^[^7A-Z5].*$", 10, 10, "ascii"),
    (r"(a|b|c)test[0-9]", 10, 10, "ascii"),
    (r"^[a-z]*$", 10, 10, "ascii"),
    (r"(q|H|0|n|;|J| )+", 10, 10, "ascii"),
    (r"[a-z]*", 10, 0, "ascii"),
    (r"L[¡-ƿ]+$", 10, 10, "controlled_utf8"),
]


def test_mutation_based_invalid_generator():
    for regex, _, limit_invalid, char_set in REGEXES:
        SupportedCharsManager.override(char_set)
        # The following regexes are pretty hard for the random mutator so
        # we limit the number of invalid inputs
        if regex == "^[^7A-Z5].*$":
            limit_invalid = 3
        if regex == "[a-z]*":
            continue
        generator = MutationBasedGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        assert len(invalid_inputs) >= limit_invalid, (
            f"Expected at least {limit_invalid} invalid input for {regex}"
        )
        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )


def test_complement_based_invalid_generator():
    for regex, _, limit_invalid, char_set in REGEXES:
        SupportedCharsManager.override(char_set)
        if regex == "[a-z]*":
            continue
        generator = ComplementBasedGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        assert len(invalid_inputs) >= limit_invalid, (
            f"Expected at least {limit_invalid} invalid input for {regex}"
        )
        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )


def test_nfa_invalid_generator():
    for regex, _, limit_invalid, char_set in REGEXES:
        SupportedCharsManager.override(char_set)
        if regex == "[a-z]*" or regex == "^[^7A-Z5].*$":
            continue
        generator = NFAInvalidGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        assert len(invalid_inputs) >= limit_invalid, (
            f"Expected at least {limit_invalid} invalid input for {regex}"
        )
        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )


def test_nfa_valid_generator():
    for regex, limit_valid, _, char_set in REGEXES:
        SupportedCharsManager.override(char_set)
        # The following regexes are pretty hard for the NFA valid generator so
        # we limit the number of valid inputs
        if regex == "^[a-z]*$":  # The problem is that will tend towards generating ""
            limit_valid = 3
        if regex == "[a-z]*":
            limit_valid = 3
        generator = NFAValidGenerator(regex, {})
        valid_inputs = generator.generate_many(10, 20)

        assert len(valid_inputs) >= limit_valid, (
            f"Expected at least {limit_valid} valid input for {regex}"
        )
        for input in valid_inputs:
            assert check_if_string_is_valid(regex, input), (
                f"Expected {input} to be valid"
            )


def test_rstr_valid_generator():
    for regex, limit_valid, _, char_set in REGEXES:
        SupportedCharsManager.override(char_set)
        generator = RstrGenerator(regex, {})
        valid_inputs = generator.generate_many(10, 20)

        assert len(valid_inputs) >= limit_valid, (
            f"Expected at least {limit_valid} valid input for {regex}"
        )
        for input in valid_inputs:
            assert check_if_string_is_valid(regex, input), (
                f"Expected {input} to be valid"
            )


def test_exrex_valid_generator():
    for regex, limit_valid, _, char_set in REGEXES:
        SupportedCharsManager.override(char_set)
        generator = ExrexGenerator(regex, {})
        valid_inputs = generator.generate_many(10, 20)

        assert len(valid_inputs) >= limit_valid, (
            f"Expected at least {limit_valid} valid input for {regex}"
        )
        for input in valid_inputs:
            assert check_if_string_is_valid(regex, input), (
                f"Expected {input} to be valid"
            )
