import random
import re
from typing import List, Type

import pytest

from zkregex_fuzzer.invinpgen import (
    ComplementBasedGenerator,
    InvalidInputGenerator,
    MutationBasedGenerator,
    NFAInvalidGenerator,
)
from zkregex_fuzzer.utils import check_if_string_is_valid


REGEXES = [
    r"^[a-z]+[0-9]{7}$",
    r"\($",
    r"(A|4|V|p)+",
    r"[a-z]+[0-9]{7}",
    r"^[^7A-Z5].*$",
    r"(a|b|c)test[0-9]",
    r"^[a-z]*$",
    r"(q|H|0|n|;|J| )+",
]

def test_mutation_based_generator():
    for regex in REGEXES:
        generator = MutationBasedGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        assert len(invalid_inputs) > 0, f"Expected at least one invalid input for {regex}"
        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )


def test_complement_based_generator():
    for regex in REGEXES:
        generator = ComplementBasedGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        assert len(invalid_inputs) > 0, f"Expected at least one invalid input for {regex}"
        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )


def test_nfa_invalid_generator():
    for regex in REGEXES:
        generator = NFAInvalidGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        assert len(invalid_inputs) > 0, f"Expected at least one invalid input for {regex}"
        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )