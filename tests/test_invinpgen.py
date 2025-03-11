import random

from zkregex_fuzzer.invinpgen import (
    ComplementBasedGenerator,
    MutationBasedGenerator,
    NFAInvalidGenerator,
)
from zkregex_fuzzer.utils import check_if_string_is_valid


def test_mutation_based_generator():
    random.seed("test")
    regex = r"^[a-z]+[0-9]{7}$"
    generator = MutationBasedGenerator(regex)
    invalid_inputs = generator.generate_many(10, 20)

    for input in invalid_inputs:
        assert not check_if_string_is_valid(regex, input), (
            f"Expected {input} to be invalid"
        )


def test_complement_based_generator():
    regexes = [
        r"\($",
        r"(A|4|V|p)+",
        r"[a-z]+[0-9]{7}",
        r"^[^7A-Z5].*$",
        r"(a|b|c)test[0-9]",
    ]

    for regex in regexes:
        generator = ComplementBasedGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )


def test_nfa_invalid_generator():
    regexes = [r"(A|4|V|p)+", r"[a-z]+[0-9]{7}", r"[^7A-Z5].*$", r"(q|H|0|n|;|J| )+"]

    for regex in regexes:
        generator = NFAInvalidGenerator(regex)
        invalid_inputs = generator.generate_many(10, 20)

        for input in invalid_inputs:
            assert not check_if_string_is_valid(regex, input), (
                f"Expected {input} to be invalid"
            )
