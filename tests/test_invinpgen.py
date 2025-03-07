import random

from zkregex_fuzzer.invinpgen import MutationBasedGenerator
from zkregex_fuzzer.utils import check_if_string_is_valid


def test_mutation_based_generator():
    random.seed("test")
    regex = r"^[a-z]+[0-9]{7}$"
    generator = MutationBasedGenerator(regex)
    invalid_inputs = generator.generate_many(10, 20)

    for input in invalid_inputs:
        assert not check_if_string_is_valid(
            regex, input
        ), f"Expected {input} to be invalid"
