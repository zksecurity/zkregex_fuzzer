import random
import pytest
import re
from zkregex_fuzzer.invinpgen import (
    ComplementBasedGenerator,
    MutationBasedGenerator,
    NFAInvalidGenerator,
    InvalidInputGenerator,
)
from zkregex_fuzzer.utils import check_if_string_is_valid
from typing import Type, List


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


# Test fixtures for various regex patterns
@pytest.fixture
def simple_regex() -> str:
    return "a[bc]d"

@pytest.fixture
def complex_regex() -> str:
    return "^(foo|bar)[0-9]{1,3}$"

@pytest.fixture
def character_class_regex() -> str:
    return "[a-z]{3}"

@pytest.fixture
def capture_group_regex() -> str:
    return "(abc|def|ghi)+"

@pytest.fixture
def email_regex() -> str:
    return r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

@pytest.fixture
def generator_classes() -> List[Type[InvalidInputGenerator]]:
    return [MutationBasedGenerator, ComplementBasedGenerator, NFAInvalidGenerator]

# Test MutationBasedGenerator
def test_mutation_based_generator_unsafe(simple_regex):
    generator = MutationBasedGenerator(simple_regex)
    result = generator.generate_unsafe()
    assert isinstance(result, str)
    # We don't assert that it's invalid because generate_unsafe doesn't guarantee that

# Test ComplementBasedGenerator
def test_complement_based_generator_unsafe(character_class_regex):
    generator = ComplementBasedGenerator(character_class_regex)
    result = generator.generate_unsafe()
    assert isinstance(result, str)
    # We don't assert that it's invalid because generate_unsafe doesn't guarantee that

# Test NFAInvalidGenerator
def test_nfa_invalid_generator_unsafe(simple_regex):
    generator = NFAInvalidGenerator(simple_regex)
    result = generator.generate_unsafe()
    assert isinstance(result, str)
    # We don't assert that it's invalid because generate_unsafe doesn't guarantee that

# Test with various regex patterns
def test_generators_with_various_patterns(generator_classes):
    patterns = [
        "a+b*c?",
        "[0-9]{3}-[0-9]{3}-[0-9]{4}",
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
        "(https?|ftp)://[^\\s/$.?#].[^\\s]*$"
    ]
    
    for pattern in patterns:
        for GeneratorClass in generator_classes:
            generator = GeneratorClass(pattern)
            result = generator.generate_unsafe()
            assert isinstance(result, str)

# Test with empty and unusual regexes
def test_generators_with_edge_case_patterns(generator_classes):
    edge_cases = [
        ".",  # Match any character
        ".*",  # Match anything
        "^$"   # Match empty string
    ]
    
    for pattern in edge_cases:
        for GeneratorClass in generator_classes:
            generator = GeneratorClass(pattern)
            # Just test that it doesn't crash
            try:
                result = generator.generate_unsafe()
                assert isinstance(result, str)
            except Exception as e:
                pytest.fail(f"{GeneratorClass.__name__} failed with pattern '{pattern}': {e}")

# Test multiple calls to generate_unsafe
def test_multiple_calls_generate_different_outputs(generator_classes):
    pattern = "abc[0-9]+"
    
    for GeneratorClass in generator_classes:
        generator = GeneratorClass(pattern)
        results = [generator.generate_unsafe() for _ in range(10)]
        # Filter out empty strings which might be returned by some generators
        non_empty_results = [r for r in results if r]
        if non_empty_results:
            # At least some of the results should be different if we have enough non-empty results
            if len(non_empty_results) > 3:
                assert len(set(non_empty_results)) > 1, f"{GeneratorClass.__name__} generated identical outputs"

# Test specific functionality of MutationBasedGenerator
def test_mutation_based_generator_mutate_input():
    generator = MutationBasedGenerator("abc[0-9]+")
    valid_input = "abc123"
    mutated = generator._mutate_input(valid_input)
    assert isinstance(mutated, str)
    assert mutated != valid_input or len(mutated) != len(valid_input)

# Test specific functionality of ComplementBasedGenerator
def test_complement_based_generator_mutations():
    generator = ComplementBasedGenerator("a[bc]d")
    
    # Test character class negation
    negated = generator._negate_character_class("a[bc]d")
    assert isinstance(negated, str)
    
    # Test capture group negation
    negated = generator._negate_or_capture("a(b|c)d")
    assert isinstance(negated, str)
    
    # Test literal mutation
    mutated = generator._mutate_literal("abcd")
    assert isinstance(mutated, str)
    
    # Test full regex mutation
    mutated_regex = generator._mutate_regex()
    assert isinstance(mutated_regex, str)

# Test specific functionality of NFAInvalidGenerator with state transitions
def test_nfa_invalid_generator_transition(simple_regex):
    generator = NFAInvalidGenerator(simple_regex)
    result = generator.generate_unsafe()
    assert isinstance(result, str)
    
    # Set specific probabilities to increase chances of invalid generation
    generator._mutation_probability = 0.8
    generator._early_end_probability = 0.2
    result = generator.generate_unsafe()
    assert isinstance(result, str)
