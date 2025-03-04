import re

from automata.regex.regex import isequal
from zkregex_fuzzer.dfa import (
    has_multiple_accepting_states_regex,
    regex_to_dfa,
    transform_dfa_to_regex,
    transform_dfa_to_single_accepting_state,
)

regex_with_multiple_accepting_states = [
    r"(ab|aba)",
    r"(ab|aba)*",
    r"(hello|hell)",
    r"b(aa|aaa)",
    r"(cat|cats)",
    r"(xy|xyx)",
    r"(a|ab|abc)",
    r"(1|12)",
]


def test_has_multiple_accepting_states_regex_without_multiple():
    regex_without_multiple_accepting_states = [
        r"(a|b)*",
        r"abc",
        r"(abc|def|ghi)",
        r"(abc)*",
        r"(hello)",
        r"(ab)*",
        r"(a|b|c)*",
        r"((a|b|c)*abc)",
        r"[a-zA-Z]+",
        r"[0-9]+",
        r"(abc|abcd|abcde)f",
        r"(hello|helloo|hellooo)(foo|foob|fooba)?bar",
        r"(foo|foob|fooba)?bar",
        r"(abc|def)(gh|jk)(lm|nop)",
    ]

    for regex in regex_without_multiple_accepting_states:
        assert not has_multiple_accepting_states_regex(regex)


def test_has_multiple_accepting_states_regex_with_multiple():
    for regex in regex_with_multiple_accepting_states:
        assert has_multiple_accepting_states_regex(regex)


def test_transform_dfa_to_regex():
    regexes = [
        r"(ab|aba)",
        r"(ab|aba)*",
        r"(hello|hell)",
    ]
    for regex in regexes:
        dfa = regex_to_dfa(regex)
        transformed_regex = transform_dfa_to_regex(dfa)
        assert isequal(regex, transformed_regex)


def test_transform_dfa_to_regex_with_multiple_accepting_states():
    strategies = ["pick_one", "new_dummy", "merge"]
    for strategy in strategies:
        for regex in regex_with_multiple_accepting_states:
            dfa = regex_to_dfa(regex)
            transformed_dfa = transform_dfa_to_single_accepting_state(
                dfa, strategy=strategy
            )
            assert len(transformed_dfa.final_states) == 1
            transformed_regex = transform_dfa_to_regex(transformed_dfa)
            new_dfa = regex_to_dfa(transformed_regex)
            assert len(new_dfa.final_states) == 1
