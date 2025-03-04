from zkregex_fuzzer.dfa import has_multiple_accepting_states_regex


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

    for regex in regex_with_multiple_accepting_states:
        assert has_multiple_accepting_states_regex(regex)
