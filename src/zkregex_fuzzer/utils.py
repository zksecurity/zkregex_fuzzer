"""
Utility functions for the regex fuzzer.
"""

import random
import re
import string

from fuzzingbook.Grammars import Grammar, simple_grammar_fuzzer

from zkregex_fuzzer.dfa import wrapped_has_one_accepting_state_regex


def create_range(start_char: str, end_char: str) -> set[str]:
    """
    Create a set of characters from start_char to end_char.
    """
    return {chr(i) for i in range(ord(start_char), ord(end_char) + 1)}


LATIN_EXT_CHARS = create_range("¡", "ƿ")
GREEK_CHARS = create_range("Ͱ", "Ͽ")
CYRILLIC_CHARS = create_range("Ѐ", "ӿ")
ASCII_CHARS = set(string.printable)


def is_valid_regex(regex: str) -> bool:
    """
    Check if a regex is valid.
    """
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


def has_lazy_quantifier(pattern: str) -> bool:
    """
    Returns True if `pattern` contains any lazy quantifiers (i.e., *?, +?, ??, or {m,n}?),
    False otherwise.

    This is a naive textual check and doesn't handle escaping inside character classes or
    more advanced regex syntax. For most simple usage, however, it suffices.
    """
    # Regex to search for the typical lazy quantifier patterns:
    #   *?   +?   ??   {m,n}?
    # We'll assume m,n are simple digit sets, e.g. {2,5}
    lazy_check = re.compile(r"(\*\?)|(\+\?)|(\?\?)|\{\d+(,\d+)?\}\?")

    match = lazy_check.search(pattern)
    return bool(match)


def correct_carret_position(regex: str) -> bool:
    """
    Correct positions are:
        - At the start of the regex
        - In a capturing group that is at the start of the regex
        - In a negated character class
    Returns True if the '^' is in the correct position, False otherwise.

    This is a naive textual check and doesn't handle escaping inside character classes or
    more advanced regex syntax. For most simple usage, however, it suffices.
    """
    # Find all occurrences of '^' that are not escaped
    caret_positions = [match.start() for match in re.finditer(r"(?<!\\)\^", regex)]
    if len(caret_positions) == 0:
        return True
    # Check each position
    status = False
    for pos in caret_positions:
        status = False
        if pos == 0:
            status = True
            continue
        # We have '^' at the end of the regex
        if pos + 1 == len(regex) and len(regex) > 1:
            continue
        # Let's check if the '^' is in a group that is at the start of the regex
        # and before '^' there is a '|' and before '|' there is either nothing or \r or \n until
        # the beginning of the group
        if (
            regex[pos - 1] == "|"
            and regex[pos + 1] == ")"
            and regex[0] == "("
            and bool(re.match(r"^\s*", regex[1 : pos - 1]))
        ):
            status = True
            continue
        # Let's check if the '^' is in a negated character class
        if regex[pos - 1] == "[":
            status = True
            continue
        if status is False:
            return False
    return status


def check_zkregex_rules_basic(regex: str) -> tuple[bool, bool]:
    """
    Check partial zk-regex constraints with a text-based approach:
      1) If '^' is present, it is either at index 0 or in substring '(|^)' or in (\r\n|^) or in substring '[^...]'
      2) No lazy quantifiers like '*?' or '+?' or '??' or '{m,n}?'
      3) Check that the regex has exactly one accepting state
    Returns True if all checks pass, False otherwise. Also return the status of the accepting state check.
    Returns (True, True) if all checks pass, (False, True) if the regex is invalid, (False, False) if the regex has multiple accepting states.
    """
    # 1) If '^' is present, it is either at index 0 or in substring '(|^)' or in (\r\n|^) or in substring '[^...]'
    if not correct_carret_position(regex):
        return False, True  # we return True as we haven't performed the DFA check

    # 2) Check no lazy quantifiers like *?, +?, ??, or {m,n}?
    if has_lazy_quantifier(regex):
        return False, True  # we return True as we haven't performed the DFA check

    # 3) Check that the regex has exactly one accepting state
    if not wrapped_has_one_accepting_state_regex(regex):
        return False, False

    return True, True


def check_if_string_is_valid(regex: str, string: str) -> bool:
    """
    Check if a string is valid for a regex.
    """
    try:
        return re.match(regex, string) is not None
    except re.error:
        return False


def grammar_fuzzer(
    grammar: Grammar,
    start_symbol: str,
    max_nonterminals: int = 10,
    max_expansion_trials: int = 100,
) -> str:
    """
    Fuzz using a grammar.
    """
    return simple_grammar_fuzzer(
        grammar,
        start_symbol=start_symbol,
        max_nonterminals=max_nonterminals,
        max_expansion_trials=max_expansion_trials,
    )


def get_random_filename():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def pretty_regex(regex: str):
    """
    Format raw string regex to printable chars
    """
    return regex.replace("\n", r"\n").replace("\r", r"\r")
