"""
Utility functions for the regex fuzzer.
"""

import random
import re
import string

from fuzzingbook.Grammars import Grammar, simple_grammar_fuzzer


def is_valid_regex(regex: str) -> bool:
    """
    Check if a regex is valid.
    """
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


def check_zkregex_rules_basic(regex: str) -> bool:
    """
    Check partial zk-regex constraints with a text-based approach:
      1) Must end with '$'
      2) If '^' is present, it is either at index 0 or in substring '(|^)'
      3) No lazy quantifiers like '*?' or '+?' or '??' or '{m,n}?'
    Returns True if all checks pass, False otherwise.

    TODO: DFA Checks -- code that actually compiles the regex to an automaton and verifies:
        - No loop from initial state back to itself (i.e. no .*-like or equivalent)
        - Only one accepting state
    """

    # 1) Must end with '$' (if it present)
    if "$" in regex and not regex.endswith("$"):
        return False

    # 2) '^' must be at start or in '(|^)'
    # We'll allow no '^' at all. If it appears, check positions.
    # We'll define a function to find all occurrences of '^'.
    allowed_positions = set()
    # If the string starts with '^', that’s allowed
    if len(regex) > 0 and regex[0] == "^":
        allowed_positions.add(0)

    # If the string contains '(|^)', that means '^' is at position (idx+2)
    idx = 0
    while True:
        idx = regex.find("(|^)", idx)
        if idx == -1:
            break
        # '^' occurs at (idx + 2)
        allowed_positions.add(idx + 2)
        idx += 4  # skip past

    # If the string contains '[^]', that means '^' is at position (idx+1)
    idx = 0
    while True:
        idx = regex.find("[^", idx)
        if idx == -1:
            break
        # '^' occurs at (idx + 1)
        allowed_positions.add(idx + 1)
        idx += 2  # skip past

    # Now see if there's any '^' outside those allowed positions
    for match in re.finditer(r"\^", regex):
        pos = match.start()
        if pos not in allowed_positions:
            return False

    # 3) Check no lazy quantifiers like *?, +?, ??, or {m,n}?
    # We do a simple regex search for them:
    # Patterns we search for: (*?), (+?), (??), ({\d+(,\d+)?}\?)
    lazy_pattern = re.compile(r"(\*\?|\+\?|\?\?|\{\d+(,\d+)?\}\?)")
    if lazy_pattern.search(regex):
        return False

    return True


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
