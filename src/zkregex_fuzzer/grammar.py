"""
Defines the grammar used for generating regexes in a style that
The Fuzzing Book understands.

We follow the restrictions described in the zk-regex repo.

The regular expressions supported by our compiler version 2.1.1 are audited by zksecurity, and have the following limitations:

    Regular expressions where the results differ between greedy and lazy matching (e.g., .+, .+?) are not supported.
    The beginning anchor ^ must either appear at the beginning of the regular expression or be in the format (|^). Additionally, the section containing this ^ must be non-public (is_public: false).
    The end anchor $ must appear at the end of the regular expression.
    Regular expressions that, when converted to DFA (Deterministic Finite Automaton), include transitions to the initial state are not supported (e.g., .*).
    Regular expressions that, when converted to DFA, have multiple accepting states are not supported.
    Decomposed regex defintions must alternate public and private states.

Note that all international characters are supported.


TODO:
 - Add more grammars.
"""
from typing import List
from fuzzingbook.Grammars import Grammar, Expansion

import string

def srange(characters: str) -> List[Expansion]:
    """Return a list of single-character expansions from the given string."""
    return [c for c in characters]

def srange_escaped(characters: str) -> List[Expansion]:
    """Return a list of single-character expansions from the given string, with escapes."""
    return [f"\\{c}" for c in characters]

def crange(start: str, end: str) -> List[Expansion]:
    """Return a list of single-character expansions from start..end inclusive."""
    return [chr(i) for i in range(ord(start), ord(end) + 1)]

REGEX_GRAMMAR: Grammar = {
    # Entry point
    "<start>": [
        "<REGEX>"
    ],

    # A regex is optional beginning anchor + expression + mandatory end anchor
    "<REGEX>": [
        "<BEGIN_ANCHOR><EXPRESSION><END_ANCHOR>",
        "<EXPRESSION><END_ANCHOR>"
    ],

    "<BEGIN_ANCHOR>": [
        "^",
        "(|^)"
    ],

    "<END_ANCHOR>": [
        "$"
    ],

    # Expression: possibly multiple union parts
    "<EXPRESSION>": [
        "<CONCAT>",
        "<CONCAT>|<EXPRESSION>"
    ],

    "<CONCAT>": [
        "<PIECE>",
        "<PIECE><CONCAT>"
    ],

    "<PIECE>": [
        "<BASIC>",
        "<BASIC><QUANTIFIER>"
    ],

    # Quantifiers - no lazy forms
    "<QUANTIFIER>": [
        "*",
        "+",
        "?",
        "{<RANGE_SPEC>}"
    ],

    "<RANGE_SPEC>": [
        "<INTEGER>",
        "<INTEGER>,<INTEGER>"
    ],

    # Up to 2-digit integer
    "<INTEGER>": [
        "<DIGIT>",
        "<DIGIT><DIGIT>",
    ],

    # Single digit
    "<DIGIT>": srange(string.digits),  # "0".."9"

    "<BASIC>": [
        #"<GROUP>",
        "<DOT>",
        "<CHARCLASS>",
        "<LITERAL_CHAR>"
    ],

    # TODO: Add support for groups. Can we handle them with JSONs?
    # "<GROUP>": [
    #     "(<EXPRESSION>)"
    # ],

    "<DOT>": [
        "."
    ],

    "<CHARCLASS>": [
        "[<CHARCLASS_BODY>]",
        # Is the complement supported?
        #"[^<CHARCLASS_BODY>]"
    ],

    # Body can have multiple items (range or char)
    "<CHARCLASS_BODY>": [
        "<RANGE><CHARCLASS_BODY>",
        "<CHAR><CHARCLASS_BODY>",
        "<RANGE>",
        "<CHAR>"
    ],

    # Ranges are restricted to these three
    # TODO: Add support for more ranges
    "<RANGE>": [
        "a-z",
        "A-Z",
        "0-9"
    ],

    # A single char is either letter, digit, or punctuation 
    "<CHAR>": [
        "<LETTER>",
        "<DIGIT>",
        "<PUNCT>"
    ],

    # We'll define letters as expansions from 'a'..'z' and 'A'..'Z'
    # TODO: Add support for any unicode?
    "<LETTER>": (
        crange("a", "z") + crange("A", "Z")
    ),

    # Some safe ASCII punctuation that won't conflict with special metas
    # TODO: Add more safe punctuation
    "<PUNCT>": srange_escaped("()"),

    # LITERAL_CHAR is basically the same set as <CHAR>
    "<LITERAL_CHAR>": [
        "<CHAR>"
    ]
}