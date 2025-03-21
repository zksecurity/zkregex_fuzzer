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

import copy
import string
from typing import List

from fuzzingbook.Grammars import Expansion, Grammar

from zkregex_fuzzer.chars import CONTROLLED_UTF8_CHARS, UNCONTROLLED_UTF8_CHARS


def srange(characters: str) -> List[Expansion]:
    """Return a list of single-character expansions from the given string."""
    return [c for c in characters]


def srange_escaped(characters: str) -> List[Expansion]:
    """Return a list of single-character expansions from the given string, with escapes."""
    return [f"\\{c}" for c in characters]


def crange(start: str, end: str) -> List[Expansion]:
    """Return a list of single-character expansions from start..end inclusive."""
    return [chr(i) for i in range(ord(start), ord(end) + 1)]


# Grammar for basic regexes
# that are DFA-compatible
BASIC_REGEX_GRAMMAR: Grammar = {
    # Entry point
    "<start>": ["<REGEX>"],
    # Main regex structure
    "<REGEX>": ["<ANCHORED_EXPR>", "<EXPR>"],
    # Expressions with various anchor forms
    "<ANCHORED_EXPR>": [
        # Standard anchors
        "^<EXPR>",
        "<EXPR>$",
        "^<EXPR>$",
        # Alternative caret forms
        "(|^)<EXPR>",  # Empty or start of line
        "(\\r\\n|^)<EXPR>",  # Windows newline or start of line
        "(\\n|^)<EXPR>",  # Unix newline or start of line
        "(\\r|^)<EXPR>",  # Carriage return or start of line
        "(\\n\\r|^)<EXPR>",  # Reverse Windows newline or start of line
        # Combinations with end anchors
        "(|^)<EXPR>$",
        "(\\r\\n|^)<EXPR>$",
        "(\\n|^)<EXPR>$",
        "(\\r|^)<EXPR>$",
        "(\\n\\r|^)<EXPR>$",
    ],
    # Expression is a series of alternations
    "<EXPR>": ["<ALT>"],
    # Alternation
    "<ALT>": ["<CONCAT>", "<CONCAT>|<ALT>"],
    # Concatenation
    "<CONCAT>": ["<QUANT>", "<QUANT><CONCAT>"],
    # Element with optional quantifier
    "<QUANT>": ["<ATOM>", "<ATOM><QUANTIFIER>"],
    # Quantifiers (all DFA-compatible)
    "<QUANTIFIER>": [
        "*",  # zero or more
        "+",  # one or more
        "?",  # zero or one
        "{<EXACT_COUNT>}",  # exactly n
        "{<MIN_COUNT>,}",  # n or more
        "{<MIN_COUNT>,<MAX_COUNT>}",  # between n and m
    ],
    # Count specifications
    "<EXACT_COUNT>": ["<SMALL_INT>"],
    "<MIN_COUNT>": ["<SMALL_INT>"],
    "<MAX_COUNT>": ["<SMALL_INT>"],
    # limit the number of digits to 2 and first digit to 1
    "<SMALL_INT>": ["1", "<DIGIT>"],
    "<DIGIT>": srange(string.digits),
    # Basic regex atoms
    "<ATOM>": [
        "<CHAR>",  # Single character
        ".",  # Any character
        "<CHARCLASS>",  # Character class
        "(<EXPR>)",  # Grouped expression
        "<SHORTHAND>",  # Character class shorthand
    ],
    # Shorthand character classes
    "<SHORTHAND>": [
        "\\s",  # Any whitespace character
        "\\S",  # Any non-whitespace character
        "\\d",  # Any digit
        "\\D",  # Any non-digit
        "\\w",  # Any word character
        "\\W",  # Any non-word character
    ],
    # Character class
    "<CHARCLASS>": [
        "[<CHARCLASS_ITEMS>]",  # Standard class
        "[^<CHARCLASS_ITEMS>]",  # Negated class
    ],
    # Items in character class
    "<CHARCLASS_ITEMS>": ["<CHARCLASS_ITEM>", "<CHARCLASS_ITEM><CHARCLASS_ITEMS>"],
    # Single item in character class
    "<CHARCLASS_ITEM>": [
        "<CHAR>",  # Individual character
        "<LOWER_LETTER>-<LOWER_LETTER>",  # Make specific character classes more likely
        "<UPPER_LETTER>-<UPPER_LETTER>",
        "<DIGIT>-<DIGIT>",
        "<CHAR>-<CHAR>",  # Character range
        "<SHORTHAND>",  # Shorthand in character class
    ],
    # Characters (simplified for clarity)
    "<CHAR>": ["<LETTER>", "<DIGIT>", "<SYMBOL>", "<ESCAPED>"],
    # Letters
    "<LETTER>": crange("a", "z") + crange("A", "Z"),
    "<LOWER_LETTER>": crange("a", "z"),
    "<UPPER_LETTER>": crange("A", "Z"),
    # Symbols that are safe to use directly
    "<SYMBOL>": srange(" !\"#%',/:;<=>@_~"),
    # Escaped special characters
    "<ESCAPED>": [f"\\{c}" for c in "\\^$.|?*+()[]{}`-&"],
}

CONTROLLED_UTF8_GRAMMAR: Grammar = copy.deepcopy(BASIC_REGEX_GRAMMAR)
CONTROLLED_UTF8_GRAMMAR["<CHAR>"] = [
    "<LETTER>",
    "<DIGIT>",
    "<SYMBOL>",
    "<ESCAPED>",
    "<UTF8_CHAR>",
]
CONTROLLED_UTF8_GRAMMAR["<UTF8_CHAR>"] = list(CONTROLLED_UTF8_CHARS.non_escaped_chars)

UNCONTROLLED_UTF8_GRAMMAR: Grammar = copy.deepcopy(BASIC_REGEX_GRAMMAR)
UNCONTROLLED_UTF8_GRAMMAR["<CHAR>"] = [
    "<LETTER>",
    "<DIGIT>",
    "<SYMBOL>",
    "<ESCAPED>",
    "<UTF8_CHAR>",
]
UNCONTROLLED_UTF8_GRAMMAR["<UTF8_CHAR>"] = list(
    UNCONTROLLED_UTF8_CHARS.non_escaped_chars
)

OLD_GRAMMAR: Grammar = {
    # Entry point
    "<start>": ["<REGEX>"],
    # A regex is optional beginning anchor + expression + mandatory end anchor
    "<REGEX>": ["<BEGIN_ANCHOR><EXPRESSION><END_ANCHOR>", "<EXPRESSION><END_ANCHOR>"],
    "<BEGIN_ANCHOR>": ["^", "(|^)"],
    "<END_ANCHOR>": ["$"],
    # Expression: possibly multiple union parts
    "<EXPRESSION>": [
        "<CONCAT>",
        # "<CONCAT>|<EXPRESSION>"
    ],
    "<CONCAT>": ["<PIECE>", "<PIECE><CONCAT>"],
    "<PIECE>": ["<BASIC>", "<BASIC><QUANTIFIER>"],
    # Quantifiers - no lazy forms
    "<QUANTIFIER>": [
        "*",
        "+",
        # "?",
        "{<RANGE_SPEC>}",
    ],
    "<RANGE_SPEC>": ["<INTEGER>", "<INTEGER>,<INTEGER>"],
    # Up to 2-digit integer
    "<INTEGER>": [
        "<DIGIT>",
        # "<DIGIT><DIGIT>",
    ],
    # Single digit
    "<DIGIT>": srange(string.digits),  # "0".."9"
    "<BASIC>": [
        # "<GROUP>",
        "<DOT>",
        "<CHARCLASS>",
        "<LITERAL_CHAR>",
    ],
    # TODO: Add support for groups. Can we handle them with JSONs?
    # "<GROUP>": [
    #     "(<EXPRESSION>)"
    # ],
    "<DOT>": ["."],
    "<CHARCLASS>": [
        "[<CHARCLASS_BODY>]",
        # Is the complement supported?
        "[^<CHARCLASS_BODY>]",
    ],
    # Body can have multiple items (range or char)
    "<CHARCLASS_BODY>": [
        "<RANGE><CHARCLASS_BODY>",
        "<CHAR><CHARCLASS_BODY>",
        "<RANGE>",
        "<CHAR>",
    ],
    # Ranges are restricted to these three
    # TODO: Add support for more ranges
    "<RANGE>": ["a-z", "A-Z", "0-9"],
    # A single char is either letter, digit, or punctuation
    "<CHAR>": ["<LETTER>", "<DIGIT>", "<PUNCT>"],
    # We'll define letters as expansions from 'a'..'z' and 'A'..'Z'
    # TODO: Add support for any unicode?
    "<LETTER>": (crange("a", "z") + crange("A", "Z")),
    # Some safe ASCII punctuation that won't conflict with special metas
    # TODO: Add more safe punctuation
    "<PUNCT>": srange_escaped("()"),
    # LITERAL_CHAR is basically the same set as <CHAR>
    "<LITERAL_CHAR>": ["<CHAR>"],
}
