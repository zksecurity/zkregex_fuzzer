"""
Defines a custom grammar.

Note the name to the grammar should be grammar.
"""

import string
from typing import List

from fuzzingbook.Grammars import Expansion, Grammar


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
grammar: Grammar = {
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
        "<CHAR>-<CHAR>",  # Character range
        "<SHORTHAND>",  # Shorthand in character class
    ],
    # Characters (simplified for clarity)
    "<CHAR>": ["<LETTER>", "<DIGIT>", "<SYMBOL>", "<ESCAPED>"],
    # Letters
    "<LETTER>": crange("a", "z") + crange("A", "Z"),
    # Symbols that are safe to use directly
    "<SYMBOL>": srange(" !\"#$%&',-/:;<=>@_`~"),
    # Escaped special characters
    "<ESCAPED>": [f"\\{c}" for c in "\\^$.|?*+()[]{"],
}
