"""
Defines the grammar used for generating regexes in a style that
The Fuzzing Book understands.
"""
from fuzzingbook.Grammars import Grammar

REGEX_GRAMMAR: Grammar = {
    "<start>": ["<regex>"],

    "<regex>": [
        "<regex>|<concat>",
        "<concat>"
    ],
    "<concat>": [
        "<concat><basic>",
        "<basic>"
    ],
    "<basic>": [
        "<elementary>*",
        "<elementary>+",
        "<elementary>"
    ],
    "<elementary>": [
        "<group>",
        "<any>",
        "<eos>",
        "<char>",
        "<set>"
    ],
    "<group>": [
        "(<regex>)"
    ],
    "<any>": ["."],
    "<eos>": ["$"],
    "<char>": [
        "a", "b", "c", "x", "y", "z"  # expand as needed
    ],
    "<set>": [
        "[<set_items>]",
        "[^<set_items>]"
    ],
    "<set_items>": [
        "<set_item><set_items>",
        "<set_item>"
    ],
    "<set_item>": [
        "<range>",
        "<char>"
    ],
    "<range>": [
        "a-z",
        "0-9"
    ]
}
