"""
Implement transformes.

* regex_to_grammar: transforms a regex to a grammar

TODO:
    - Add more tests
    - Fix linting errors
"""

import sre_parse
import string
import sre_constants
from typing import Any, Dict, List, Tuple

from fuzzingbook.Grammars import Expansion, Grammar


# Define character sets for CATEGORY expansion
_PRINTABLE_ASCII_SET = set(string.printable)  # Using printable ASCII as a base set
_CATEGORY_CHARS_EXPANSION = {
    sre_constants.CATEGORY_DIGIT: set(string.digits),
    sre_constants.CATEGORY_NOT_DIGIT: _PRINTABLE_ASCII_SET - set(string.digits),
    sre_constants.CATEGORY_SPACE: set(string.whitespace),
    sre_constants.CATEGORY_NOT_SPACE: _PRINTABLE_ASCII_SET - set(string.whitespace),
    sre_constants.CATEGORY_WORD: set(string.ascii_letters + string.digits + "_"),
    sre_constants.CATEGORY_NOT_WORD: _PRINTABLE_ASCII_SET
    - set(string.ascii_letters + string.digits + "_"),
    # Add sre_constants.CATEGORY_LINEBREAK and sre_constants.CATEGORY_NOT_LINEBREAK if needed
}


def regex_to_grammar(regex: str) -> Grammar:
    """
    Convert a Python-style regex into a Fuzzing Book–style grammar.
    Produces expansions that should generate strings matching the regex,
    at least for common constructs.

    Handles these sre_parse tokens:
      - LITERAL: accumulate consecutive characters into a literal
      - ANY: dot '.' => expand to e.g. letters/digits/punct
      - IN: bracket class [abc], [0-9]
      - SUBPATTERN: grouped subpattern ( ... )
      - BRANCH: union (...|...)
      - AT: anchors '^' or '$' => skip in expansions
      - MAX_REPEAT: quantifiers {m,n}, *, +, ?

    This is a simplified approach that may not be exactly 1:1 with
    Python's entire regex engine, but demonstrates how to build a
    grammar from typical parse tokens.

    NOTE: Maybe we should do something like this:
    https://rahul.gopinath.org/post/2021/10/22/fuzzing-with-regular-expressions/
    Where we parse the regex concretely, and then convert it into a grammar.
    """

    parsed_pattern = sre_parse.parse(regex)
    # Convert the parse object to a list of tokens
    # Typically the top-level is a SubPattern object that is iterable
    tokens = list(parsed_pattern)

    grammar: Grammar = {}
    grammar["<start>"] = ["<REGEX_0>"]

    # We'll parse that top-level token list into a single rule <REGEX_0>
    parse_tokens_into_rule(tokens, grammar, "<REGEX_0>")

    return grammar


def parse_tokens_into_rule(
    token_list: List[Tuple[Any, Any]], grammar: Grammar, rule_name: str
) -> None:
    """
    Build expansions for `rule_name` in `grammar`, based on the given `token_list`.
    We'll produce a single or multiple expansions:
      - If we see a BRANCH token, we'll produce union expansions
      - Otherwise, we produce a single expansion (concatenation) for the tokens
    """

    # Because Python can have top-level BRANCH meaning union, we first detect that case.
    # If there's a single token like (BRANCH, (None, [list1, list2, ...])),
    # it means union of branch1, branch2, ...
    if len(token_list) == 1 and token_list[0][0] == sre_parse.BRANCH:
        # token_value is (None, [branch1_tokens, branch2_tokens, ...])
        _, (__, branches) = token_list[0]
        expansions = []
        for b_tokens in branches:
            # parse each branch as its own rule
            sub_rule = new_rule_name(grammar, prefix="BRANCH")
            parse_tokens_into_rule(b_tokens, grammar, sub_rule)
            expansions.append(sub_rule)
        grammar[rule_name] = expansions
        return

    # Otherwise, we treat the tokens as a concatenation
    # We'll accumulate sub-rules or literal text for each token, then produce a single expansion
    expansion_parts: List[str] = []
    literal_buffer: List[str] = []

    def flush_literal_buffer():
        """If we have buffered chars, turn them into a new rule (or direct expansion)."""
        if not literal_buffer:
            return None
        s = "".join(literal_buffer)
        literal_buffer.clear()
        sub_rule = new_rule_name(grammar, "LIT")
        grammar[sub_rule] = [s]
        return sub_rule

    i = 0
    while i < len(token_list):
        token_type, token_value = token_list[i]

        if token_type == sre_parse.LITERAL:
            # single char
            literal_buffer.append(chr(token_value))

        elif token_type == sre_parse.IN:
            # bracket class [ ... ]
            # flush any pending literal
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)

            # parse the bracket contents
            class_rule = handle_in_class(token_value, grammar)
            expansion_parts.append(class_rule)

        elif token_type == sre_parse.ANY:
            # dot (.)
            # flush literal
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)
            dot_rule = handle_dot(grammar)
            expansion_parts.append(dot_rule)

        elif token_type == sre_parse.SUBPATTERN:
            # group
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)

            # token_value is an sre_parse.SubPattern object.
            # Its .data attribute contains the list of tokens for the subpattern.
            sub_pattern_tokens = token_value.data

            group_rule = new_rule_name(grammar, "GRP")
            # Pass the actual list of tokens from the subpattern's data
            parse_tokens_into_rule(sub_pattern_tokens, grammar, group_rule)
            expansion_parts.append(group_rule)

        elif token_type == sre_parse.BRANCH:
            # union that is part of the sequence => can be complicated
            # Typically, top-level union is alone. But if we see it inline,
            # we can produce expansions with each branch. We'll do a naive approach:
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)

            _, (__, branches) = token_value
            # We'll create a union rule
            union_rule = new_rule_name(grammar, "UNION")
            # Each branch is a list of tokens. We'll parse each as a new rule
            union_exp = []
            for b_tokens in branches:
                br_subrule = new_rule_name(grammar, "BRNCH")
                parse_tokens_into_rule(b_tokens, grammar, br_subrule)
                union_exp.append(br_subrule)
            grammar[union_rule] = union_exp

            expansion_parts.append(union_rule)

        elif token_type == sre_parse.MAX_REPEAT:
            # e.g. {m,n}, or *, +, ?
            # token_value = (min_count, max_count, sub_tokens)
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)

            (min_count, max_count, sub_tokens) = token_value
            # parse the repeated piece
            repeated_rule = new_rule_name(grammar, "REP")
            parse_tokens_into_rule(sub_tokens, grammar, repeated_rule)
            # produce expansions that unroll from min..max (with some clamp)
            rep_rule = handle_max_repeat(repeated_rule, min_count, max_count, grammar)
            expansion_parts.append(rep_rule)

        elif token_type == sre_parse.AT:
            # anchors like ^ or $
            # skip them for expansions
            # flush literal if any
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)
            # do nothing for anchor text
            pass

        else:
            # flush literal and skip unknown tokens or handle them
            lit_rule = flush_literal_buffer()
            if lit_rule:
                expansion_parts.append(lit_rule)
            # You can add more elif for advanced tokens: CATEGORY, etc.
            pass

        i += 1

    # End of loop: flush any leftover literal
    lit_rule = flush_literal_buffer()
    if lit_rule:
        expansion_parts.append(lit_rule)

    if not expansion_parts:
        # If we ended up with no expansions, produce an empty string
        grammar[rule_name] = [""]
    else:
        # We'll produce a single expansion string by concatenating sub-rule references
        # e.g. <PART_0><PART_1>
        grammar[rule_name] = ["".join(expansion_parts)]


# ------------------------------------------------------------------------


def handle_in_class(token_list_in: List[Tuple[Any, Any]], grammar: Grammar) -> str:
    """
    Handle bracket classes [ ... ] like [a-z0-9\\w].
    token_list_in is a list of (op, val). e.g. (RANGE, (97, 122)) for a-z.
    We gather possible chars, considering negation and categories.
    Then define a new rule that enumerates those chars.
    """
    collected_chars_for_set = set()
    is_negated = False

    # Make a mutable copy of the token list to check for NEGATE
    processing_tokens = list(token_list_in)

    if processing_tokens and processing_tokens[0][0] == sre_constants.NEGATE:
        is_negated = True
        processing_tokens.pop(0)  # Remove NEGATE, process the rest

    for in_op, val in processing_tokens:
        if in_op == sre_constants.LITERAL:
            collected_chars_for_set.add(chr(val))
        elif in_op == sre_parse.RANGE:
            (start, end) = val
            # Ensure start <= end, though Python's range handles start > end by yielding nothing
            for cp in range(min(start, end), max(start, end) + 1):
                collected_chars_for_set.add(chr(cp))
        elif in_op == sre_constants.CATEGORY:
            expanded_set = _CATEGORY_CHARS_EXPANSION.get(val)
            if expanded_set:
                collected_chars_for_set.update(expanded_set)
            # else: you could log an unhandled category if necessary

    # Determine the final character set for the FuzzingBook grammar rule
    final_char_list_for_rule = []
    if is_negated:
        # For a negated class [^...], the rule should expand to characters NOT in collected_chars_for_set
        # We use a representative set (printable ASCII) as the universe
        valid_expansion_chars = _PRINTABLE_ASCII_SET - collected_chars_for_set
        if not valid_expansion_chars:  # Fallback if negation makes the set empty
            valid_expansion_chars.add("X")  # Default character like 'X' or a space
        final_char_list_for_rule = sorted(list(valid_expansion_chars))
    else:
        # For a positive class [...], the rule expands to characters IN collected_chars_for_set
        if not collected_chars_for_set:  # Fallback if the class was empty
            collected_chars_for_set.add("X")
        final_char_list_for_rule = sorted(list(collected_chars_for_set))

    rule_name = new_rule_name(grammar, "CLASS")
    # Each character in the final list becomes a separate expansion choice for the FuzzingBook grammar
    grammar[rule_name] = final_char_list_for_rule
    return rule_name


def handle_dot(grammar: Grammar) -> str:
    """
    Create or reuse a rule that enumerates which characters '.' can match.
    In Python, '.' typically matches all except newlines, but that might be too big.
    We'll pick a smaller set for demonstration.
    """
    dot_rule = new_rule_name(grammar, "DOT")
    # For a quick example, let's do letters + digits
    expansions = list(string.ascii_letters + string.digits)
    grammar[dot_rule] = expansions
    return dot_rule


def handle_max_repeat(
    sub_rule: str, min_count: int, max_count: int, grammar: Grammar
) -> str:
    """
    Convert a repetition from min_count..max_count into expansions that unroll
    sub_rule repeated that many times. Large max_count might be clamped.
    """
    # clamp large ranges for demonstration
    if max_count > 6 and max_count != sre_parse.MAXREPEAT:
        max_count = 6
    if max_count == sre_parse.MAXREPEAT:
        max_count = min_count + 3  # ad-hoc clamp

    rep_rule = new_rule_name(grammar, prefix="MREP")
    expansions = []
    for count in range(min_count, max_count + 1):
        expansions.append(
            sub_rule * count
        )  # e.g. "<SUBRULE><SUBRULE>... <count times>"
    # If min_count = 0, we also include the empty string as one expansion
    if min_count == 0:
        expansions.append("")

    grammar[rep_rule] = expansions
    return rep_rule


# Utility for generating unique rule names
def new_rule_name(grammar: Grammar, prefix="PART") -> str:
    rule_count = 0
    while True:
        candidate = f"<{prefix}_{rule_count}>"
        rule_count += 1
        if candidate not in grammar:
            return candidate
