"""
fuzzer.py

Implements the logic for generating regexes using The Fuzzing Book's GrammarFuzzer.
"""

import re
from fuzzingbook.Grammars import simple_grammar_fuzzer, Grammar
from zkregex_fuzzer.transformers import regex_to_grammar

def grammar_fuzzer(grammar: Grammar, start_symbol: str, max_nonterminals: int = 10, max_expansion_trials: int = 100): 
    return simple_grammar_fuzzer(grammar,
                           start_symbol=start_symbol,
                           max_nonterminals=max_nonterminals,
                           max_expansion_trials=max_expansion_trials)


def is_valid_regex(regex: str) -> bool:
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


def generate_regexes(grammar: Grammar, num=10, max_depth=5):
    """
    Generate `num` random regex strings using the grammar.
    :param num: Number of regex strings to generate
    :param max_depth: Maximum expansion depth
    :return: A list of generated regex strings
    """

    results = []
    while len(results) < num:
        regex = grammar_fuzzer(grammar, "<start>", max_depth)
        print(is_valid_regex(regex))
        try:
            grammar_from_regex = regex_to_grammar(regex)
            solution = grammar_fuzzer(grammar_from_regex, "<start>", max_depth)
            results.append((regex, grammar_from_regex, solution))
        except Exception as e:
            continue

    return results
