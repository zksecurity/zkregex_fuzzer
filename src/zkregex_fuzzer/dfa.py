"""
dfa

A number of functions for working with DFAs.
"""

from automata.fa.nfa import NFA
from automata.fa.dfa import DFA

def regex_to_dfa(regex: str) -> DFA:
    """
    Convert a regex to a DFA.
    """
    try:
        nfa = NFA.from_regex(regex)
    except Exception as e:
        raise ValueError(f"Failed to parse '{regex}' into an automaton: {e}")
    try:
        return DFA.from_nfa(nfa, minify=True)
    except Exception as e:
        raise ValueError(f"Failed to convert NFA to DFA: {e}")

def has_multiple_accepting_states_regex(regex: str) -> bool:
    """
    Returns True if converting the given regex to a DFA yields
    multiple accepting (final) states. Returns False otherwise.

    NOTE:
      - Only handles a subset of regex syntax recognized by automata-lib.
      - For advanced Python regex features, a custom NFA builder is needed.
    """
    dfa = regex_to_dfa(regex)
    num_final_states = len(dfa.final_states)

    return num_final_states > 1

def has_multiple_accepting_states_dfa(dfa: DFA) -> bool:
    """
    Returns True if the given DFA has multiple accepting (final) states.
    Returns False otherwise.
    """
    return len(dfa.final_states) > 1
