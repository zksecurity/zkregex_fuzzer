"""
dfa

A number of functions for working with DFAs.
"""

import random

from automata.fa.dfa import DFA
from automata.fa.gnfa import GNFA
from automata.fa.nfa import NFA


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


def transform_dfa_to_regex(dfa: DFA) -> str:
    """
    Convert a DFA to a regular expression.
    """
    # Convert the DFA to an equivalent GNFA
    gnfa = GNFA.from_dfa(dfa)
    # Use state elimination to get a regular expression
    regex = gnfa.to_regex()
    return regex


def _pick_one_strategy(
    states: set, alphabet: set, transitions: dict, initial: str, original_finals: set
) -> DFA:
    """
    Choose one of the accepting states as the sole final state.
    """
    chosen_final = random.choice(list(original_finals))
    new_final_states = {chosen_final}
    # Redirect transitions that pointed to any other final state
    for state in states:
        for symbol in alphabet:
            if (
                transitions[state].get(symbol) in original_finals
                and transitions[state][symbol] != chosen_final
            ):
                transitions[state][symbol] = chosen_final
    # Remove other final states if they are no longer needed (unreachable and not initial)
    for f in list(original_finals):
        if f != chosen_final and f != initial:
            states.discard(f)
            transitions.pop(f, None)
    # Construct the new DFA
    return DFA(
        states=states,
        input_symbols=alphabet,
        transitions=transitions,
        initial_state=initial,
        final_states=new_final_states,
        allow_partial=True,
    )


def _new_dummy_strategy(
    states: set, alphabet: set, transitions: dict, initial: str, original_finals: set
) -> DFA:
    """
    Introduce a new dummy accepting state.
    """
    new_final_name = "DummyFinal"
    # Ensure the new state name is unique
    while new_final_name in states:
        new_final_name += "_X"
    # Add the new state
    states.add(new_final_name)
    # Redirect all transitions that lead into any original final state to the new dummy final
    for state in states:
        if state == new_final_name:
            continue
        for symbol in alphabet:
            if transitions[state].get(symbol) in original_finals:
                transitions[state][symbol] = new_final_name
    # Define the new final state's transitions. We can leave it partial (no outgoing transitions)
    # or make it a trap for completeness. Here we leave it with no outgoing transitions (partial DFA).
    transitions[new_final_name] = {}
    # Remove final status from original finals and drop those states if unreachable (except initial)
    for f in original_finals:
        if f != initial:
            states.discard(f)
            transitions.pop(f, None)
    # New final state set contains only the dummy state
    return DFA(
        states=states,
        input_symbols=alphabet,
        transitions=transitions,
        initial_state=initial,
        final_states={new_final_name},
        allow_partial=True,
    )


def _merge_strategy(
    states: set, alphabet: set, transitions: dict, initial: str, original_finals: set
) -> DFA:
    """
    Merge all accepting states into one unified state.
    """
    merged_name = "MergedFinal"
    while merged_name in states:
        merged_name += "_X"
    # If the initial state is one of the finals, handle carefully by keeping it (to preserve empty-string acceptance)
    if initial in original_finals:
        merged_name = (
            initial  # use initial as the merged final to preserve its identity
        )
    # Build the merged state's transition function by combining outgoing transitions of all original finals
    merged_transitions = {}
    for symbol in alphabet:
        destinations = set()
        for f in original_finals:
            if f not in transitions:
                continue
            dest = transitions[f].get(symbol)
            # If the destination is one of the original finals, treat it as a self-loop in the merged state
            if dest in original_finals:
                destinations.add(merged_name)
            elif dest is not None:
                destinations.add(dest)
        if len(destinations) == 1:
            # Exactly one possible destination for this symbol
            merged_transitions[symbol] = destinations.pop()
        elif len(destinations) > 1:
            # Conflict: multiple different destinations for the same symbol.
            # To keep the DFA deterministic, choose one arbitrarily (e.g., the first in the set).
            merged_transitions[symbol] = next(iter(destinations))
        # If destinations is empty, no transition defined (partial DFA for that symbol from merged state).
    # Remove all old final states (except if one is initial, which we are reusing as merged_name)
    for f in list(original_finals):
        if f == initial:  # if initial is being used as merged_name, skip removal
            continue
        states.discard(f)
        transitions.pop(f, None)
    # Add the merged state to the state set
    states.add(merged_name)
    # Update transitions: redirect any transition pointing to an old final to point to the merged state
    for state in list(states):
        if state == merged_name:
            continue
        for symbol in alphabet:
            if transitions[state].get(symbol) in original_finals:
                transitions[state][symbol] = merged_name
    # Set the merged state's transitions as computed
    transitions[merged_name] = merged_transitions
    # Define the single new final state
    return DFA(
        states=states,
        input_symbols=alphabet,
        transitions=transitions,
        initial_state=initial,
        final_states={merged_name},
        allow_partial=True,
    )


def transform_dfa_to_single_accepting_state(dfa: DFA, strategy: str = "random") -> DFA:
    """
    Transform a DFA to a single accepting state.
    """
    # If there's already one or zero accepting states, no change needed
    if len(dfa.final_states) <= 1:
        return dfa

    assert strategy in ["pick_one", "new_dummy", "merge", "random"]

    # Copy components of the DFA for modification
    states = set(dfa.states)
    alphabet = set(dfa.input_symbols)
    transitions = {
        state: dict(dest_dict)  # copy of inner dict
        for state, dest_dict in dfa.transitions.items()
    }
    initial = dfa.initial_state
    original_finals = set(dfa.final_states)

    # Randomly choose one of the transformation strategies
    if strategy == "random":
        strategy = random.choice(["pick_one", "new_dummy", "merge"])

    if strategy == "pick_one":
        return _pick_one_strategy(
            states, alphabet, transitions, initial, original_finals
        )
    elif strategy == "new_dummy":
        return _new_dummy_strategy(
            states, alphabet, transitions, initial, original_finals
        )
    else:
        return _merge_strategy(states, alphabet, transitions, initial, original_finals)
