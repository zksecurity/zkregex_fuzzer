"""
dfa

A number of functions for working with DFAs.
"""

import random
import re
import string
from typing import Dict, Optional, Set

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


def has_one_accepting_state_regex(regex: str) -> bool:
    """
    Returns True if converting the given regex to a DFA yields
    exactly one accepting (final) state. Returns False otherwise.
    """
    dfa = regex_to_dfa(regex)
    return len(dfa.final_states) == 1


def wrapped_has_one_accepting_state_regex(regex: str) -> bool:
    """
    Returns True if converting the given regex to a DFA yields
    exactly one accepting (final) state. Returns False otherwise.

    NOTE:
      - As the automata-lib does not support starting with '^' and ending with '$',
      we just remove them from the regex and check if the rest of the regex has one accepting state.
    """
    if regex.startswith("^"):
        regex = regex[1:]
    # There are also some more cases with "starting" "^"
    elif regex.startswith("(|^)"):
        regex = regex[4:]
    # Cases like '(\r\n|^)...', '(\r|^)...', '(\n|^)...'
    elif bool(re.match(r"^\([\\r\\n]*\|\^\).*", regex)):
        regex = regex[regex.find("^") + 2 :]
    if regex.endswith("$"):
        regex = regex[:-1]
    return has_one_accepting_state_regex(regex)


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


def _get_alphabet(
    use_unicode: bool, num_states: int, min_size: int = 2, max_size: int = 10
) -> Set[str]:
    """
    Generate a random alphabet for a DFA.
    """
    alphabet_size = random.randint(min_size, max_size)
    if use_unicode:
        alphabet = set()
        while len(alphabet) < alphabet_size:
            codepoint = random.randint(0, 0x10FFFF)
            try:
                char = chr(codepoint)
            except ValueError:
                continue  # skip invalid code points (if any)
            alphabet.add(char)
    else:
        # Restricted character set: letters, digits, punctuation, whitespace
        allowed_pool = (
            string.ascii_letters
            + string.digits
            + string.punctuation
            + string.whitespace
        )
        alphabet = set(random.sample(allowed_pool, alphabet_size))
    return alphabet


def generate_random_dfa(
    max_depth: int = 5,
    use_unicode: bool = False,
    single_final_state: bool = False,
    seed: Optional[int] = None,
) -> DFA:
    """
    Generate a random DFA with a given seed for reproducibility.
    """
    # Seed the random number generator for reproducibility (if seed is given)
    if seed is not None:
        random.seed(seed)
    else:
        seed = random.randrange(0, 2**32)
        random.seed(seed)

    num_states = random.randint(1, max_depth)

    # Define state names (q0, q1, ..., qN) and the initial state
    states = {f"q{i}" for i in range(num_states)}
    initial_state = "q0"

    # Determine final state(s)
    if single_final_state:
        final_state = random.choice(list(states))
        final_states = {final_state}
    else:
        # One or more final states (randomly chosen subset of states)
        num_finals = random.randint(1, num_states)  # at least one final
        final_states = set(random.sample(list(states), num_finals))

    alphabet = _get_alphabet(use_unicode, num_states)

    # Construct transitions: for each state and each symbol, choose a random next state
    transitions: Dict[str, Dict[str, str]] = {}
    for state in states:
        transitions[state] = {}
        for sym in alphabet:
            transitions[state][sym] = random.choice(list(states))

    # Ensure at least one self-loop (cycle)
    loop_exists = any(
        state == dest for state in states for dest in transitions[state].values()
    )
    if not loop_exists:
        # Add a self-loop on a random state with a random symbol
        some_state = random.choice(list(states))
        some_symbol = random.choice(list(alphabet))
        transitions[some_state][some_symbol] = some_state

    # Ensure at least one branching point (one state with two different outgoing targets)
    if len(alphabet) >= 2:
        branching_exists = any(len(set(transitions[s].values())) >= 2 for s in states)
        if not branching_exists:
            # Force branching on the initial state (as an example)
            sym_list = list(alphabet)
            # Make sure we have at least two symbols to create a branch
            if len(sym_list) >= 2:
                sym1, sym2 = sym_list[0], sym_list[1]
                # Assign different targets for sym1 and sym2 from the initial state
                if transitions[initial_state][sym1] == transitions[initial_state][sym2]:
                    # Pick a different state for sym2 if both symbols currently go to the same target
                    possible_targets = list(states - {transitions[initial_state][sym1]})
                    if possible_targets:
                        transitions[initial_state][sym2] = random.choice(
                            possible_targets
                        )
                    # (If no possible_targets, it means only one state exists, handled by loop above)

    # Introduce an "optional" path (allow skipping or taking a symbol):
    # We do this by creating an alternate route to a final state.
    if single_final_state and len(states) > 1:
        # For a single final state, ensure multiple paths (direct & indirect) to it
        final_state = next(iter(final_states))  # the only final state
        # If initial state doesn't already have a direct transition to final, add one
        if final_state not in transitions[initial_state].values():
            sym = random.choice(list(alphabet))
            transitions[initial_state][sym] = final_state
        # Also ensure an indirect path: find a symbol from initial that goes to an intermediate state
        intermediate_symbols = [
            sym
            for sym, dest in transitions[initial_state].items()
            if dest != final_state
        ]
        if intermediate_symbols:
            sym = intermediate_symbols[0]
            intermediate_state = transitions[initial_state][sym]
            # Link the intermediate state to the final state on some symbol (if not already final)
            if intermediate_state != final_state:
                sym2 = random.choice(list(alphabet))
                transitions[intermediate_state][sym2] = final_state
    elif not single_final_state:
        # If multiple finals are allowed, we can treat the start state as an optional accepting state
        # (Accept empty string or early termination)
        if initial_state not in final_states:
            final_states.add(initial_state)

    # Construct the DFA with the generated components
    dfa = DFA(
        states=states,
        input_symbols=alphabet,
        transitions=transitions,
        initial_state=initial_state,
        final_states=final_states,
    )

    # Minimize the DFA for a simpler equivalent automaton
    try:
        # If automata-lib provides a direct minification method
        dfa = dfa.minify()
    except AttributeError:
        # Fallback: convert to NFA and use DFA.from_nfa for minimization
        nfa_transitions: Dict[str, Dict[str, Set[str]]] = {}
        for state, trans in transitions.items():
            # Each DFA transition becomes a singleton set in the NFA transition
            nfa_transitions[state] = {sym: {dest} for sym, dest in trans.items()}
        nfa = NFA(
            states=states,
            input_symbols=alphabet,
            transitions=nfa_transitions,
            initial_state=initial_state,
            final_states=final_states,
        )
        # Convert NFA to DFA with minimization
        dfa = DFA.from_nfa(nfa, minify=True)

    return dfa


def dfa_string_matching(
    regex: str,
    max_length: int = 10,
) -> str:
    """
    Convert `regex` to a DFA using automata-lib, then randomly generate a string
    that the DFA accepts. Returns a string that the DFA accepts.
    """

    # Step 1: Convert to NFA or directly to DFA
    dfa = regex_to_dfa(regex)

    # Step 2: Determine for each state if acceptance is possible from that state
    # We'll do a BFS backward from each final state to mark reachable states.
    can_reach_accept = _compute_accept_reachability(dfa)

    # Step 3: Do a random walk
    s = _random_walk_dfa(dfa, can_reach_accept, max_length)
    if s is None:
        raise ValueError("Failed to generate a string that the DFA accepts.")
    return s


def _compute_accept_reachability(dfa: DFA) -> dict:
    """
    For each state, store whether it's possible to reach a final state.
    Returns a dict: state -> bool
    """
    # Start from final states and do BFS/DFS backwards:
    # We'll create a graph reversed: from each state, we see where it can come from.
    reverse_graph = {s: [] for s in dfa.states}
    for s in dfa.states:
        for sym, t in dfa.transitions[s].items():
            reverse_graph[t].append((s, sym))

    can_reach = {s: False for s in dfa.states}
    # Mark final states as can_reach = True
    queue = list(dfa.final_states)
    for f in queue:
        can_reach[f] = True

    # BFS
    idx = 0
    while idx < len(queue):
        current = queue[idx]
        idx += 1
        for prev_state, _symbol in reverse_graph[current]:
            if not can_reach[prev_state]:
                can_reach[prev_state] = True
                queue.append(prev_state)

    return can_reach


def _random_walk_dfa(
    dfa: DFA, can_reach_accept: dict, max_length: int
) -> Optional[str]:
    """
    Start at dfa.initial_state, randomly choose transitions that lead to states
    from which a final state is reachable, until we reach a final or exceed max_length.
    Note that max_length is not a hard limit, but rather a wanted length.
    Return the accepted string or None if we can't produce one.
    """
    hard_limit = 100
    current_state = dfa.initial_state
    out = []
    # We'll limit the number of steps to avoid infinite loops
    for length_counter in range(hard_limit):
        # If current_state is final, maybe stop or continue?
        # We'll do a random 50% chance to stop if final, producing a short string.
        if current_state in dfa.final_states:
            if length_counter >= max_length or random.random() < 0.5:
                # 50% chance to end early if final
                return "".join(out)
        # gather possible transitions that lead to can_reach_accept state
        next_options = [
            (symbol, dest)
            for symbol, dest in dfa.transitions[current_state].items()
            if can_reach_accept[dest]
        ]

        if not next_options:
            # no valid transitions, so if we are final we can stop; else give up
            if current_state in dfa.final_states:
                return "".join(out)
            else:
                return None

        # choose a random transition
        symbol, dest = random.choice(next_options)
        out.append(symbol)
        current_state = dest

    # If we are here, we've reached max_length. Accept if the state is final
    if current_state in dfa.final_states:
        return "".join(out)
    return None
