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

from zkregex_fuzzer.chars import ASCII_CHARS


def get_supported_symbols() -> set[str]:
    """
    Get the set of symbols that are supported by the regex engine.
    """
    # TODO make this configurable
    # Symbols should include at least all ASCII characters
    return ASCII_CHARS


def regex_to_nfa(regex: str) -> NFA:
    """
    Convert a regex to an NFA.
    """
    symbols = get_supported_symbols()
    regex = unwrap_regex(regex)

    try:
        return NFA.from_regex(regex, input_symbols=symbols)
    except Exception as e:
        raise ValueError(f"Failed to parse '{regex}' into an automaton: {e}")


def regex_to_dfa(regex: str) -> DFA:
    """
    Convert a regex to a DFA.
    """
    nfa = regex_to_nfa(regex)
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


def unwrap_regex(regex: str) -> str:
    """
    Unwrap a regex by removing the start and end anchors.
    """
    if regex.startswith("^"):
        regex = regex[1:]
    # There are also some more cases with "starting" "^"
    elif regex.startswith("(|^)"):
        regex = regex[4:]
    # Cases like '(\r\n|^)...', '(\r|^)...', '(\n|^)...'
    elif bool(re.match(r"^\([\r\n]*\|\^\).*", regex)):
        regex = regex[regex.find("^") + 2 :]
    elif bool(re.match(r"^\([\\r\\n]*\|\^\).*", regex)):
        regex = regex[regex.find("^") + 2 :]
    if regex.endswith("$"):
        regex = regex[:-1]
    return regex.replace("\n", r"\n").replace("\r", r"\r")


def wrapped_has_one_accepting_state_regex(regex: str) -> bool:
    """
    Returns True if converting the given regex to a DFA yields
    exactly one accepting (final) state. Returns False otherwise.

    NOTE:
      - As the automata-lib does not support starting with '^' and ending with '$',
      we just remove them from the regex and check if the rest of the regex has one accepting state.
    """
    return has_one_accepting_state_regex(unwrap_regex(regex))


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
) -> DFA:
    """
    Generate a random DFA with a given seed for reproducibility.

    Randomly incorporates regex features like character classes, repetition,
    and fixed string prefixes/suffixes.

    Parameters:
        max_depth: Maximum number of states in the DFA
        use_unicode: Whether to use Unicode characters in the alphabet
        single_final_state: Whether to generate a DFA with exactly one final state

    TODO:
      - Add regex features
      - Add support for more complex regex features
      - Add support for more complex DFA structures
    """
    # Original implementation for generating a DFA directly
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


def transform_dfa_to_single_final_state(dfa: DFA) -> DFA:
    """
    Convert a DFA with multiple final states to one with a single final state.

    This implementation follows a principled automata theory approach:
    1. Add a new final state
    2. Redirect transitions from original final states to this new state
    3. Make the new final state the only accepting state
    4. Ensure the DFA is complete

    Returns:
        A new DFA with exactly one final state
    """
    # If the DFA already has a single final state, return it as-is
    if len(dfa.final_states) == 1:
        return dfa

    # Create mutable copies of the DFA's components
    states = set(dfa.states)
    alphabet = set(dfa.input_symbols)
    transitions = {}
    for state in states:
        transitions[state] = {}
        for symbol in alphabet:
            if state in dfa.transitions and symbol in dfa.transitions[state]:
                transitions[state][symbol] = dfa.transitions[state][symbol]

    initial_state = dfa.initial_state
    original_finals = set(dfa.final_states)

    # Step 1: Add a new single final state
    new_final = max(states) + 1
    states.add(new_final)
    transitions[new_final] = {}

    # Step 2: Redirect transitions from all existing final states to the new final state
    for final_state in original_finals:
        for symbol in alphabet:
            if symbol in transitions[final_state]:
                transitions[final_state][symbol] = new_final
        if len(transitions[final_state]) == 0:
            transitions[final_state][list(alphabet)[0]] = new_final

    # Step 4: Create the transformed DFA with single final state
    new_dfa = DFA(
        states=states,
        input_symbols=alphabet,
        transitions=transitions,
        initial_state=initial_state,
        final_states={new_final},
        allow_partial=True,
    )
    # Step 5: Minimize the DFA to merge equivalent states
    # The automata-lib library has a built-in minify method
    try:
        minimized_dfa = new_dfa.minify()
        # check if we can transform the minimized dfa to a regex
        regex = transform_dfa_to_regex(minimized_dfa)
        if not regex:
            raise Exception("Failed to transform minimized DFA to regex")
        return minimized_dfa
    except Exception as e:
        raise Exception(f"DFA minimization failed: {e}")


def dfa_string_matching(
    regex: str,
    wanted_length: int = 50,
    direct_match: bool = True,
) -> str:
    """
    Convert `regex` to a DFA using automata-lib, then randomly generate a string
    that the DFA accepts. Returns a string that the DFA accepts.

    Parameters:
        regex: The regular expression to match
        wanted_length: The desired length of the generated string
        direct_match: If True, only follow paths that lead to accepting states
    """
    regex = unwrap_regex(regex)
    # Some hard limited length that we can't exceed
    # TODO make this configurable
    max_length = 500
    # Convert regex to NFA
    nfa = NFA.from_regex(regex, input_symbols=get_supported_symbols())

    # Start with the initial state and an empty string
    current_states = nfa._get_lambda_closures()[nfa.initial_state]
    result = ""

    # If we start in a final state and regex allows empty string, we might return empty
    if not current_states.isdisjoint(nfa.final_states) and random.random() < 0.2:
        return ""

    # If direct_match is True, precompute which states can reach a final state
    reachable_to_final = None
    if direct_match:
        # Compute states that can reach a final state (reverse BFS)
        reachable_to_final = set()
        queue = list(nfa.final_states)
        visited = set(queue)

        # Build reverse transition graph
        reverse_transitions = {}
        for state in nfa.states:
            reverse_transitions[state] = []

        for state in nfa.states:
            if state in nfa.transitions:
                for symbol, next_states in nfa.transitions[state].items():
                    for next_state in next_states:
                        reverse_transitions[next_state].append((state, symbol))

        # Do BFS from final states
        while queue:
            state = queue.pop(0)
            reachable_to_final.add(state)

            for prev_state, _ in reverse_transitions[state]:
                if prev_state not in visited:
                    visited.add(prev_state)
                    queue.append(prev_state)

    # Maximum number of attempts to find an accepting path
    max_attempts = 5
    for attempt in range(max_attempts):
        current_states = nfa._get_lambda_closures()[nfa.initial_state]
        result = ""

        # Try to build a matching string by traversing the NFA
        for _ in range(max_length):
            # Get all possible transitions from current states
            possible_moves = []
            for state in current_states:
                if state in nfa.transitions:
                    for symbol, next_states in nfa.transitions[state].items():
                        if symbol:  # Skip lambda transitions
                            for next_state in next_states:
                                # If direct_match is True, only consider moves that can reach a final state
                                if not direct_match or next_state in reachable_to_final:
                                    possible_moves.append((symbol, next_state))

            # No more possible moves
            if not possible_moves:
                break

            # Choose moves with a bias toward making progress
            # For longer patterns, we want to avoid getting stuck in loops
            if len(possible_moves) > 1 and len(result) > wanted_length * 0.7:
                # In later stages, prioritize moves that might lead to acceptance faster
                # We'll do this by favoring transitions to states closer to final states

                # Group possible moves by their target state
                moves_by_state = {}
                for symbol, next_state in possible_moves:
                    if next_state not in moves_by_state:
                        moves_by_state[next_state] = []
                    moves_by_state[next_state].append(symbol)

                # If we're in a state we've seen before, try to avoid it
                # Convert states to string representation for hashing
                current_state_str = "".join(str(s) for s in sorted(current_states))
                if hasattr(dfa_string_matching, "seen_states"):
                    if current_state_str in dfa_string_matching.seen_states:
                        # Try to choose a different path than before
                        dfa_string_matching.seen_states[current_state_str] += 1
                    else:
                        dfa_string_matching.seen_states[current_state_str] = 1
                else:
                    dfa_string_matching.seen_states = {current_state_str: 1}

                # Bias towards less-visited transitions
                weights = []
                for symbol, next_state in possible_moves:
                    next_state_str = "".join(
                        str(s) for s in sorted(nfa._get_lambda_closures()[next_state])
                    )
                    visits = dfa_string_matching.seen_states.get(next_state_str, 0)
                    # Weight inversely to number of visits (add 1 to avoid division by zero)
                    weights.append(1.0 / (visits + 1))

                # Normalize weights
                total = sum(weights)
                if total > 0:
                    weights = [w / total for w in weights]
                    symbol, next_state = random.choices(
                        possible_moves, weights=weights, k=1
                    )[0]
                else:
                    symbol, next_state = random.choice(possible_moves)
            else:
                # Standard random choice for early parts of the pattern
                symbol, next_state = random.choice(possible_moves)

            result += symbol

            # Update current states with the chosen move and its lambda closure
            current_states = nfa._get_lambda_closures()[next_state]

            # If we're in a final state, we might choose to stop
            if not current_states.isdisjoint(nfa.final_states):
                if random.random() < 0.3:
                    break
                # If we have reached the wanted length, we're more likely to stop
                if len(result) >= wanted_length and random.random() < 0.9:
                    break

        # Check if our string is accepted by the NFA
        if nfa.accepts_input(result):
            return result

        # If we failed, we'll try again with a clean slate
        if hasattr(dfa_string_matching, "seen_states"):
            delattr(dfa_string_matching, "seen_states")

    raise ValueError(f"Failed to generate a string that the NFA accepts: {regex}")
