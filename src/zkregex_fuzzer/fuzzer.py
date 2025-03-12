"""
Implements the logic for generating regexes using The Fuzzing Book's GrammarFuzzer.

NOTE: we generate the regexes outside of the runner to avoid duplicating the regexes.
Additionally, generating the regexes should be super fast so it's fine to do it outside of the runner.
"""

import concurrent.futures
import importlib
import importlib.util
import os
from concurrent.futures import ProcessPoolExecutor

from fuzzingbook.Grammars import Grammar, simple_grammar_fuzzer
from tqdm.auto import tqdm

from zkregex_fuzzer.configs import (
    GRAMMARS,
    INVALID_INPUT_GENERATORS,
    TARGETS,
    VALID_INPUT_GENERATORS,
)
from zkregex_fuzzer.harness import HarnessResult, HarnessStatus, harness
from zkregex_fuzzer.logger import logger, set_logging_enabled
from zkregex_fuzzer.regexgen import (
    DatabaseRegexGenerator,
    DFARegexGenerator,
    GrammarRegexGenerator,
)
from zkregex_fuzzer.report import Stats, print_stats
from zkregex_fuzzer.runner import PythonReRunner
from zkregex_fuzzer.runner.base_runner import Runner
from zkregex_fuzzer.transformers import regex_to_grammar
from zkregex_fuzzer.utils import pretty_regex


def fuzz_with_grammar(
    target_grammar: str,
    target_implementation: str,
    oracle_params: list[tuple[bool, str]],
    regex_num: int,
    inputs_num: int,
    max_depth: int,
    kwargs: dict,
):
    """
    Fuzz test with grammar.
    """
    target_runner = TARGETS[target_implementation]

    if target_grammar == "basic":
        grammar = GRAMMARS[target_grammar]
    elif target_grammar.endswith(".py"):
        try:
            # Get absolute path
            if not os.path.isabs(target_grammar):
                # Assume relative to current working directory
                target_grammar = os.path.abspath(target_grammar)
            if not os.path.exists(target_grammar):
                raise ValueError(f"Grammar file not found: {target_grammar}")
            # Load the module from file path
            spec = importlib.util.spec_from_file_location(
                "grammar_module", target_grammar
            )
            if spec is None:
                raise ValueError(f"Failed to create spec for grammar: {target_grammar}")
            grammar_module = importlib.util.module_from_spec(spec)
            if spec.loader is None:
                raise ValueError(
                    f"Failed to create loader for grammar: {target_grammar}"
                )
            spec.loader.exec_module(grammar_module)

            grammar = grammar_module.grammar
        except ImportError as e:
            raise ValueError(f"Failed to import grammar: {e}")
    else:
        raise ValueError(f"Invalid grammar: {target_grammar}")

    regex_generator = GrammarRegexGenerator(
        grammar, "<start>", max_nonterminals=max_depth
    )
    regexes = regex_generator.generate_many(regex_num)
    logger.info(f"Generated {len(regexes)} regexes.")

    fuzz_with_regexes(regexes, inputs_num, target_runner, oracle_params, kwargs)


def fuzz_with_database(
    target_implementation: str,
    oracle_params: list[tuple[bool, str]],
    regex_num: int,
    inputs_num: int,
    kwargs: dict,
):
    """
    Fuzz test with database.
    """
    target_runner = TARGETS[target_implementation]

    regex_generator = DatabaseRegexGenerator()
    regexes = regex_generator.generate_many(regex_num)
    logger.info(f"Generated {len(regexes)} regexes.")

    fuzz_with_regexes(regexes, inputs_num, target_runner, oracle_params, kwargs)


def fuzz_with_single_regex(
    regex: str,
    inputs_num: int,
    target_runner: type[Runner],
    oracle_params: list[tuple[bool, str]],
    kwargs: dict,
):
    fuzz_with_regexes([regex], inputs_num, target_runner, oracle_params, kwargs)


def fuzz_with_dfa(
    target_implementation: str,
    oracle_params: list[tuple[bool, str]],
    regex_num: int,
    inputs_num: int,
    kwargs: dict,
):
    """
    Fuzz test with DFA.
    """
    target_runner = TARGETS[target_implementation]

    regex_generator = DFARegexGenerator()
    regexes = regex_generator.generate_many(regex_num)
    logger.info(f"Generated {len(regexes)} regexes.")

    fuzz_with_regexes(regexes, inputs_num, target_runner, oracle_params, kwargs)


# Define a proper function that can be pickled (outside of any other function)
def _process_regex_inputs(params):
    """Process a single regex with its inputs (for parallel processing)"""
    (
        regex,
        target_runner,
        oracle_params,
        inputs_num,
        max_input_size,
        kwargs,
    ) = params
    return harness_runtime(
        regex,
        target_runner,
        oracle_params,
        inputs_num,
        max_input_size,
        kwargs,
    )


def bug_logging(regex, inputs, result):
    if result.status != HarnessStatus.SUCCESS:
        logger.info("-" * 80)
        logger.info(f"Found a bug with regex: {pretty_regex(regex)}")
        logger.info(f"Output path: {result.output_path}")
        logger.info(f"Oracle: {result.oracle}")
        logger.info(f"Inputs: {inputs}")
        logger.info(f"Result: {result.status}")
        logger.info(f"Failed inputs: {result.failed_inputs}")
        logger.info(f"Error message: {result.error_message}")
        logger.info("-" * 80)


def fuzz_with_regexes(
    regexes: list[str],
    inputs_num: int,
    target_runner: type[Runner],
    oracle_params: list[tuple[bool, str]],
    kwargs: dict,
):
    """
    Fuzz test with pre-seeded regexes.
    """

    def _process_results(regex, result):
        for inputs, oracle_result in zip(result[1], result[2]):
            oracle_str = "valid" if oracle_result.oracle else "invalid"
            # Log status after each completion
            logger.info(
                f"Finished testing regex with {len(inputs)} inputs and oracle {oracle_str}: {pretty_regex(regex)} ({oracle_result.status})..."
            )
            bug_logging(regex, inputs, oracle_result)

    max_input_size = kwargs.get("max_input_size", None)
    n_process = kwargs.get("process_num", 1)

    if n_process > 1:
        # Create parameter tuples for process_map
        params = [
            (
                regex,
                target_runner,
                oracle_params,
                inputs_num,
                max_input_size,
                kwargs,
            )
            for regex in regexes
        ]

        # Use concurrent.futures directly for more control

        # Create progress bar
        with tqdm(total=len(params), desc="Testing Regexes   ") as pbar:
            results = []

            # Use ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=n_process) as executor:
                # Submit all tasks
                future_to_regex = {
                    executor.submit(_process_regex_inputs, param): param[
                        0
                    ]  # regex is param[0]
                    for param in params
                }
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_regex):
                    regex = future_to_regex[future]
                    try:
                        result = future.result()
                        results.append(result)

                        _process_results(regex, result)

                        # Update progress bar
                        pbar.update(1)
                    except Exception as exc:
                        logger.error(
                            f"Error processing regex {pretty_regex(regex)}: {exc}"
                        )
                        pbar.update(1)
    else:
        results = []
        for regex in regexes:
            logger.info(f"Testing regex: {pretty_regex(regex)}")
            result = harness_runtime(
                regex,
                target_runner,
                oracle_params,
                inputs_num,
                max_input_size,
                kwargs,
            )
            _process_results(regex, result)
            results.append(result)

    stats = Stats(results)
    print_stats(stats)


def harness_runtime(
    regex, target_runner, oracle_params, inputs_num, max_input_size, kwargs
) -> tuple[str, list[list[str]], list[HarnessResult]]:
    """
    Harness for running regexes.

    NOTE: This function is called by the Parallel library, so it runs in a separate process.
    I.e., no shared state between processes.

    TODO: This is slightly inefficient as we are compiling the regexes multiple times.
    """

    # We should use the PythonReRunner to check the validity of the regexes and the inputs.
    # If there is a bug in the PythonReRunner, we might not find it as we will think that
    # either the regex or the input is invalid.
    primary_runner = PythonReRunner
    if kwargs.get("process_num", 1) > 1:
        set_logging_enabled(False)
    all_regex_inputs = []
    all_results = []
    for oracle, oracle_generator in oracle_params:
        if oracle:
            generator = VALID_INPUT_GENERATORS[oracle_generator]
        else:
            generator = INVALID_INPUT_GENERATORS[oracle_generator]
        regex_inputs = []
        try:
            regex_inputs = generator(regex, kwargs).generate_many(
                inputs_num, max_input_size
            )
        except ValueError as e:
            logger.warning(e)
        result = harness(
            regex, primary_runner, target_runner, regex_inputs, oracle, kwargs
        )
        all_regex_inputs.append(regex_inputs)
        all_results.append(result)
        if result.status == HarnessStatus.COMPILE_ERROR:
            break
    return regex, all_regex_inputs, all_results
