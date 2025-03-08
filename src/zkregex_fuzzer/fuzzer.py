"""
Implements the logic for generating regexes using The Fuzzing Book's GrammarFuzzer.
"""

import concurrent.futures
from concurrent.futures import ProcessPoolExecutor

from fuzzingbook.Grammars import Grammar, simple_grammar_fuzzer
from tqdm.auto import tqdm

from zkregex_fuzzer.configs import GRAMMARS, TARGETS, VALID_INPUT_GENERATORS
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
    oracle_params: tuple[bool, str],
    regex_num: int,
    inputs_num: int,
    max_depth: int,
    kwargs: dict,
):
    """
    Fuzz test with grammar.
    """
    target_runner = TARGETS[target_implementation]
    grammar = GRAMMARS[target_grammar]

    regex_generator = GrammarRegexGenerator(grammar, "<start>")
    regexes = regex_generator.generate_many(regex_num)
    logger.info(f"Generated {len(regexes)} regexes.")

    fuzz_with_regexes(regexes, inputs_num, target_runner, oracle_params, kwargs)


def fuzz_with_database(
    target_implementation: str,
    oracle_params: tuple[bool, str],
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
    oracle_params: tuple[bool, str],
    kwargs: dict,
):
    fuzz_with_regexes([regex], inputs_num, target_runner, oracle_params, kwargs)


def fuzz_with_dfa(
    target_implementation: str,
    oracle_params: tuple[bool, str],
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
        oracle,
        oracle_generator,
        inputs_num,
        max_input_size,
        kwargs,
    ) = params
    return harness_runtime(
        regex,
        target_runner,
        oracle,
        oracle_generator,
        inputs_num,
        max_input_size,
        kwargs,
    )


def bug_logging(regex, inputs, result):
    if result.status != HarnessStatus.SUCCESS:
        logger.info("-" * 80)
        logger.info(f"Found a bug with regex: {pretty_regex(regex)}")
        logger.info(f"Output path: {result.output_path}")
        logger.info(f"Inputs: {inputs}")
        logger.info(f"Result: {result.status}")
        logger.info(f"Failed inputs: {result.failed_inputs}")
        logger.info(f"Error message: {result.error_message}")
        logger.info("-" * 80)


def fuzz_with_regexes(
    regexes: list[str],
    inputs_num: int,
    target_runner: type[Runner],
    oracle_params: tuple[bool, str],
    kwargs: dict,
):
    """
    Fuzz test with pre-seeded regexes.
    """
    max_input_size = kwargs.get("max_input_size", None)
    oracle, oracle_generator = oracle_params
    if not oracle:
        raise NotImplementedError("Oracle not implemented")

    n_process = kwargs.get("process_num", 1)

    if n_process > 1:
        # Create parameter tuples for process_map
        params = [
            (
                regex,
                target_runner,
                oracle,
                oracle_generator,
                inputs_num,
                max_input_size,
                kwargs,
            )
            for regex in regexes
        ]

        # Use concurrent.futures directly for more control

        # Create progress bar
        with tqdm(total=len(params), desc="Testing Regexes") as pbar:
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

                        # Log status after each completion
                        logger.info(
                            f"Finished testing regex with {len(result[1])} inputs: {pretty_regex(regex)} ..."
                        )
                        bug_logging(regex, result[1], result[2])

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
                oracle,
                oracle_generator,
                inputs_num,
                max_input_size,
                kwargs,
            )
            logger.info(
                f"Finished testing regex with {len(result[1])} inputs: {pretty_regex(regex)} ..."
            )
            results.append(result)
            bug_logging(regex, result[1], result[2])

    stats = Stats(results)
    print_stats(stats)


def harness_runtime(
    regex, target_runner, oracle, oracle_generator, inputs_num, max_input_size, kwargs
) -> tuple[str, list[str], HarnessResult]:
    """
    Harness for running regexes.

    NOTE: This function is called by the Parallel library, so it runs in a separate process.
    I.e., no shared state between processes.
    """

    # We should use the PythonReRunner to check the validity of the regexes and the inputs.
    # If there is a bug in the PythonReRunner, we might not find it as we will think that
    # either the regex or the input is invalid.
    primary_runner = PythonReRunner
    if kwargs.get("process_num", 1) > 1:
        set_logging_enabled(False)
    generator = VALID_INPUT_GENERATORS[oracle_generator]
    regex_inputs = []
    try:
        regex_inputs = generator(regex, kwargs).generate_many(
            inputs_num, max_input_size
        )
    except ValueError as e:
        logger.warning(e)
    result = harness(regex, primary_runner, target_runner, regex_inputs, oracle, kwargs)
    return regex, regex_inputs, result
