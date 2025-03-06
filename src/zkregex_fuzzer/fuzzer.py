"""
Implements the logic for generating regexes using The Fuzzing Book's GrammarFuzzer.
"""

from fuzzingbook.Grammars import Grammar, simple_grammar_fuzzer
from joblib import Parallel, delayed

from zkregex_fuzzer.configs import GRAMMARS, TARGETS, VALID_INPUT_GENERATORS
from zkregex_fuzzer.harness import HarnessResult, HarnessStatus, harness
from zkregex_fuzzer.logger import dynamic_filter, logger
from zkregex_fuzzer.regexgen import DatabaseRegexGenerator, GrammarRegexGenerator
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
    if oracle:
        generator = VALID_INPUT_GENERATORS[oracle_generator]
        logger.info(f"Generating {inputs_num} inputs for each regex.")
        regexes_inputs = []
        for regex in regexes:
            try:
                regex_inputs = generator(regex).generate_many(
                    inputs_num, max_input_size
                )
            except ValueError as e:
                logger.warning(e)
                regex_inputs = []
            regexes_inputs.append(regex_inputs)
    else:
        raise NotImplementedError("Oracle not implemented")

    n_process = kwargs.get("process_num", 1)
    results = Parallel(n_jobs=n_process)(
        delayed(harness_runtime)(regex, regex_inputs, target_runner, oracle, kwargs)
        for regex, regex_inputs in zip(regexes, regexes_inputs)
    )

    for regex, inputs, result in results:  # type: ignore
        if result.status != HarnessStatus.SUCCESS:
            print("-" * 80)
            print(f"Found a bug with regex: {pretty_regex(regex)}")
            print(f"Inputs: {inputs}")
            print(f"Result: {result.status}")
            print(f"Failed inputs: {result.failed_inputs}")
            print(f"Error message: {result.error_message}")
            print("-" * 80)


def harness_runtime(
    regex, inputs, target_runner, oracle, kwargs
) -> tuple[str, list[str], HarnessResult]:
    """
    Harness for running regexes.
    """

    # We should use the PythonReRunner to check the validity of the regexes and the inputs.
    # If there is a bug in the PythonReRunner, we might not find it as we will think that
    # either the regex or the input is invalid.
    primary_runner = PythonReRunner
    logger.info(f"Testing regex: {pretty_regex(regex)} -------- ({len(inputs)} inputs)")
    if kwargs.get("process_num", 1) > 1:
        dynamic_filter.set_enabled(False)
    result = harness(regex, primary_runner, target_runner, inputs, oracle, kwargs)
    return regex, inputs, result
