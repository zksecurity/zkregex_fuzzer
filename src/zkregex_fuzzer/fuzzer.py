"""
Implements the logic for generating regexes using The Fuzzing Book's GrammarFuzzer.

NOTE: we generate the regexes outside of the runner to avoid duplicating the regexes.
Additionally, generating the regexes should be super fast so it's fine to do it outside of the runner.
"""

import concurrent.futures
import importlib
import importlib.util
import os
import signal
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from functools import wraps

import psutil
from fuzzingbook.Grammars import Grammar, simple_grammar_fuzzer
from tqdm.auto import tqdm

from zkregex_fuzzer.configs import (
    DEFAULT_HARNESS_TIMEOUT,
    DEFAULT_INPUT_GEN_TIMEOUT,
    DEFAULT_REGEX_TIMEOUT,
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


# Enhanced timeout decorator that kills subprocesses
def timeout_decorator(seconds, error_message="Timeout"):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [TimeoutError(error_message)]
            process_created = threading.Event()
            parent_pid = os.getpid()

            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    result[0] = e
                finally:
                    process_created.set()  # Signal that we're done

            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()

            # Wait for the function to complete or timeout
            thread.join(seconds)

            # If the thread is still alive after the timeout
            if thread.is_alive():
                logger.warning(f"Timeout occurred: {error_message}")

                # Find and kill all child processes
                try:
                    parent = psutil.Process(parent_pid)
                    children = parent.children(recursive=True)

                    for child in children:
                        try:
                            # Check if this is a process created by our function
                            # This is a heuristic - we're assuming processes created
                            # during the function execution are related to it
                            if child.create_time() > time.time() - seconds - 1:
                                logger.warning(
                                    f"Killing subprocess with PID {child.pid}"
                                )
                                child.kill()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                except Exception as e:
                    logger.error(f"Error killing subprocesses: {e}")

                raise TimeoutError(error_message)

            # If the function raised an exception, re-raise it
            if isinstance(result[0], Exception):
                raise result[0]

            return result[0]

        return wrapper

    return decorator


def _process_regex_inputs(param):
    """
    Process a single regex with its inputs.
    This function is called by the ProcessPoolExecutor.
    """
    regex, target_runner, oracle_params, inputs_num, max_input_size, kwargs = param

    # Get the overall timeout
    timeout_per_regex = kwargs.get("timeout_per_regex", DEFAULT_REGEX_TIMEOUT)

    # Apply a strict timeout to the entire function
    @timeout_decorator(
        timeout_per_regex, f"Timeout after {timeout_per_regex}s processing regex"
    )
    def process_with_timeout():
        return harness_runtime(
            regex, target_runner, oracle_params, inputs_num, max_input_size, kwargs
        )

    try:
        return process_with_timeout()
    except TimeoutError as e:
        logger.error(f"{e}: {pretty_regex(regex)}")
        return regex, [], []


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

    # Get timeout from kwargs or use default
    timeout_per_regex = kwargs.get("timeout_per_regex", DEFAULT_REGEX_TIMEOUT)

    # Set default timeouts for input generation and harness if not provided
    if "input_gen_timeout" not in kwargs:
        kwargs["input_gen_timeout"] = DEFAULT_INPUT_GEN_TIMEOUT
    if "harness_timeout" not in kwargs:
        kwargs["harness_timeout"] = DEFAULT_HARNESS_TIMEOUT

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

        # Create progress bar
        with tqdm(total=len(params), desc="Testing Regexes   ") as pbar:
            results = []

            # Use ProcessPoolExecutor with a context manager to ensure proper cleanup
            with ProcessPoolExecutor(max_workers=n_process) as executor:
                # Submit all tasks at once
                futures_to_regex = {
                    executor.submit(_process_regex_inputs, param): param[
                        0
                    ]  # regex is param[0]
                    for param in params
                }

                # Process results as they complete with a strict timeout
                for future in concurrent.futures.as_completed(futures_to_regex):
                    regex = futures_to_regex[future]
                    try:
                        # Add a strict timeout to get the result
                        result = future.result(timeout=timeout_per_regex)
                        results.append(result)
                        _process_results(regex, result)
                    except concurrent.futures.TimeoutError:
                        logger.error(
                            f"Executor timeout after {timeout_per_regex}s processing regex: {pretty_regex(regex)}"
                        )
                        # Try to cancel the future
                        future.cancel()
                        # Add a placeholder result to maintain count
                        results.append((regex, [], []))
                    except Exception as exc:
                        logger.error(
                            f"Error processing regex {pretty_regex(regex)}: {exc}"
                        )
                        # Add a placeholder result to maintain count
                        results.append((regex, [], []))
                    finally:
                        # Always update progress bar regardless of success/failure
                        pbar.update(1)
    else:
        results = []
        for regex in regexes:
            logger.info(f"Testing regex: {pretty_regex(regex)}")
            try:
                # Apply a strict timeout to the entire function
                @timeout_decorator(
                    timeout_per_regex,
                    f"Timeout after {timeout_per_regex}s processing regex",
                )
                def process_single_regex():
                    return harness_runtime(
                        regex,
                        target_runner,
                        oracle_params,
                        inputs_num,
                        max_input_size,
                        kwargs,
                    )

                result = process_single_regex()
                _process_results(regex, result)
                results.append(result)
            except TimeoutError as e:
                logger.error(f"{e}: {pretty_regex(regex)}")
                results.append((regex, [], []))
            except Exception as exc:
                logger.error(f"Error processing regex {pretty_regex(regex)}: {exc}")
                results.append((regex, [], []))

    stats = Stats(results)
    print_stats(stats)


def harness_runtime(
    regex, target_runner, oracle_params, inputs_num, max_input_size, kwargs
) -> tuple[str, list[list[str]], list[HarnessResult]]:
    """
    Harness for running regexes with separate timeouts for input generation and harness execution.
    """
    # Get timeouts from kwargs or use defaults
    input_gen_timeout = kwargs.get("input_gen_timeout", DEFAULT_INPUT_GEN_TIMEOUT)
    harness_timeout = kwargs.get("harness_timeout", DEFAULT_HARNESS_TIMEOUT)

    # We should use the PythonReRunner to check the validity of the regexes and the inputs.
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

        # Generate inputs with timeout
        regex_inputs = []
        try:
            # Apply a strict timeout to input generation
            @timeout_decorator(
                input_gen_timeout,
                f"Input generation timeout after {input_gen_timeout}s",
            )
            def generate_inputs():
                return generator(regex, kwargs).generate_many(
                    inputs_num, max_input_size
                )

            regex_inputs = generate_inputs()
        except TimeoutError as e:
            logger.warning(f"{e} for regex: {pretty_regex(regex)}")
            # Create a result with INPUT_GEN_TIMEOUT status
            result = HarnessResult(
                regex=regex,
                inp_num=len(regex_inputs),
                oracle=oracle,
                status=HarnessStatus.INPUT_GEN_TIMEOUT,
                failed_inputs=regex_inputs,
                error_message=str(e),
            )
            all_regex_inputs.append([])
            all_results.append(result)
            continue
        except ValueError as e:
            logger.warning(e)

        # Run harness with timeout
        try:
            # Apply a strict timeout to harness execution
            @timeout_decorator(
                harness_timeout, f"Harness execution timeout after {harness_timeout}s"
            )
            def run_harness():
                return harness(
                    regex, primary_runner, target_runner, regex_inputs, oracle, kwargs
                )

            result = run_harness()
            all_regex_inputs.append(regex_inputs)
            all_results.append(result)
        except TimeoutError as e:
            logger.warning(f"{e} for regex: {pretty_regex(regex)}")
            # Create a result with HARNESS_TIMEOUT status
            result = HarnessResult(
                regex=regex,
                inp_num=len(regex_inputs),
                oracle=oracle,
                status=HarnessStatus.HARNESS_TIMEOUT,
                failed_inputs=regex_inputs,
                error_message=str(e),
            )
            all_regex_inputs.append(regex_inputs)  # Include the generated inputs
            all_results.append(result)

        # Break if there was a compile error
        if result.status == HarnessStatus.COMPILE_ERROR:
            break

    return regex, all_regex_inputs, all_results
