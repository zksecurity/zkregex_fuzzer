"""
Implements the logic for generating regexes using The Fuzzing Book's GrammarFuzzer.
"""

import re
from fuzzingbook.Grammars import simple_grammar_fuzzer, Grammar
from zkregex_fuzzer.transformers import regex_to_grammar
from zkregex_fuzzer.configs import TARGETS, GRAMMARS, VALID_INPUT_GENERATORS
from zkregex_fuzzer.regexgen import GrammarRegexGenerator
from zkregex_fuzzer.harness import harness, HarnessStatus
from zkregex_fuzzer.runner import PythonReRunner
from zkregex_fuzzer.logger import logger

def fuzz_with_grammar(
        target_grammar: str,
        target_implementation: str,
        oracle_params: tuple[bool, str],
        regex_num: int,
        inputs_num: int,
        max_depth: int,
    ):
    """
    Fuzz test with grammar.
    """
    target_runner = TARGETS[target_implementation]
    grammar = GRAMMARS[target_grammar]

    regex_generator = GrammarRegexGenerator(grammar, "<start>")
    regexes = regex_generator.generate_many(regex_num)
    logger.info(f"Generated {len(regexes)} regexes.")
    oracle, oracle_generator = oracle_params
    if oracle:
        generator = VALID_INPUT_GENERATORS[oracle_generator]
        logger.info(f"Generating {inputs_num} inputs for each regex.")
        regexes_inputs = [generator(regex).generate_many(inputs_num) for regex in regexes]
    else:
        raise NotImplementedError("Oracle not implemented")

    # We should use the PythonReRunner to check the validity of the regexes and the inputs.
    # If there is a bug in the PythonReRunner, we might not find it as we will think that 
    # either the regex or the input is invalid.
    primary_runner = PythonReRunner
    for regex, inputs in zip(regexes, regexes_inputs):
        print(f"Testing regex: {regex} -------- ({len(inputs)} inputs)")
        result = harness(regex, primary_runner, target_runner, inputs, oracle)
        if result.status == HarnessStatus.FAILED:
            print("-" * 80)
            print(f"Found a bug with regex: {regex}")
            print(f"Inputs: {inputs}")
            print(f"Result: {result}")
