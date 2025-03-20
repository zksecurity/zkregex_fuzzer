"""
Command-line interface to the grammar-based fuzzer for regex generation.
"""

import argparse
import os
import random
import uuid
from pathlib import Path

from zkregex_fuzzer.configs import (
    DEFAULT_HARNESS_TIMEOUT,
    DEFAULT_INPUT_GEN_TIMEOUT,
    DEFAULT_REGEX_TIMEOUT,
    FUZZER_VERSION,
    GENERATORS,
    INVALID_INPUT_GENERATORS,
    TARGETS,
    VALID_INPUT_GENERATORS,
)
from zkregex_fuzzer.fuzzer import (
    fuzz_with_database,
    fuzz_with_dfa,
    fuzz_with_grammar,
    fuzz_with_single_regex,
)
from zkregex_fuzzer.harness import HarnessStatus
from zkregex_fuzzer.logger import enable_file_logging, logger
from zkregex_fuzzer.report import Configuration, print_fuzzing_configuration
from zkregex_fuzzer.reproduce import reproduce
from zkregex_fuzzer.runner.circom import (
    CircomSubprocess,
    SnarkjsSubprocess,
    ZkRegexSubprocess,
)
from zkregex_fuzzer.runner.subprocess import BarretenbergSubprocess, NoirSubprocess


def fuzz_parser():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--regex-num",
        type=int,
        default=10,
        help="Number of regexes to generate (default: 10).",
    )
    parser.add_argument(
        "--inputs-num",
        type=int,
        default=10,
        help="Number of inputs to generate for each regex (default: 10).",
    )
    parser.add_argument(
        "--oracle",
        choices=["valid", "invalid", "combined"],
        help="Wherether the generated inputs should be valid or invalid wrt the regex.",
    )
    parser.add_argument(
        "--target",
        choices=list(TARGETS.keys()),
        help=f"The target to fuzz (options: {list(TARGETS.keys())}).",
    )
    parser.add_argument(
        "--valid-input-generator",
        choices=list(VALID_INPUT_GENERATORS.keys()),
        help=f"The valid input generator to use for the fuzzer (options: {list(VALID_INPUT_GENERATORS.keys())}).",
    )
    parser.add_argument(
        "--invalid-input-generator",
        choices=list(INVALID_INPUT_GENERATORS.keys()),
        help=f"The invalid input generator to use for the fuzzer (options: {list(INVALID_INPUT_GENERATORS.keys())}).",
    )
    parser.add_argument(
        "--seed",
        default=str(uuid.uuid4()),
        help="Seed for random generator (default: UUIDv4)",
    )
    parser.add_argument(
        "--save",
        choices=[status.name for status in HarnessStatus],
        nargs="+",
        help="Save reproducible files according to the specified Harness status",
    )
    parser.add_argument(
        "--save-output",
        type=str,
        default=os.path.join(os.getcwd(), "fuzzer_sessions", str(uuid.uuid4())[:5]),
        help="The output path where the reproducible files will be stored (default: .)",
    )
    parser.add_argument(
        "--fuzzer",
        choices=list(GENERATORS.keys()),
        help=f"The fuzzer to use for regex generation (options: {list(GENERATORS.keys())}).",
        required=True,
    )
    parser.add_argument(
        "--regex",
        type=str,
        help="The regex to fuzz when passing --fuzzer single.",
    )
    parser.add_argument(
        "--grammar-max-non-terminals",
        type=int,
        default=30,
        help="Maximum number of non-terminals in the grammar (default: 25).",
    )
    parser.add_argument(
        "--grammar-custom-grammar",
        type=str,
        default="basic",
        help="The custom grammar to use for the fuzzer. If a path ended in .py is passed, it will be used as a custom grammar file. Otherwise, the grammar will be generated using the grammar.py file in the zkregex_fuzzer package (default: basic).",
    )
    parser.add_argument(
        "--max-input-size",
        type=int,
        default=600,
        help="Maximum size of the circuit input (default: 600).",
    )
    parser.add_argument(
        "--process-num",
        type=int,
        default=1,
        help="Number of parallel process to use for the fuzzer (default: 1).",
    )
    parser.add_argument(
        "--circom-library",
        nargs="*",
        type=str,
        help="Path to the circom library to be included",
    )

    parser.add_argument(
        "--circom-prove",
        action="store_true",
        help="Run the proving and verification step with SnarkJS.",
    )

    parser.add_argument(
        "--circom-ptau",
        type=str,
        help="Path to the ptau (powers-of-tau) file for the proving step",
    )

    parser.add_argument(
        "--noir-prove",
        action="store_true",
        help="Run the proving and verification step with Barretenberg.",
    )

    parser.add_argument(
        "--logger-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logger level (default: INFO).",
    )
    parser.add_argument(
        "--predefined-inputs",
        nargs="*",
        type=str,
        help="Predefined inputs to use for the fuzzer.",
    )
    # timeout options
    parser.add_argument(
        "--timeout-per-regex",
        type=int,
        default=DEFAULT_REGEX_TIMEOUT,
        help="Timeout for regex generation (default: 420).",
    )
    parser.add_argument(
        "--input-gen-timeout",
        type=int,
        default=DEFAULT_INPUT_GEN_TIMEOUT,
        help="Timeout for input generation (default: 120).",
    )
    parser.add_argument(
        "--harness-timeout",
        type=int,
        default=DEFAULT_HARNESS_TIMEOUT,
        help="Timeout for harness execution (default: 300).",
    )
    return parser


def reproduce_parser():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "--path",
        nargs="+",
        type=str,
        help="Path to the target directory output that want to be reproduced (support wildcard pattern).",
        required=True,
    )
    parser.add_argument(
        "--logger-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logger level (default: INFO).",
    )

    return parser


def do_fuzz(args):
    if args.valid_input_generator == "predefined" and not args.predefined_inputs:
        print("Predefined inputs are required for predefined valid input generator.")
        exit(1)

    logging_file = None
    if args.process_num > 1:
        logging_file = enable_file_logging()

    zk_regex_version = None
    circom_version = None
    snarkjs_version = None
    noir_version = None
    bb_version = None

    if args.target == "circom":
        try:
            zk_regex_version = ZkRegexSubprocess.get_installed_version()
            circom_version = CircomSubprocess.get_installed_version()
            if args.circom_prove:
                snarkjs_version = SnarkjsSubprocess.get_installed_version()

        except ValueError as e:
            print(e)
            exit(1)

        # check if path to circom library passed as -l arg exists
        if args.circom_library:
            normalized_path = []
            for path in args.circom_library:
                abs_path = Path(path).resolve()
                if not abs_path.exists():
                    print(f"Path to circom library {abs_path} does not exist.")
                    exit(1)
                normalized_path.append(str(abs_path))
            args.circom_library = normalized_path
        else:
            print("Path to circom library is required for circom target.")
            exit(1)

        # check if path to ptau used in proving step exists
        if args.circom_prove:
            if not args.circom_ptau:
                print("Path to ptau file is required for proving.")
                exit(1)

            ptau_path = Path(args.circom_ptau).resolve()
            if not ptau_path.exists():
                print(f"Path to ptau file {ptau_path} does not exist.")
                exit(1)

    elif args.target == "noir":
        try:
            zk_regex_version = ZkRegexSubprocess.get_installed_version()
            noir_version = NoirSubprocess.get_installed_version()
            if args.noir_prove:
                bb_version = BarretenbergSubprocess.get_installed_version()
        except ValueError as e:
            print(e)
            exit(1)

    configuration = Configuration(
        fuzzer_version=FUZZER_VERSION,
        fuzzer=args.fuzzer,
        target=args.target,
        oracle=args.oracle,
        valid_input_generator=args.valid_input_generator,
        invalid_input_generator=args.invalid_input_generator,
        regex_num=args.regex_num,
        inputs_num=args.inputs_num,
        grammar_max_non_terminals=args.grammar_max_non_terminals,
        grammar_custom_grammar=args.grammar_custom_grammar,
        seed=args.seed,
        zk_regex_version=zk_regex_version,
        circom_version=circom_version,
        snarkjs_version=snarkjs_version,
        noir_version=noir_version,
        bb_version=bb_version,
        num_process=args.process_num,
        logging_file=logging_file,
        output_path=args.save_output,
        save_options=args.save,
    )

    # Use the new reporting function to print configuration
    print_fuzzing_configuration(configuration)

    kwargs = vars(args)

    # set global seed
    random.seed(args.seed)

    dir_path = Path(args.save_output)
    dir_path.mkdir(parents=True, exist_ok=True)

    if args.oracle == "valid":
        if not args.valid_input_generator:
            print("Valid input generator is required for valid oracle.")
            exit(1)
        oracle_params = [(True, args.valid_input_generator)]
    elif args.oracle == "invalid":
        if not args.invalid_input_generator:
            print("Invalid input generator is required for invalid oracle.")
            exit(1)
        oracle_params = [(False, args.invalid_input_generator)]
    elif args.oracle == "combined":
        if not args.valid_input_generator or not args.invalid_input_generator:
            print(
                "Valid and invalid input generators are required for combined oracle."
            )
            exit(1)
        oracle_params = [
            (True, args.valid_input_generator),
            (False, args.invalid_input_generator),
        ]
    else:
        print("Oracle is required.")
        exit(1)

    if args.fuzzer == "grammar":
        fuzz_with_grammar(
            target_grammar=args.grammar_custom_grammar,
            target_implementation=args.target,
            oracle_params=oracle_params,
            regex_num=args.regex_num,
            inputs_num=args.inputs_num,
            max_depth=args.grammar_max_non_terminals,
            kwargs=kwargs,
        )
    elif args.fuzzer == "database":
        fuzz_with_database(
            target_implementation=args.target,
            oracle_params=oracle_params,
            regex_num=args.regex_num,
            inputs_num=args.inputs_num,
            kwargs=kwargs,
        )
    elif args.fuzzer == "dfa":
        fuzz_with_dfa(
            target_implementation=args.target,
            oracle_params=oracle_params,
            regex_num=args.regex_num,
            inputs_num=args.inputs_num,
            kwargs=kwargs,
        )
    elif args.fuzzer == "single":
        if not args.regex:
            print("Regex is required when passing --fuzzer single.")
            exit(1)
        fuzz_with_single_regex(
            regex=args.regex,
            inputs_num=args.inputs_num,
            target_runner=TARGETS[args.target],
            oracle_params=oracle_params,
            kwargs=kwargs,
        )

    # if dir_path is empty, delete it
    if not os.listdir(dir_path):
        os.rmdir(dir_path)


def do_reproduce(args):
    reproduce(args.path)


def main():
    parser = argparse.ArgumentParser()

    subparser = parser.add_subparsers(dest="subcommand")
    subparser.add_parser(
        "fuzz", help="Fuzz the target regex implementation.", parents=[fuzz_parser()]
    )
    subparser.add_parser(
        "reproduce",
        help="Reproduce the bug that found by the fuzzer.",
        parents=[reproduce_parser()],
    )

    args = parser.parse_args()

    logger.setLevel(args.logger_level)

    if args.subcommand == "fuzz":
        do_fuzz(args)
    elif args.subcommand == "reproduce":
        do_reproduce(args)


if __name__ == "__main__":
    main()
