"""
Command-line interface to the grammar-based fuzzer for regex generation.
"""

import argparse
import os
from pathlib import Path
from zkregex_fuzzer.fuzzer import fuzz_with_database, fuzz_with_grammar
from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.configs import TARGETS, VALID_INPUT_GENERATORS, GENERATORS
from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.runner.circom import CircomSubprocess, SnarkjsSubprocess, ZkRegexSubprocess

def main():
    parser = argparse.ArgumentParser(
        description="Generate fuzzed regexes using The Fuzzing Book's GrammarFuzzer."
    )
    parser.add_argument(
        "--regex-num",
        type=int,
        default=10,
        help="Number of regexes to generate (default: 10)."
    )
    parser.add_argument(
        "--inputs-num",
        type=int,
        default=10,
        help="Number of inputs to generate for each regex (default: 10)."
    )
    parser.add_argument(
        "--oracle",
        choices=["valid", "invalid"],
        help="Wherether the generated inputs should be valid or invalid wrt the regex."
    )
    parser.add_argument(
        "--target",
        choices=list(TARGETS.keys()),
        help=f"The target to fuzz (options: {list(TARGETS.keys())})."
    )
    parser.add_argument(
        "--valid-input-generator",
        choices=list(VALID_INPUT_GENERATORS.keys()),
        help=f"The valid input generator to use for the fuzzer (options: {list(VALID_INPUT_GENERATORS.keys())})."
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.getcwd(),
        help=f"The output path where the reproducible files will be stored (default: .)"
    )
    parser.add_argument(
        "--fuzzer",
        choices=list(GENERATORS.keys()),
        help=f"The fuzzer to use for regex generation (options: {list(GENERATORS.keys())}).",
        required=True,
    )
    parser.add_argument(
        "--grammar-max-depth",
        type=int,
        default=5,
        help="Maximum depth of recursion in the grammar (default: 5)."
    )
    parser.add_argument(
        "--circom-max-input-size",
        type=int,
        default=600,
        help="Maximum size of the circuit input (default: 600)."
    )
    parser.add_argument(
        "--circom-library",
        nargs="*",
        type=str,
        help="Path to the circom library to be included"
    )

    parser.add_argument(
        "--circom-prove",
        action="store_true",
        help="Run the proving and verification step with SnarkJS."
    )

    parser.add_argument(
        "--circom-ptau",
        type=str,
        help="Path to the ptau (powers-of-tau) file for the proving step"
    )
    parser.add_argument(
        "--logger-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logger level (default: INFO)."
    )

    args = parser.parse_args()

    logger.setLevel(args.logger_level)

    if args.oracle == "valid" and not args.valid_input_generator:
        print("Valid input generator is required for valid oracle.")
        exit(1)
    
    if args.target == "circom":
        try:
            circom_version = CircomSubprocess.get_installed_version()
            snarkjs_version = SnarkjsSubprocess.get_installed_version()
            zk_regex_version = ZkRegexSubprocess.get_installed_version()
            print("-" * 80)
            print(f"Circom: {circom_version}")
            print(f"SnarkJS: {snarkjs_version}")
            print(f"zk-regex: {zk_regex_version}")
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

    print("-" * 80)
    print(f"Fuzzing with {args.fuzzer} fuzzer.")
    print("=" * 80)
    print(f"Target: {args.target}")
    print(f"Oracle: {args.oracle}")
    print(f"Valid input generator: {args.valid_input_generator}")
    print(f"Regex num: {args.regex_num}")
    print(f"Inputs num: {args.inputs_num}")
    print(f"Max depth: {args.grammar_max_depth}")
    print("-" * 80)

    if args.fuzzer == "grammar":
        fuzz_with_grammar(
            target_grammar="basic",
            target_implementation=args.target,
            oracle_params=(args.oracle == "valid", args.valid_input_generator),
            regex_num=args.regex_num,
            inputs_num=args.inputs_num,
            max_depth=args.grammar_max_depth,
            kwargs=vars(args)
        )
    elif args.fuzzer == "database":
        fuzz_with_database(
            target_implementation=args.target,
            oracle_params=(args.oracle == "valid", args.valid_input_generator),
            regex_num=args.regex_num,
            inputs_num=args.inputs_num,
            kwargs=vars(args)
        )
    

if __name__ == "__main__":
    main()
