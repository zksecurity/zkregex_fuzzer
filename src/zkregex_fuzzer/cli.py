"""
Command-line interface to the grammar-based fuzzer for regex generation.
"""

import argparse
from pathlib import Path
from zkregex_fuzzer.fuzzer import fuzz_with_grammar
from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.configs import TARGETS, VALID_INPUT_GENERATORS
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
        "--max-input-size",
        type=int,
        default=200,
        help="Maximum size of the circuit input (default: 200)."
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
        "--fuzzer",
        choices=["grammar"],
        help=f"The fuzzer to use for the fuzzer (options: grammar).",
        required=True,
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum depth of recursion in the grammar (default: 5)."
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

    args = parser.parse_args()

    if args.oracle == "valid" and not args.valid_input_generator:
        raise ValueError("Valid input generator is required for valid oracle.")
    
    if args.target == "circom":
        circom_version = CircomSubprocess.get_installed_version()
        snarkjs_version = SnarkjsSubprocess.get_installed_version()
        zk_regex_version = ZkRegexSubprocess.get_installed_version()
        print("-" * 80)
        print(f"Circom: {circom_version}")
        print(f"SnarkJS: {snarkjs_version}")
        print(f"zk-regex: {zk_regex_version}")

        # check if path to circom library passed as -l arg exists
        normalized_path = []
        for path in args.circom_library:
            abs_path = Path(path).resolve()
            if not abs_path.exists():
                raise ValueError(f"Path to circom library {abs_path} does not exist.")
            normalized_path.append(str(abs_path))
        args.circom_library = normalized_path

        # check if path to ptau used in proving step exists
        if args.circom_prove:
            if not args.circom_ptau:
                raise ValueError("Path to ptau file is required for proving.")
            
            ptau_path = Path(args.circom_ptau).resolve()
            if not ptau_path.exists():
                raise ValueError(f"Path to ptau file {ptau_path} does not exist.")

    print("-" * 80)
    print(f"Fuzzing with {args.fuzzer} fuzzer.")
    print("=" * 80)
    print(f"Target: {args.target}")
    print(f"Oracle: {args.oracle}")
    print(f"Valid input generator: {args.valid_input_generator}")
    print(f"Regex num: {args.regex_num}")
    print(f"Inputs num: {args.inputs_num}")
    print(f"Max depth: {args.max_depth}")
    print("-" * 80)

    if args.fuzzer == "grammar":
        fuzz_with_grammar(
            target_grammar="basic",
            target_implementation=args.target,
            oracle_params=(args.oracle == "valid", args.valid_input_generator),
            regex_num=args.regex_num,
            inputs_num=args.inputs_num,
            max_depth=args.max_depth,
            kwargs=vars(args)
        )
    

if __name__ == "__main__":
    main()
