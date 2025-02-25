"""
Command-line interface to the grammar-based fuzzer for regex generation.
"""

import argparse
from zkregex_fuzzer.fuzzer import fuzz_with_grammar
from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.configs import TARGETS, VALID_INPUT_GENERATORS
from zkregex_fuzzer.logger import logger

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

    args = parser.parse_args()

    if args.oracle == "valid" and not args.valid_input_generator:
        raise ValueError("Valid input generator is required for valid oracle.")

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
        )
    

if __name__ == "__main__":
    main()
