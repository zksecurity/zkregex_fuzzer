"""
Command-line interface to the grammar-based fuzzer for regex generation.
"""

import argparse
from zkregex_fuzzer.fuzzer import generate_regexes
from zkregex_fuzzer.grammar import REGEX_GRAMMAR
def main():
    parser = argparse.ArgumentParser(
        description="Generate fuzzed regexes using The Fuzzing Book's GrammarFuzzer."
    )
    parser.add_argument(
        "--num",
        type=int,
        default=10,
        help="Number of regexes to generate (default: 10)."
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum depth of recursion in the grammar (default: 5)."
    )

    args = parser.parse_args()

    # Generate the regexes
    regex_list = generate_regexes(grammar=REGEX_GRAMMAR, num=args.num, max_depth=args.max_depth)

    # Print them
    for i, regex in enumerate(regex_list, start=1):
        print(f"Regex {i}: {regex}")

if __name__ == "__main__":
    main()
