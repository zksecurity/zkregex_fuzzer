"""
Implements the logic for generating a report from the fuzzing results.
"""

import os
from dataclasses import dataclass

from zkregex_fuzzer.harness import HarnessResult, HarnessStatus


@dataclass
class Configuration:
    fuzzer_version: str
    fuzzer: str
    target: str
    oracle: str
    valid_input_generator: str
    invalid_input_generator: str
    regex_num: int
    inputs_num: int
    grammar_max_non_terminals: int
    grammar_custom_grammar: str | None
    seed: str
    num_process: int
    zk_regex_version: str | None
    circom_version: str | None
    snarkjs_version: str | None
    noir_version: str | None
    bb_version: str | None
    logging_file: str | None
    output_path: str
    save_options: list[str]


class Stats:
    """
    Statistics about the fuzzing run.
    """

    def __init__(self, results: list[tuple[str, list[list[str]], list[HarnessResult]]]):
        self.regexes, self.inputs, self.results = zip(*results)

    def get_stats(self):
        return {
            "regexes": len(self.regexes),
            "total_inputs": sum(
                [
                    len(inputs)
                    for oracle_inputs in self.inputs
                    for inputs in oracle_inputs
                ]
            ),
            "avg_inputs": sum(
                [
                    len(inputs)
                    for oracle_inputs in self.inputs
                    for inputs in oracle_inputs
                ]
            )
            / len(self.regexes),
            "min_inputs": min(
                [
                    len(inputs)
                    for oracle_inputs in self.inputs
                    for inputs in oracle_inputs
                ]
            ),
            "max_inputs": max(
                [
                    len(inputs)
                    for oracle_inputs in self.inputs
                    for inputs in oracle_inputs
                ]
            ),
            "total_errors": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status != HarnessStatus.SUCCESS
                ]
            ),
            "total_valid": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.SUCCESS
                ]
            ),
            "total_oracle_violations": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.FAILED
                ]
            ),
            "total_compile_errors": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.COMPILE_ERROR
                ]
            ),
            "total_run_errors": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.RUN_ERROR
                ]
            ),
            "total_invalid_seed": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.INVALID_SEED
                ]
            ),
            "total_input_gen_timeout": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.INPUT_GEN_TIMEOUT
                ]
            ),
            "total_harness_timeout": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.HARNESS_TIMEOUT
                ]
            ),
            "total_substr_mismatch": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.SUBSTR_MISMATCH
                ]
            ),
            "total_regex_timeout": sum(
                [
                    1
                    for oracle_results in self.results
                    for result in oracle_results
                    if result.status == HarnessStatus.REGEX_TIMEOUT
                ]
            ),
        }


@dataclass
class FuzzingReportData:
    pass


def get_fuzzing_configuration_string(configuration: Configuration):
    return f"""
Fuzzer: {configuration.fuzzer}
Target: {configuration.target}
Oracle: {configuration.oracle}
Valid input generator: {configuration.valid_input_generator}
Invalid input generator: {configuration.valid_input_generator}
Regex num: {configuration.regex_num}
Inputs num: {configuration.inputs_num}
Grammar max non-terminals: {configuration.grammar_max_non_terminals}
Grammar custom grammar: {configuration.grammar_custom_grammar}
Seed: {configuration.seed}
Num process: {configuration.num_process}
zk-regex: {configuration.zk_regex_version}
Circom: {configuration.circom_version}
SnarkJS: {configuration.snarkjs_version}
Noir: {configuration.noir_version}
Barretenberg: {configuration.bb_version}
Logging file: {configuration.logging_file}
Output path: {configuration.output_path}
Save options: {configuration.save_options}
"""


def print_fuzzing_configuration(configuration: Configuration):
    """
    Print the fuzzing configuration in a nicely formatted box.

    Args:
        args: The command-line arguments from argparse
    """
    banner = r"""
 ####### #    # ######                              
      #  #   #  #     # ######  ####  ###### #    # 
     #   #  #   #     # #      #    # #       #  #  
    #    ###    ######  #####  #      #####    ##   
   #     #  #   #   #   #      #  ### #        ##   
  #      #   #  #    #  #      #    # #       #  #  
 ####### #    # #     # ######  ####  ###### #    # 
                                                    
 #######                                            
 #       #    # ###### ###### ###### #####          
 #       #    #     #      #  #      #    #         
 #####   #    #    #      #   #####  #    #         
 #       #    #   #      #    #      #####          
 #       #    #  #      #     #      #   #          
 #        ####  ###### ###### ###### #    #         
"""
    print(banner)

    width = 85

    # Top border
    print("\n" + "╔" + "═" * (width - 2) + "╗")

    # Title with side borders
    title = f"🚀 FUZZING WITH {configuration.fuzzer.upper()} FUZZER"
    padding = (width - 2 - len(title)) // 2
    print("║" + " " * padding + title + " " * (width - 3 - padding - len(title)) + "║")

    # Separator line
    print("╠" + "═" * (width - 2) + "╣")

    # Target specific versions
    target_specific_items = []
    if configuration.zk_regex_version:
        target_specific_items.append(f"  - {configuration.zk_regex_version}")
    if configuration.target == "circom":
        target_specific_items.append(f"  - {configuration.circom_version}")
        if configuration.snarkjs_version:
            target_specific_items.append(f"  - {configuration.snarkjs_version}")
    if configuration.target == "noir":
        target_specific_items.append(f"  - {configuration.noir_version}")
        if configuration.bb_version:
            target_specific_items.append(f"  - {configuration.bb_version}")

    # Configuration items with side borders
    config_items = (
        [
            f"🔧 Fuzzer version: {configuration.fuzzer_version}",
            f"📋 Target: {configuration.target}",
        ]
        + target_specific_items
        + [
            f"🎯 Oracle: {configuration.oracle}",
            f"🔄 Valid input generator: {configuration.valid_input_generator}",
            f"🔄 Invalid input generator: {configuration.invalid_input_generator}",
            f"🔢 Regex num: {configuration.regex_num}",
            f"📥 Inputs num: {configuration.inputs_num}",
            f"🔍 Max non-terminals: {configuration.grammar_max_non_terminals}",
            f"🔍 Custom grammar: {configuration.grammar_custom_grammar}",
            f"🌱 Seed: {configuration.seed}",
            f"🔄 Num process: {configuration.num_process}",
            f"🔍 Logging file: {os.path.relpath(configuration.logging_file, os.getcwd()) if configuration.logging_file else 'None'}",
            f"🔍 Save options: {', '.join(configuration.save_options)}",
            f"🔍 Output path: {os.path.relpath(configuration.output_path, os.getcwd())}",
        ]
    )

    for item in config_items:
        # check if first character of item is a space and not an emoji
        extra_space = 1 if item[0] == " " else 0
        print("║ " + item + " " * (width - 4 - len(item)) + extra_space * " " + "║")

    # Bottom border
    print("╚" + "═" * (width - 2) + "╝")


def print_stats(stats: Stats):
    """
    Print statistics about the fuzzing run in a visually appealing format.

    Args:
        stats: The Stats object containing fuzzing results
    """
    # Get the statistics dictionary
    stats_dict = stats.get_stats()

    # Calculate additional stats for display
    error_rate = (
        stats_dict["total_errors"]
        / (stats_dict["total_errors"] + stats_dict["total_valid"])
        * 100
        if stats_dict["regexes"] > 0
        else 0
    )
    success_rate = 100 - error_rate

    # Terminal width
    term_width = 80

    # Top border with title
    print("\n" + "╔" + "═" * (term_width - 2) + "╗")
    title = "📊 FUZZING CAMPAIGN RESULTS 📊"
    padding = (term_width - 2 - len(title) + 2) // 2
    print(
        "║"
        + " " * padding
        + title
        + " " * (term_width - 4 - padding - len(title))
        + "║"
    )
    print("╠" + "═" * (term_width - 2) + "╣")

    # Coverage section
    print("║ 🔍 COVERAGE METRICS" + " " * (term_width - 22) + "║")
    print("╟" + "─" * (term_width - 2) + "╢")
    print(
        f"║  • Regex patterns tested: {stats_dict['regexes']:,}"
        + " " * (term_width - 29 - len(f"{stats_dict['regexes']:,}"))
        + "║"
    )
    print(
        f"║  • Total test inputs: {stats_dict['total_inputs']:,}"
        + " " * (term_width - 25 - len(f"{stats_dict['total_inputs']:,}"))
        + "║"
    )
    print(
        f"║  • Avg inputs per regex: {stats_dict['avg_inputs']:.2f}"
        + " " * (term_width - 28 - len(f"{stats_dict['avg_inputs']:.2f}"))
        + "║"
    )
    print(
        f"║  • Min inputs per regex: {stats_dict['min_inputs']:,}"
        + " " * (term_width - 28 - len(f"{stats_dict['min_inputs']:,}"))
        + "║"
    )
    print(
        f"║  • Max inputs per regex: {stats_dict['max_inputs']:,}"
        + " " * (term_width - 28 - len(f"{stats_dict['max_inputs']:,}"))
        + "║"
    )

    # Results section
    print("╟" + "─" * (term_width - 2) + "╢")
    print("║ 🧪 TEST RESULTS" + " " * (term_width - 18) + "║")
    print("╟" + "─" * (term_width - 2) + "╢")

    print(
        "║ We skip tests without inputs and tests when there is a compile error         ║"
    )
    print(
        f"║  • Total tests: {stats_dict['total_valid'] + stats_dict['total_errors']:,}"
        + " "
        * (
            term_width
            - 19
            - len(f"{stats_dict['total_valid'] + stats_dict['total_errors']:,}")
        )
        + "║"
    )
    print(
        f"║  • Successful tests: {stats_dict['total_valid']:,}"
        + " " * (term_width - 24 - len(f"{stats_dict['total_valid']:,}"))
        + "║"
    )
    print(
        f"║  • Failed tests: {stats_dict['total_errors']:,}"
        + " " * (term_width - 20 - len(f"{stats_dict['total_errors']:,}"))
        + "║"
    )

    # Create a visual bar chart for success rate
    bar_width = term_width - 30  # Ensure bar fits within constraints
    filled_chars = int(bar_width * success_rate / 100)
    empty_chars = bar_width - filled_chars

    # Use plain ASCII for the progress bar
    success_bar = "#" * filled_chars + "-" * empty_chars

    print(
        f"║  • Success rate: {success_rate:.2f}% [{success_bar}]"
        + " "
        * max(
            0,
            term_width
            - len(f"║  • Success rate: {success_rate:.2f}% [{success_bar}]")
            - 1,
        )
        + "║"
    )

    # Error breakdown
    if stats_dict["total_errors"] > 0:
        print("╟" + "─" * (term_width - 2) + "╢")
        print("║ ❌ ERROR BREAKDOWN" + " " * (term_width - 21) + "║")
        print("╟" + "─" * (term_width - 2) + "╢")

        error_types = [
            ("Oracle violations", stats_dict["total_oracle_violations"]),
            ("Compilation errors", stats_dict["total_compile_errors"]),
            ("Runtime errors", stats_dict["total_run_errors"]),
            ("Substr mismatch", stats_dict["total_substr_mismatch"]),
            ("Invalid seed errors", stats_dict["total_invalid_seed"]),
            ("Input gen timeout", stats_dict["total_input_gen_timeout"]),
            ("Harness timeout", stats_dict["total_harness_timeout"]),
            ("Regex timeout", stats_dict["total_regex_timeout"]),
        ]

        for error_type, count in error_types:
            if count > 0:
                percent = count / stats_dict["total_errors"] * 100
                line = f"║  • {error_type}: {count:,} ({percent:.1f}%)"
                print(line + " " * (term_width - len(line) - 1) + "║")

    # Summary section
    print("╠" + "═" * (term_width - 2) + "╣")
    if stats_dict["total_errors"] > 0:
        summary = f"💥 Found {stats_dict['total_errors']:,} potential issues by using {stats_dict['regexes']:,} regexes!"
    else:
        summary = "✅ All tests passed successfully! No issues detected."

    # Center the summary text
    padding = (term_width - 2 - len(summary)) // 2
    print(
        "║"
        + " " * padding
        + summary
        + " " * (term_width - 3 - padding - len(summary))
        + "║"
    )

    # Bottom border
    print("╚" + "═" * (term_width - 2) + "╝\n")
