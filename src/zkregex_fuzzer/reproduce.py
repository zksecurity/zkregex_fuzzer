"""
Reproduce bugs found by the fuzzer.
"""

import glob
import json
from pathlib import Path

from zkregex_fuzzer.configs import TARGETS
from zkregex_fuzzer.harness import HarnessStatus
from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.runner import RegexCompileError, RegexRunError
from zkregex_fuzzer.utils import pretty_regex


def reproduce(path_list: list[str]):
    for pattern in path_list:
        expanded_path = glob.glob(pattern)
        if not expanded_path:
            logger.info(f"Path {pattern} is not exist, skipping.")
            continue

        for path in expanded_path:
            directory = Path(path)
            if not directory.exists():
                continue

            if not (directory / "metadata.json").exists():
                logger.info(f"metadata.json is not exist in {directory}, skipping.")
                continue

            simulate_harness(directory)


def simulate_harness(directory: Path):
    with open(str(directory / "metadata.json"), "r") as f:
        metadata = json.loads(f.read())

    regex = metadata["regex"]
    inputs = metadata["inputs"]
    expected_status = metadata["status"]
    kwargs = metadata["config"]

    target_runner = TARGETS[metadata["config"]["target"]]
    oracle = True if metadata["config"]["oracle"] == "valid" else False

    # Create a nicely formatted heading
    print("\n" + "═" * 80)
    print("🔍 REPRODUCING BUG REPORT")
    print("═" * 80)

    # Display regex with nice formatting
    print("📋 Regular Expression:")
    print(f"   {pretty_regex(regex)}")

    # Display metadata in a structured way
    print("\n📁 Metadata:")
    print(f"   • Directory: {directory}")
    print(f"   • Target: {kwargs['target']}")
    print(f"   • Oracle: {kwargs['oracle']}")
    print(f"   • Expected status: {expected_status}")

    # Format the inputs more nicely
    print("\n📥 Test Inputs:")
    if not inputs:
        print("   • No inputs provided")
    else:
        for i, inp in enumerate(inputs, 1):
            # Truncate very long inputs with ellipsis
            display_input = inp
            if len(inp) > 70:
                display_input = inp[:67] + "..."

            # Escape newlines and tabs for better display
            display_input = (
                display_input.replace("\n", "\\n")
                .replace("\t", "\\t")
                .replace("\r", "\\r")
            )
            print(f'   {i}. "{display_input}"')

    print("\n" + "─" * 80)
    print("🔬 REPRODUCTION RESULTS")
    print("─" * 80)

    try:
        runner = target_runner(regex, kwargs)
    except RegexCompileError as e:
        if expected_status == HarnessStatus.COMPILE_ERROR.name:
            print("✅ Successfully reproduced COMPILE_ERROR!")
            print("─" * 80)
            print(f"🛑 Error details:\n{e}")
        else:
            print(f"❌ Unexpected COMPILE_ERROR status (expected {expected_status})")
            print(f"🛑 Error details:\n{e}")

        print("═" * 80 + "\n")
        return

    failed_inputs = []
    for input in inputs:
        try:
            runner_status, runner_str = runner.match(input)
            if runner_status != oracle:
                failed_inputs.append(input)

        except RegexRunError as e:
            if expected_status == HarnessStatus.RUN_ERROR.name:
                print("✅ Successfully reproduced RUN_ERROR!")
                print("─" * 80)
                print(f"🛑 Error details:\n{e}")
            else:
                print(f"❌ Unexpected RUN_ERROR status (expected {expected_status})")
                print(f"🛑 Error details:\n{e}")

    if len(failed_inputs) > 0:
        if expected_status == HarnessStatus.FAILED.name:
            print("✅ Successfully reproduced FAILED status!")
            print(f"   {len(failed_inputs)}/{len(inputs)} inputs failed validation")

            # Show the failed inputs
            print("\n⚠️ Failed inputs:")
            for i, inp in enumerate(failed_inputs, 1):
                display_input = inp
                if len(inp) > 70:
                    display_input = inp[:67] + "..."
                display_input = (
                    display_input.replace("\n", "\\n")
                    .replace("\t", "\\t")
                    .replace("\r", "\\r")
                )
                print(f'   {i}. "{display_input}"')
        else:
            print(f"❌ Unexpected FAILED status (expected {expected_status})")
            print(f"   {len(failed_inputs)}/{len(inputs)} inputs failed validation")
    else:
        if expected_status == HarnessStatus.SUCCESS.name:
            print("✅ Successfully reproduced SUCCESS status!")
            print("   All inputs passed validation")
        else:
            print(f"❌ Unexpected SUCCESS status (expected {expected_status})")
            print("   All inputs passed validation")

    runner.clean()
    print("═" * 80 + "\n")
