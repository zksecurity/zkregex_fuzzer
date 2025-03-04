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

    print(f"Reproducing regex: {pretty_regex(regex)}")
    print("-" * 80)
    print(f"Directory path: {directory}")
    print(f"Inputs: {inputs}")
    print(f"Expected result: {expected_status}")
    print("-" * 80)

    try:
        runner = target_runner(regex, kwargs)
    except RegexCompileError as e:
        if expected_status == HarnessStatus.COMPILE_ERROR.name:
            print("Reproduce completed successfully!")
            print("-" * 80)
            print(e)
        else:
            print(f"Unexpected COMPILE_ERROR reproduce status: {e}")

        print("=" * 80)
        return

    failed_inputs = []
    for input in inputs:
        try:
            runner_status, runner_str = runner.match(input)
            if runner_status != oracle:
                failed_inputs.append(input)

        except RegexRunError as e:
            if expected_status == HarnessStatus.RUN_ERROR.name:
                print("Reproduce completed successfully!")
                print("-" * 80)
                print(e)
            else:
                print(f"Unexpected RUN_ERROR reproduce status: {e}")

    if len(failed_inputs) > 0:
        if expected_status == HarnessStatus.FAILED.name:
            print("Reproduce completed successfully!")
        else:
            print(f"Unexpected FAILED reproduce status: {failed_inputs}")
    else:
        if expected_status == HarnessStatus.SUCCESS.name:
            print("Reproduce completed successfully!")
        else:
            print(f"Unexpected SUCCESS reproduce status: {inputs}")

    runner.clean()
    print("=" * 80)
