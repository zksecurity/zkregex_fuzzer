"""
Harness for running regexes.

TODO:
  - Atm the oracle is just a boolean value for valid and invalid inputs.
    In the future, we could pass invalid regexes and check if the secondary runner fails to compile.
"""

import json
import random
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Type, Union

from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.runner import RegexCompileError, RegexRunError, Runner
from zkregex_fuzzer.utils import get_random_filename


class HarnessStatus(Enum):
    SUCCESS = 0  # Did not find a bug
    INVALID_SEED = (
        1  # The seed is invalid (i.e., the primary runner rejects it or fails)
    )
    COMPILE_ERROR = 2  # The secondary runner failed to compile
    RUN_ERROR = 3  # The secondary runner failed to run
    FAILED = 4  # Found a bug


@dataclass
class HarnessResult:
    regex: str
    inp_num: int
    oracle: bool
    # List of inputs that failed in the secondary runner.
    failed_inputs: List[str]
    # Status (an enum for the result of the test)
    status: HarnessStatus
    # Error message (if any)
    error_message: str = ""


def _return_harness_result(
    result: HarnessResult,
    status_to_save: list,
    output_path: str,
    runner: Union[Runner, None],
    kwargs: dict,
):
    if result.status.name in status_to_save:
        metadata = {
            "config": kwargs,
            "regex": result.regex,
            "inputs": result.failed_inputs,
            "status": result.status.name,
        }

        if runner:
            dir_path = runner.save(output_path)
        else:
            dir_path = Path(output_path) / f"output_{get_random_filename()}"
            dir_path.mkdir()

        metadata_json = json.dumps(metadata)
        metadata_path = Path(dir_path) / "metadata.json"
        with open(metadata_path.absolute(), "w") as f:
            f.write(metadata_json)

    if runner:
        runner.clean()

    return result


def harness(
    regex: str,
    primary_runner_cls: Type[Runner],
    secondary_runner_cls: Type[Runner],
    inputs: List[str],
    oracle: bool,
    kwargs: dict,
) -> HarnessResult:
    """
    Harness for running regexes.

    regex: The regex to use to test.
    primary_runner_cls: The class of the primary runner (typically the python re module).
    secondary_runner_cls: The class of the secondary runner (either circom or noir runners).
    inputs: The inputs to use to test the regex.
    oracle: The oracle to use to test the regex. True if the inputs are valid regexes. False if the inputs are invalid regexes.
    kwargs: The arguments to pass to the secondary runner.

    Returns:
        A HarnessResult object.
    """
    regex = regex
    inp_num = len(inputs)
    output_path = kwargs.get("save_output", "")
    status_to_save = kwargs.get("save", None) or []

    try:
        primary_runner = primary_runner_cls(regex, {})
    except RegexCompileError as e:
        return _return_harness_result(
            HarnessResult(
                regex, inp_num, oracle, [], HarnessStatus.INVALID_SEED, str(e)
            ),
            status_to_save,
            output_path,
            None,
            kwargs,
        )

    try:
        secondary_runner = secondary_runner_cls(regex, kwargs)
    except RegexCompileError as e:
        return _return_harness_result(
            HarnessResult(
                regex, inp_num, oracle, [], HarnessStatus.COMPILE_ERROR, str(e)
            ),
            status_to_save,
            output_path,
            None,
            kwargs,
        )

    failed_inputs = []

    for input in inputs:
        primary_runner_str = None
        try:
            primary_runner_status, primary_runner_str = primary_runner.match(input)
            if primary_runner_status != oracle:
                return _return_harness_result(
                    HarnessResult(
                        regex, inp_num, oracle, [], HarnessStatus.INVALID_SEED
                    ),
                    status_to_save,
                    output_path,
                    None,
                    kwargs,
                )
        except RegexRunError as e:
            return _return_harness_result(
                HarnessResult(
                    regex, inp_num, oracle, [], HarnessStatus.INVALID_SEED, str(e)
                ),
                status_to_save,
                output_path,
                None,
                kwargs,
            )
        try:
            secondary_runner_status, secondary_runner_str = secondary_runner.match(
                input
            )
            if secondary_runner_status != oracle:
                failed_inputs.append(input)

            # TODO: support for substr matching
            # elif secondary_runner_status == oracle and primary_runner_str != secondary_runner_str:
            # failed_inputs.append(input)
        except RegexRunError as e:
            return _return_harness_result(
                HarnessResult(
                    regex, inp_num, oracle, [input], HarnessStatus.RUN_ERROR, str(e)
                ),
                status_to_save,
                output_path,
                secondary_runner,
                kwargs,
            )

    if len(failed_inputs) > 0:
        return _return_harness_result(
            HarnessResult(regex, inp_num, oracle, failed_inputs, HarnessStatus.FAILED),
            status_to_save,
            output_path,
            secondary_runner,
            kwargs,
        )

    return _return_harness_result(
        HarnessResult(regex, inp_num, oracle, inputs, HarnessStatus.SUCCESS),
        status_to_save,
        output_path,
        secondary_runner,
        kwargs,
    )
