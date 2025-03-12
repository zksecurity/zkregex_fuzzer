"""
Runner for Circom.
"""

import json
import shutil
import tempfile
from pathlib import Path

from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.runner.base_runner import RegexRunError, Runner
from zkregex_fuzzer.runner.subprocess import (
    BarretenbergSubprocess,
    NoirSubprocess,
    ZkRegexSubprocess,
)

NOIR_MAIN_TEMPLATE = """
fn main(input: [u8; MAX_INPUT_SIZE]) -> pub [Field; MAX_INPUT_SIZE] {
    let matches = regex::regex_match(input);
    let substring = regex::extract_substring::<MAX_INPUT_SIZE, MAX_INPUT_SIZE>(matches.get(0), input);
    let mut result: [Field; MAX_INPUT_SIZE] = [0; MAX_INPUT_SIZE];
    for i in 0..MAX_INPUT_SIZE {
        let r = substring.get_unchecked(i);
        result[i] = Field::from(r);
    }
    print("output: ");
    println(result);
    result
}
"""


class NoirRunner(Runner):
    """
    Runner that uses the Circom compiler.
    """

    def __init__(self, regex: str, kwargs: dict):
        self._path = tempfile.TemporaryDirectory(delete=False).name

        self._run_the_prover = kwargs.get("noir_prove", False)
        self._noir_max_input_size = kwargs.get("max_input_size", 200)
        super().__init__(regex, kwargs)
        self._runner = "Noir"
        self.identifer = ""

    def _construct_working_dir(self) -> str:
        dir_path = Path(self._path)

        # create nargo.toml
        with open(dir_path / "Nargo.toml", "w") as f:
            content = '[package]\nname = "test_regex"\ntype = "bin"\nauthors = [""]\n\n[dependencies]'
            f.write(content)

        src_path = dir_path / "src"
        src_path.mkdir()

        # create src/main.nr
        with open(src_path / "main.nr", "w") as f:
            main_func = "mod regex;\n\n"
            main_func += (
                f"global MAX_INPUT_SIZE: u32 = {self._noir_max_input_size};\n\n"
            )
            main_func += NOIR_MAIN_TEMPLATE
            f.write(main_func)

        return str(src_path)

    def compile(self, regex: str) -> None:
        """
        Compile the regex.
        """
        logger.debug("Compiling regex starts")

        # Setup main directory
        src_path = self._construct_working_dir()

        # Create JSON for the regex for zk-regex
        base_json = {"parts": []}
        # the section start with beginning anchor (^) must be non-public (is_public: false).
        # else, make the section public
        if regex.startswith("^"):
            regex_parts = [
                {"regex_def": regex[0], "is_public": False},
                {"regex_def": regex[1:], "is_public": True},
            ]
        else:
            regex_parts = [{"regex_def": regex, "is_public": True}]

        base_json["parts"] = regex_parts
        regex_json = json.dumps(base_json)

        # Write the JSON to a temporary file
        json_file_path = str(Path(self._path) / "regex.json")
        with open(json_file_path, "wb") as f:
            f.write(regex_json.encode())

        noir_file_path = str(Path(src_path) / "regex.nr")

        # Call zk-regex to generate the noir code
        logger.debug("Generating noir code starts")
        ZkRegexSubprocess.compile_to_noir(json_file_path, noir_file_path)
        logger.debug("Generating noir code ends")

        # Compile the noir code (nargo check)
        logger.debug("Compiling noir code starts")
        NoirSubprocess.compile(self._path)
        logger.debug("Compiling noir code ends")

        if self._run_the_prover:
            BarretenbergSubprocess.export_verification_key(self._path)

        logger.debug("Compiling regex ends")

    def match(self, input: str) -> tuple[bool, str]:
        """
        Match the regex on an input.
        """

        logger.debug("Matching regex starts")
        # Convert input to list of decimal ASCII values and pad input with zeroes
        numeric_input = [ord(c) for c in input] + [0] * (
            self._noir_max_input_size - len(input)
        )

        # Write input to a Prover.toml
        with open(Path(self._path) / "Prover.toml", "w") as f:
            f.write(f"input = {str(numeric_input)}")

        # Skip if input is larger than noir max input size
        if len(numeric_input) > self._noir_max_input_size:
            raise RegexRunError("Input too large for input: {len(numeric_input)}")

        # Generate the witness
        logger.debug("Generating witness starts")
        outputs = NoirSubprocess.witness_gen(self._path)
        is_match = len(outputs) > 0
        logger.debug("Generating witness ends")

        if self._run_the_prover and is_match:
            # prove
            BarretenbergSubprocess.prove(self._path)
            # verify
            if not BarretenbergSubprocess.verify(self._path):
                raise RegexRunError(
                    "Error running with Barretenberg: Proof verification failed"
                )

        # Convert the output to a string
        substr_output_numeric = outputs
        substr_output = "".join([chr(int(c)) for c in substr_output_numeric])
        substr_output = substr_output.strip("\x00")  # remove zero padding

        return is_match, substr_output

    def clean(self):
        # Remove all temporary files
        if Path(self._path).exists():
            shutil.rmtree(self._path)

    def save(self, path) -> str:
        base_path = Path(self._path)
        target_path = Path(path).resolve()

        dst_path = target_path / f"output_{base_path.stem}"
        base_path.replace(dst_path)

        return str(dst_path)
