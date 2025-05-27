"""
Runner for Noir.
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
fn main(
    in_haystack: [u8; MAX_HAYSTACK_LEN],
    match_start: u32,
    match_length: u32,
    current_states: [Field; MAX_MATCH_LEN],
    next_states: [Field; MAX_MATCH_LEN],
    capture_group_1_id: [Field; MAX_MATCH_LEN],
    capture_group_1_start: [Field; MAX_MATCH_LEN],
    capture_group_start_indices: [Field; NUM_CAPTURE_GROUPS],
) -> pub [u8; CAPTURE_1_MAX_LENGTH] {
    let capture_1 = test_regex::regex_match::<MAX_HAYSTACK_LEN, MAX_MATCH_LEN>(
        in_haystack,
        match_start,
        match_length,
        current_states,
        next_states,
        capture_group_1_id,
        capture_group_1_start,
        capture_group_start_indices,
    );
    print("output: ");
    println(capture_1);
    capture_1.storage()
}
"""


class NoirRunner(Runner):
    """
    Runner that uses the Circom compiler.
    """

    def __init__(self, regex: str, oracle: bool, kwargs: dict):
        self._path = tempfile.TemporaryDirectory(delete=False).name

        self._run_the_prover = kwargs.get("noir_prove", False)
        self._noir_max_haystack_len = kwargs.get("max_haystack_len", 200)
        self._noir_max_match_len = kwargs.get("max_match_len", 200)
        self._noir_num_capture_groups = kwargs.get("num_capture_groups", 1)
        self._noir_capture_1_max_length = kwargs.get("capture_1_max_length", 200)
        self._template_name = "Test"
        super().__init__(regex, oracle, kwargs)
        self._runner = "Noir"
        self.identifer = ""

    def _construct_working_dir(self) -> str:
        dir_path = Path(self._path)

        # create nargo.toml
        with open(dir_path / "Nargo.toml", "w") as f:
            content = '[package]\nname = "fuzzer_regex"\ntype = "bin"\nauthors = [""]\n\n[dependencies]\nzkregex = { tag = "2.2.0", git = "https://github.com/zkemail/zk-regex", directory = "noir" }'
            f.write(content)

        src_path = dir_path / "src"
        src_path.mkdir()

        # create src/main.nr
        with open(src_path / "main.nr", "w") as f:
            main_func = "mod test_regex;\n\n"
            main_func += (
                f"global MAX_HAYSTACK_LEN: u32 = {self._noir_max_haystack_len};\n"
            )
            main_func += f"global MAX_MATCH_LEN: u32 = {self._noir_max_match_len};\n"
            main_func += (
                f"global NUM_CAPTURE_GROUPS: u32 = {self._noir_num_capture_groups};\n"
            )
            main_func += f"global CAPTURE_1_MAX_LENGTH: u32 = {self._noir_capture_1_max_length};\n\n"
            main_func += NOIR_MAIN_TEMPLATE
            f.write(main_func)

        return str(src_path)

    def _convert_json_to_toml(self, json_input_path: str):
        """
        Convert JSON circuit inputs to TOML format for Noir.
        """
        import json
        import toml

        # Read the JSON input
        with open(json_input_path, "r") as f:
            json_data = json.load(f)

        # Convert to TOML format
        toml_data = {
            "in_haystack": json_data["in_haystack"],
            "match_start": json_data["match_start"],
            "match_length": json_data["match_length"],
            "current_states": json_data["curr_states"],
            "next_states": json_data["next_states"],
            "capture_group_start_indices": json_data["capture_group_start_indices"],
        }

        # Handle capture groups dynamically
        for i, capture_group_ids in enumerate(json_data["capture_group_ids"]):
            toml_data[f"capture_group_{i+1}_id"] = capture_group_ids

        for i, capture_group_starts in enumerate(json_data["capture_group_starts"]):
            toml_data[f"capture_group_{i+1}_start"] = capture_group_starts

        # Create Prover.toml file path in the same directory
        toml_path = str(Path(json_input_path).parent / "Prover.toml")

        # Write TOML file
        with open(toml_path, "w") as f:
            toml.dump(toml_data, f)

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
                {"PublicPattern": [regex[1:], self._noir_capture_1_max_length]}
            ]
        else:
            regex_parts = [{"PublicPattern": [regex, self._noir_capture_1_max_length]}]

        base_json["parts"] = regex_parts
        regex_json = json.dumps(base_json)

        # Write the JSON to a temporary file
        json_file_path = str(Path(self._path) / "regex.json")
        with open(json_file_path, "wb") as f:
            f.write(regex_json.encode())

        # Call zk-regex to generate the noir code
        logger.debug("Generating noir code starts")
        ZkRegexSubprocess.compile_to_noir(json_file_path, src_path, self._template_name)
        logger.debug("Generating noir code ends")

        graph_file_path = str(Path(src_path) / "test_graph.json")
        self._graph_path = graph_file_path

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
        # Generate circuit inputs using zk-regex CLI
        input_path = str(Path(self._path) / "test_input.json")
        status =ZkRegexSubprocess.generate_circuit_inputs(
            graph_path=self._graph_path,
            input_str=input,
            max_haystack_len=self._noir_max_haystack_len,
            max_match_len=self._noir_max_match_len,
            output_path=input_path,
            proving_framework="noir",
            oracle=self._oracle,
        )
        if status and self._oracle is False:
            return False, ""
        self._convert_json_to_toml(input_path)

        # Generate the witness
        logger.debug("Generating witness starts")
        outputs = NoirSubprocess.witness_gen(self._path)
        is_match = len(outputs) > 0
        logger.debug("Generating witness ends")

        # Debug prints
        logger.debug(f"Raw outputs from witness_gen: {outputs}")
        logger.debug(f"is_match (len(outputs) > 0): {is_match}")

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

        logger.debug(f"substr_output_numeric: {substr_output_numeric}")
        logger.debug(f"substr_output: '{substr_output}'")
        logger.debug(
            f"Final result: is_match={is_match}, substr_output='{substr_output}'"
        )

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
