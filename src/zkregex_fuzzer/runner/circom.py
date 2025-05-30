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
    CircomSubprocess,
    SnarkjsSubprocess,
    ZkRegexSubprocess,
)


class CircomRunner(Runner):
    """
    Runner that uses the Circom compiler.
    """

    def __init__(self, regex: str, oracle: bool, kwargs: dict):
        self._circom_path = ""
        self._graph_path = ""
        self._r1cs_path = ""
        self._wasm_path = ""
        self._zkey_path = ""
        self._vkey_path = ""
        self._input_path = ""
        self._dir_path = tempfile.TemporaryDirectory(delete=False).name

        self._run_the_prover = kwargs.get("circom_prove", False)
        self._ptau_path = kwargs.get("circom_ptau", None)
        self._link_path = kwargs.get("circom_library", [])
        self._circom_max_input_size = kwargs.get("max_input_size", 200)
        self._template_name = "Test"
        super().__init__(regex, oracle, kwargs)
        self._runner = "Circom"
        self.identifer = ""

    def compile(self, regex: str) -> None:
        """
        Compile the regex.
        """
        logger.debug("Compiling regex starts")
        # Create JSON for the regex for zk-regex
        base_json = {"parts": []}

        # the section start with beginning anchor (^) must be non-public (is_public: false).
        # else, make the section public
        if regex.startswith("^"):
            regex_parts = [
                {"Pattern": regex[1:]},
            ]
        else:
            regex_parts = [
                {"Pattern": regex},
            ]

        base_json["parts"] = regex_parts
        regex_json = json.dumps(base_json)

        # Write the JSON to a temporary file
        json_file_path = str(Path(self._dir_path) / "regex.json")
        with open(json_file_path, "wb") as f:
            f.write(regex_json.encode())

        # Call zk-regex to generate the circom code
        logger.debug("Generating circom code starts")
        ZkRegexSubprocess.compile_to_circom(
            json_file_path, self._dir_path, self._template_name
        )
        logger.debug("Generating circom code ends")

        circom_file_path = str(Path(self._dir_path) / "test_regex.circom")
        graph_file_path = str(Path(self._dir_path) / "test_graph.json")

        # Append the circom file to include the main function
        with open(circom_file_path, "a") as f:
            f.write("\n\n")
            f.write(
                "component main { public [inHaystack] } = "
                + f"{self._template_name}Regex({self._circom_max_input_size}, {self._circom_max_input_size - 2});"
            )

        self._circom_path = circom_file_path
        self._graph_path = graph_file_path

        # Compile the circom code to wasm
        logger.debug("Compiling circom code starts")
        self._wasm_path, self._r1cs_path = CircomSubprocess.compile(
            circom_file_path, self._link_path
        )
        logger.debug("Compiling circom code ends")

        # Also setup the proving and verification key if the flag is set
        if self._run_the_prover:
            self._zkey_path = SnarkjsSubprocess.setup_zkey(
                self._r1cs_path, self._ptau_path
            )
            self._vkey_path = SnarkjsSubprocess.export_verification_key(self._zkey_path)
        logger.debug("Compiling regex ends")

    def match(self, input: str) -> tuple[bool, str]:
        """
        Match the regex on an input.
        """
        logger.debug("Matching regex starts")
        # Generate circuit inputs using zk-regex CLI
        input_path = str(Path(self._dir_path) / "test_input.json")
        ZkRegexSubprocess.generate_circuit_inputs(
            graph_path=self._graph_path,
            input_str=input,
            max_haystack_len=self._circom_max_input_size,
            max_match_len=self._circom_max_input_size - 2,
            output_path=input_path,
            proving_framework="circom",
            oracle=self._oracle,
        )

        self._input_path = input_path

        # Generate the witness
        logger.debug("Generating witness starts")
        witness_path = SnarkjsSubprocess.witness_gen(self._wasm_path, input_path)
        logger.debug("Generating witness ends")

        # Also run the proving backend if the flag is set
        if self._run_the_prover:
            # Proving
            proof, public_input = SnarkjsSubprocess.prove(self._zkey_path, witness_path)
            # Verification
            if not SnarkjsSubprocess.verify(self._vkey_path, proof, public_input):
                raise RegexRunError(
                    "Error running with SnarkJS: Proof verification failed"
                )

        # Extract from the witness the result of the match
        result = SnarkjsSubprocess.extract_witness(witness_path)

        substr_length = len(input)
        substr_output_numeric = result[2 : substr_length + 2]
        substr_output = "".join([chr(int(c)) for c in substr_output_numeric])
        substr_output = substr_output.strip("\x00")  # remove zero padding

        # Return the output of the match
        output = int(result[1])
        logger.debug("Matching regex ends")
        return output == 1, substr_output

    def clean(self):
        # Remove all temporary files
        if Path(self._dir_path).exists():
            shutil.rmtree(self._dir_path)

    def save(self, path) -> str:
        base_path = Path(self._dir_path)
        target_path = Path(path).resolve()

        dst_path = target_path / f"output_{base_path.stem}"
        base_path.replace(dst_path)

        return str(dst_path)
