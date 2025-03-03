"""
Runner for Circom.
"""

import json, tempfile, subprocess, shutil
from pathlib import Path
from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.runner.base_runner import Runner, RegexCompileError, RegexRunError
from zkregex_fuzzer.runner.subprocess import ZkRegexSubprocess, CircomSubprocess, SnarkjsSubprocess

class CircomRunner(Runner):
    """
    Runner that uses the Circom compiler.
    """

    def __init__(self, regex: str, kwargs: dict):
        self._circom_path = ""
        self._input_path = ""
        self._wasm_path = ""
        self._r1cs_path = ""
        self._zkey_path = ""
        self._vkey_path = ""

        self._run_the_prover = kwargs.get("circom_prove", False)
        self._ptau_path = kwargs.get("circom_ptau", None)
        self._link_path = kwargs.get("circom_library", [])
        self._circom_max_input_size = kwargs.get("max_input_size", 200)
        self._template_name = "TestRegex"
        super().__init__(regex, kwargs)
        self._runner = "Circom"
        self.identifer = ""

    def compile(self, regex: str) -> None:
        """
        Compile the regex.
        """
        logger.debug(f"Compiling regex starts")
        # Create JSON for the regex for zk-regex 
        base_json = {
            "parts": []
        }
        # TODO: handle the following if is_public is set to True:
        # the section containing this ^ must be non-public (is_public: false).
        regex_parts = {"regex_def": regex, "is_public": False}
        base_json["parts"].append(regex_parts)
        regex_json = json.dumps(base_json)

        # Write the JSON to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            tmp_file.write(regex_json.encode())
            json_file_path = tmp_file.name

        circom_file_path = tempfile.NamedTemporaryFile(suffix=".circom", delete=False).name

        # Call zk-regex to generate the circom code
        logger.debug(f"Generating circom code starts")
        ZkRegexSubprocess.compile_to_circom(json_file_path, circom_file_path, self._template_name)
        logger.debug(f"Generating circom code ends")

        # Append the circom file to include the main function
        with open(circom_file_path, 'a') as f:
            f.write("\n\n")
            f.write("component main {public [msg]} = " + f"{self._template_name}({self._circom_max_input_size});")

        self._circom_path = circom_file_path

        # Compile the circom code to wasm
        logger.debug(f"Compiling circom code starts")
        self._wasm_path, self._r1cs_path = CircomSubprocess.compile(circom_file_path, self._link_path)
        logger.debug(f"Compiling circom code ends")

        # Also setup the proving and verification key if the flag is set
        if self._run_the_prover:
            self._zkey_path = SnarkjsSubprocess.setup_zkey(self._r1cs_path, self._ptau_path)
            self._vkey_path = SnarkjsSubprocess.export_verification_key(self._zkey_path)
        logger.debug(f"Compiling regex ends")

    def match(self, input: str) -> tuple[bool, str]:
        """
        Match the regex on an input.
        """
        logger.debug(f"Matching regex starts")
        # Convert input to list of decimal ASCII values and pad input with zeroes
        numeric_input = [ord(c) for c in input] + [0] * (self._circom_max_input_size - len(input))
        
        # Write input to a temporary JSON file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            tmp_file.write(json.dumps({"msg": numeric_input}).encode())
            input_path = tmp_file.name
        
        self._input_path = input_path

        # Skip if input is larger than circuit max input size
        if len(numeric_input) > self._circom_max_input_size:
            raise RegexRunError(f"Input too large for input: {len(numeric_input)}")
        
        # Generate the witness
        logger.debug(f"Generating witness starts")
        witness_path = SnarkjsSubprocess.witness_gen(self._wasm_path, input_path)
        logger.debug(f"Generating witness ends")
        
        # Also run the proving backend if the flag is set
        if self._run_the_prover:
            # Proving
            proof, public_input = SnarkjsSubprocess.prove(self._zkey_path, witness_path)
            # Verification
            if not SnarkjsSubprocess.verify(self._vkey_path, proof, public_input):
                raise RegexRunError(f"Error running with SnarkJS: Proof verification failed")

        # Extract from the witness the result of the match
        result = SnarkjsSubprocess.extract_witness(witness_path)

        # TODO: get and convert substr output to its string representation
        
        # Return the output of the match
        output = int(result[1])
        logger.debug(f"Matching regex ends")
        return output == 1, ""
    
    def clean(self):
        # Remove all temporary files
        if self._wasm_path:
            shutil.rmtree(Path(self._wasm_path).parent)
        if self._circom_path: Path(self._circom_path).unlink(True)
        if self._input_path: Path(self._input_path).unlink(True)
        if self._r1cs_path: Path(self._r1cs_path).unlink(True)
        if self._zkey_path: Path(self._zkey_path).unlink(True)
        if self._vkey_path: Path(self._vkey_path).unlink(True)
    
    def save(self, path) -> str:
        circom_path = Path(self._circom_path)
        input_path = Path(self._input_path)
        r1cs_path = Path(self._r1cs_path)
        wasm_path = Path(self._wasm_path)
        target_path = Path(path).resolve() / f"output_{r1cs_path.stem}"
        target_path.mkdir()

        if self._circom_path: circom_path.replace(target_path / circom_path.name)
        if self._input_path: input_path.replace(target_path / input_path.name)
        if self._r1cs_path: r1cs_path.replace(target_path / r1cs_path.name)
        if self._wasm_path: wasm_path.replace(target_path / wasm_path.name)
        
        if self._run_the_prover:
            zkey_path = Path(self._zkey_path)
            vkey_path = Path(self._vkey_path)

            zkey_path.replace(target_path / zkey_path.name)
            vkey_path.replace(target_path / vkey_path.name)

        return str(target_path)