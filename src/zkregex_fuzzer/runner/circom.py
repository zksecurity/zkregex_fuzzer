"""
Runner for Circom.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.runner.base_runner import RegexCompileError, RegexRunError, Runner


class ZkRegexSubprocess:
    @classmethod
    def get_installed_version(cls) -> str:
        """
        Get the installed version of zk-regex.
        """
        if shutil.which("zk-regex"):
            cmd = ["zk-regex", "--version"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.strip()
        else:
            raise ValueError("zk-regex is not installed")

    @classmethod
    def compile(
        cls,
        json_file_path: str,
        output_file_path: str,
        template_name: str = "TestRegex",
        substr=True,
    ):
        """
        Compile a regex using zk-regex.
        """
        cmd = [
            "zk-regex",
            "decomposed",
            "-d",
            json_file_path,
            "-c",
            output_file_path,
            "-t",
            template_name,
            "-g",
            "true" if substr else "false",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexCompileError(f"Error compiling with zk-regex: {result.stderr}")


class CircomSubprocess:
    @classmethod
    def get_installed_version(cls) -> str:
        """
        Get the installed version of Circom.
        """
        if shutil.which("circom"):
            cmd = ["circom", "--version"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.strip()
        else:
            raise ValueError("Circom is not installed")

    @classmethod
    def compile(cls, circom_file_path: str, link_path: list[str]) -> tuple[str, str]:
        """
        Compile a circom file to r1cs and wasm.
        """

        base_name = Path(circom_file_path).stem
        base_dir = Path(circom_file_path).parent

        cmd = ["circom", circom_file_path, "--wasm", "--r1cs", "-o", str(base_dir)]
        for path in link_path:
            cmd.append("-l")
            cmd.append(path)

        logger.debug(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexCompileError(f"Error compiling with Circom: {result.stderr}")

        r1cs_file_path = base_dir / f"{base_name}.r1cs"
        wasm_file_path = base_dir / f"{base_name}_js/{base_name}.wasm"
        return str(wasm_file_path), str(r1cs_file_path)


class SnarkjsSubprocess:
    @classmethod
    def get_installed_version(cls) -> str:
        """
        Get the installed version of SnarkJS.
        """
        if shutil.which("snarkjs"):
            cmd = ["snarkjs", "--help"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.split("\n")[0]
        else:
            raise ValueError("SnarkJS is not installed")

    @classmethod
    def setup_zkey(cls, circuit_path: str, ptau_path: str) -> str:
        """
        Setup the circuit with the powers of tau.
        """

        base_name = Path(circuit_path).stem
        output_path = str(Path(circuit_path).parent / f"{base_name}.zkey")

        cmd = ["snarkjs", "groth16", "setup", circuit_path, ptau_path, output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexRunError(f"Error running with SnarkJS: {result.stderr}")

        return str(output_path)

    @classmethod
    def export_verification_key(cls, zkey_path: str) -> str:
        """
        Export the verification key from the zkey.
        """

        base_name = Path(zkey_path).stem
        output_path = str(Path(zkey_path).parent / f"{base_name}.vkey.json")

        cmd = ["snarkjs", "zkey", "export", "verificationkey", zkey_path, output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexRunError(f"Error running with SnarkJS: {result.stdout}")

        return str(output_path)

    @classmethod
    def witness_gen(cls, wasm_file_path: str, input_path: str) -> str:
        """
        Generate a witness for the wasm file.
        """

        base_name = Path(wasm_file_path).stem
        output_path = str(Path(input_path).parent / f"{base_name}.wtns")

        cmd = ["snarkjs", "wtns", "calculate", wasm_file_path, input_path, output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        logger.debug(" ".join(cmd))
        if result.returncode != 0:
            raise RegexRunError(f"Error running with SnarkJS: {result.stdout}")

        return str(output_path)

    @classmethod
    def prove(cls, zkey_path: str, witness_path: str) -> tuple[str, str]:
        """
        geenrate proof from the witness with the zkey.
        """

        base_name = Path(zkey_path).stem
        proof_path = str(Path(witness_path).parent / f"{base_name}.proof.json")
        public_input_path = str(Path(witness_path).parent / f"{base_name}.public.json")

        cmd = [
            "snarkjs",
            "groth16",
            "prove",
            zkey_path,
            witness_path,
            proof_path,
            public_input_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexRunError(f"Error running with SnarkJS: {result.stdout}")

        return proof_path, public_input_path

    @classmethod
    def verify(cls, vkey_path: str, proof_path: str, public_input_path: str) -> bool:
        """
        Verify the proof with the verification key.
        """

        cmd = [
            "snarkjs",
            "groth16",
            "verify",
            vkey_path,
            public_input_path,
            proof_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexRunError(f"Error running with SnarkJS: {result.stdout}")

        return "OK" in result.stdout

    @classmethod
    def extract_witness(cls, witness_path: str) -> dict:
        """
        Extract the witness from the witness file.
        """

        base_name = Path(witness_path).stem
        output_path = str(Path(witness_path).parent / f"{base_name}.json")

        cmd = [
            "snarkjs",
            "wtns",
            "export",
            "json",
            witness_path,
            output_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        logger.debug(" ".join(cmd))
        if result.returncode != 0:
            logger.debug(result.stdout)
            raise RegexRunError(f"Error running with SnarkJS: {result.stdout}")

        json_result = json.loads(open(output_path, "r").read())
        Path(output_path).unlink()

        return json_result


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
        self._circom_max_input_size = kwargs.get("circom_max_input_size", 200)
        self._template_name = "TestRegex"
        super().__init__(regex, kwargs)
        self._runner = "Circom"
        self.identifer = ""

    def compile(self, regex: str) -> None:
        """
        Compile the regex.
        """
        logger.debug("Compiling regex starts")
        # Create JSON for the regex for zk-regex
        base_json = {"parts": []}
        # TODO: handle the following if is_public is set to True:
        # the section containing this ^ must be non-public (is_public: false).
        regex_parts = {"regex_def": regex, "is_public": False}
        base_json["parts"].append(regex_parts)
        regex_json = json.dumps(base_json)

        # Write the JSON to a temporary file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            tmp_file.write(regex_json.encode())
            json_file_path = tmp_file.name

        circom_file_path = tempfile.NamedTemporaryFile(
            suffix=".circom", delete=False
        ).name

        # Call zk-regex to generate the circom code
        logger.debug("Generating circom code starts")
        ZkRegexSubprocess.compile(json_file_path, circom_file_path, self._template_name)
        logger.debug("Generating circom code ends")

        # Append the circom file to include the main function
        with open(circom_file_path, "a") as f:
            f.write("\n\n")
            f.write(
                "component main {public [msg]} = "
                + f"{self._template_name}({self._circom_max_input_size});"
            )

        self._circom_path = circom_file_path

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
        # Convert input to list of decimal ASCII values and pad input with zeroes
        numeric_input = [ord(c) for c in input] + [0] * (
            self._circom_max_input_size - len(input)
        )

        # Write input to a temporary JSON file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            tmp_file.write(json.dumps({"msg": numeric_input}).encode())
            input_path = tmp_file.name

        self._input_path = input_path

        # Skip if input is larger than circuit max input size
        if len(numeric_input) > self._circom_max_input_size:
            raise RegexRunError(f"Input too large for input: {len(numeric_input)}")

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

        # TODO: get and convert substr output to its string representation

        # Return the output of the match
        output = int(result[1])
        logger.debug("Matching regex ends")
        return output == 1, ""

    def clean(self):
        # Remove all temporary files
        if self._wasm_path:
            shutil.rmtree(Path(self._wasm_path).parent)
        if self._circom_path:
            Path(self._circom_path).unlink(True)
        if self._input_path:
            Path(self._input_path).unlink(True)
        if self._r1cs_path:
            Path(self._r1cs_path).unlink(True)
        if self._zkey_path:
            Path(self._zkey_path).unlink(True)
        if self._vkey_path:
            Path(self._vkey_path).unlink(True)

    def save(self, path) -> str:
        circom_path = Path(self._circom_path)
        input_path = Path(self._input_path)
        r1cs_path = Path(self._r1cs_path)
        wasm_path = Path(self._wasm_path)
        target_path = Path(path).resolve() / f"output_{r1cs_path.stem}"
        target_path.mkdir()

        if self._circom_path:
            circom_path.replace(target_path / circom_path.name)
        if self._input_path:
            input_path.replace(target_path / input_path.name)
        if self._r1cs_path:
            r1cs_path.replace(target_path / r1cs_path.name)
        if self._wasm_path:
            wasm_path.replace(target_path / wasm_path.name)

        if self._run_the_prover:
            zkey_path = Path(self._zkey_path)
            vkey_path = Path(self._vkey_path)

            zkey_path.replace(target_path / zkey_path.name)
            vkey_path.replace(target_path / vkey_path.name)

        return str(target_path)
