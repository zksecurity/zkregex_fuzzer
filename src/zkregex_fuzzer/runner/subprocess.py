import json
import re
import shutil
import subprocess
from pathlib import Path

from zkregex_fuzzer.logger import logger

from .base_runner import RegexCompileError, RegexRunError


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
    def compile_to_circom(
        cls,
        json_file_path: str,
        output_file_path: str,
        template_name: str = "TestRegex",
        substr=True,
    ):
        """
        Compile a regex using zk-regex
        into Circom circuit.
        """
        cmd = [
            "zk-regex",
            "decomposed",
            "--decomposed-regex-path",
            json_file_path,
            "--output-file-path",
            output_file_path,
            "--template-name",
            template_name,
            "--proving-framework",
            "circom",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexCompileError(f"Error compiling with zk-regex: {result.stderr}")

    @classmethod
    def generate_circuit_inputs(
        cls,
        graph_path: str,
        input_str: str,
        max_haystack_len: int,
        max_match_len: int,
        output_path: str,
        proving_framework: str,
        oracle: bool,
    ) -> bool:
        """
        Generate Circom inputs from a cached graph and test string.

        Returns:
            if oracle is True, return True if the input is valid, False otherwise.
            if oracle is False, return True if the input is invalid, False otherwise.
        """
        if '"' in input_str:
            input_str = "'" + input_str + "'"
        elif "'" in input_str:
            input_str = '"' + input_str + '"'
        elif input_str[0] == "-":
            input_str = '"' + input_str + '"'
        cmd = [
            "zk-regex",
            "generate-circuit-input",
            "--graph-path",
            graph_path,
            "--input",
            input_str, 
            "--max-haystack-len",
            str(max_haystack_len),
            "--max-match-len",
            str(max_match_len),
            "--output-file-path",
            output_path,
            "--proving-framework",
            proving_framework,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # if oracle is false we except it to fail
            if not oracle:
                return True

            raise RegexRunError(
                f"Error generating inputs with zk-regex (oracle is True but we failed to generate an input): {result.stderr}"
            )
        if not oracle:
            raise RegexRunError(
                f"Error generating inputs with zk-regex (oracle is False but we generated an input): {result.stderr}"
            )
        return True

    @classmethod
    def compile_to_noir(
        cls,
        json_file_path: str,
        output_file_path: str,
        template_name: str = "TestRegex",
        substr=True,
    ):
        """
        Compile a regex using zk-regex
        into Noir circuit.
        """
        cmd = [
            "zk-regex",
            "decomposed",
            "--decomposed-regex-path",
            json_file_path,
            "--output-file-path",
            output_file_path,
            "--template-name",
            template_name,
            "--proving-framework",
            "noir",
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
        base_dir = Path(circuit_path).parent
        output_path = str(base_dir / f"{base_name}.zkey")

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
        base_dir = Path(zkey_path).parent
        output_path = str(base_dir / f"{base_name}.vkey.json")

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
        base_dir = Path(wasm_file_path).parent
        output_path = str(base_dir / f"{base_name}.wtns")

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
        base_dir = Path(zkey_path).parent
        proof_path = str(base_dir / f"{base_name}.proof.json")
        public_input_path = str(base_dir / f"{base_name}.public.json")

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


class NoirSubprocess:
    @classmethod
    def get_installed_version(cls) -> str:
        """
        Get the installed version of noir.
        """
        if shutil.which("nargo"):
            cmd = ["nargo", "--version"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.split("\n")[0]
        else:
            raise ValueError("Noir (nargo) is not installed")

    @classmethod
    def compile(cls, noir_dir_path: str):
        """
        Compile Noir workspace.
        """
        cmd = [
            "nargo",
            "compile",
            "--silence-warnings",
            "--skip-underconstrained-check",
        ]

        logger.debug(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=noir_dir_path)

        if result.returncode != 0:
            raise RegexCompileError(f"Error compiling with Noir: {result.stderr}")

    @staticmethod
    def _extract_output(stdout: str) -> list:
        """
        Extract the output from the stdout.
        Currently, there is no known method from nargo CLI to extract
        only public output from the witness.
        """
        match = re.search(r"output: \[([^\]]+)\]", stdout)
        if match:
            hex_values = match.group(1)
            int_list = [
                int(x, 16) for x in hex_values.split(", ")
            ]  # Convert hex to int
            return int_list

        return []

    @classmethod
    def witness_gen(cls, noir_dir_path: str) -> list[int]:
        """
        Generate witness with Noir.
        """
        cmd = ["nargo", "execute", "--silence-warnings"]

        logger.debug(" ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=noir_dir_path)

        if result.returncode != 0:
            return []

        return cls._extract_output(result.stdout)


class BarretenbergSubprocess:
    @classmethod
    def get_installed_version(cls) -> str:
        """
        Get the installed version of Barretenberg.
        """
        if shutil.which("bb"):
            cmd = ["bb", "--version"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            match = re.search(r"\b\d+\.\d+\.\d+\b", result.stdout)
            if match:
                version = match.group()
                return version
            else:
                return result.stdout.strip()
        else:
            raise ValueError("Barretenberg is not installed")

    @classmethod
    def export_verification_key(cls, path: str) -> str:
        """
        Export the verification key from the circuit.
        """

        json_path = str(Path(path) / "target/test_regex.json")
        vk_path = str(Path(path) / "target/vk")

        cmd = ["bb", "write_vk", "-b", json_path, "-o", vk_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexRunError(f"Error running with Barretenberg: {result.stderr}")

        return vk_path

    @classmethod
    def prove(cls, path: str) -> str:
        """
        generate proof from the witness.
        """

        base_path = Path(path)
        json_path = str(base_path / "target/test_regex.json")
        gz_path = str(base_path / "target/test_regex.gz")
        proof_path = str(base_path / "target/proof")

        cmd = [
            "bb",
            "prove",
            "-b",
            json_path,
            "-w",
            gz_path,
            "-o",
            proof_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RegexRunError(f"Error proving with Barretenberg: {result.stderr}")

        return proof_path

    @classmethod
    def verify(cls, path: str) -> bool:
        """
        Verify the proof with the verification key.
        """

        vkey_path = Path(path) / "target/vk"
        proof_path = Path(path) / "target/proof"

        cmd = [
            "bb",
            "verify",
            "-k",
            vkey_path,
            "-p",
            proof_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logger.debug(result.stderr)
            return False

        return True
