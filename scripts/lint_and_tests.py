import subprocess
import sys


def run_command(command: str) -> int:
    """Runs a shell command and returns the exit code."""
    print(f"Running: {command}")
    process = subprocess.run(command, shell=True)
    return process.returncode


def run_linter() -> int:
    """Runs Ruff to check for linting errors."""
    print("Running Ruff Linter...")
    return run_command("ruff check .")


def run_formatter() -> int:
    """Runs Black to check for formatting errors."""
    print("Running Black Formatter...")
    return run_command("ruff format .")


def run_tests() -> int:
    """Placeholder for future test execution."""
    print("Running Tests (Placeholder)...")
    return run_command("pytest")


if __name__ == "__main__":
    lint_exit_code = run_linter()
    test_exit_code = run_tests()

    if lint_exit_code != 0 or test_exit_code != 0:
        print("❌ Checks failed!")
        sys.exit(1)  # Fail GitHub Action if linting or tests fail
    else:
        print("✅ All checks passed!")
        sys.exit(0)
