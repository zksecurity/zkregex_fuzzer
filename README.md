# zkregex_fuzzer

## Installation

First, you need to generate a virtual env.

```bash
python3 -m venv venv
source venv/bin/activate
```

Next, you can run the fuzzer locally:

```
pip install -e .
python src/zkregex_fuzzer/cli.py --help
```

or you can install it:

```
pip install -e .
zkregex-fuzzer --help
```

## Linting and tests

```
pip install -e '.[dev]'
# Either run manually
ruff check .
ruff format .
pytest
# or through the script
python scripts/lint_and_tests.py
```

### Circom

In order to target Circom implementation, you need to install Circom and SnarkJS (optional)

Circom:

```
git clone https://github.com/iden3/circom.git
cargo build --release
cargo install --path circom
```

SnarkJS: 

```
npm install -g snarkjs@latest
```

### Noir

In order to target Noir implementation, you need to install Noir as follows:

```
git clone git@github.com:Mach-34/noir-zk-regex.git
cd noir-zk-regex
git checkout fix/efficient-substrings
cargo install --path packages/compiler/
```

Optionally, install Barretenberg if we want to test the proving/verification as well:

```
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup
```

## Example Run

### Fuzzing

```
python src/zkregex_fuzzer/cli.py fuzz --fuzzer grammar --oracle valid --target python_re --valid-input-generator exrex
```

### Reproducing bugs

```
python src/zkregex_fuzzer/cli.py reproduce --path output*
```

# Test zkregex

First we need to install zkregex. Follow the instructions from here:

<https://github.com/zkemail/zk-regex/tree/main/packages/compiler>

We further need to have installed zk-regex circom dependencies (circomlib and zk-regex circuits).
You can follow the instructions from here:

<https://github.com/zkemail/zk-regex/>

Finally, if we say that you install the above in the parent directory you can run the fuzzer with the following command:

```
python src/zkregex_fuzzer/cli.py fuzz \
    --oracle valid \
    --target circom \
    --valid-input-generator rstr \
    --fuzzer grammar \
    --circom-library ../zk-regex/node_modules/circomlib ../zk-regex/node_modules/
```
