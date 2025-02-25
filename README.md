# zkregex_fuzzer

## Installation

First, you need to generate a virtual env.

```bash
python3 -m venv venv
source venv/bin/activate
```

Next, you can run the fuzzer locally:

```
pip install -r requirements.txt
python src/zkregex_fuzzer/cli.py --help
```

or you can install it:

```
pip install -e .
zkregex-fuzzer --help
```

## Example Run

```
python src/zkregex_fuzzer/cli.py --fuzzer grammar --oracle valid --target python_re --valid-input-generator exrex
```

# Test zkregex

First we need to install zkregex. Follow the instructions from here:

<https://github.com/zkemail/zk-regex/tree/main/packages/compiler>
