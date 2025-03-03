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
