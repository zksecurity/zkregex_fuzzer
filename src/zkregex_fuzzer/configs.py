from zkregex_fuzzer.runner import CircomRunner, PythonReRunner
from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.vinpgen import GrammarBasedGenerator, RstrGenerator, ExrexGenerator


TARGETS = {
    "circom": CircomRunner,
    "python_re": PythonReRunner,
}

GRAMMARS = {
    "basic": REGEX_GRAMMAR,
}

VALID_INPUT_GENERATORS = {
    "grammar": GrammarBasedGenerator,
    "rstr": RstrGenerator,
    "exrex": ExrexGenerator,
}
