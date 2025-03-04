from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.regexgen import DatabaseRegexGenerator, GrammarRegexGenerator
from zkregex_fuzzer.runner import CircomRunner, PythonReRunner
from zkregex_fuzzer.vinpgen import ExrexGenerator, GrammarBasedGenerator, RstrGenerator

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

GENERATORS = {
    "grammar": GrammarRegexGenerator,
    "database": DatabaseRegexGenerator,
}
