from zkregex_fuzzer.runner import CircomRunner, PythonReRunner, NoirRunner
from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.regexgen import GrammarRegexGenerator, DatabaseRegexGenerator
from zkregex_fuzzer.vinpgen import GrammarBasedGenerator, RstrGenerator, ExrexGenerator


TARGETS = {
    "circom": CircomRunner,
    "noir": NoirRunner,
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