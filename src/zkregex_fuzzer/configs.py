from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.regexgen import (
    DatabaseRegexGenerator,
    DFARegexGenerator,
    GrammarRegexGenerator,
)
from zkregex_fuzzer.runner import CircomRunner, NoirRunner, PythonReRunner
from zkregex_fuzzer.vinpgen import (
    DFAWalkerGenerator,
    ExrexGenerator,
    GrammarBasedGenerator,
    MixedGenerator,
    RstrGenerator,
)

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
    "dfa": DFAWalkerGenerator,
    "mixed": MixedGenerator,
}

GENERATORS = {
    "grammar": GrammarRegexGenerator,
    "database": DatabaseRegexGenerator,
    "dfa": DFARegexGenerator,
    "single": None,  # Just pass a regex to use
}
