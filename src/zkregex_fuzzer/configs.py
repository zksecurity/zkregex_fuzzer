from zkregex_fuzzer.grammar import REGEX_GRAMMAR
from zkregex_fuzzer.invinpgen import (
    ComplementBasedGenerator,
    MutationBasedGenerator,
    NFAInvalidGenerator,
    MixedGenerator as MixedInvalidGenerator,
    PredefinedGenerator as PredefinedInvalidGenerator,
)
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
    PredefinedGenerator,
    RstrGenerator,
)

FUZZER_VERSION = "0.1.0"

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
    "predefined": PredefinedGenerator,
}

INVALID_INPUT_GENERATORS = {
    "mutation": MutationBasedGenerator,
    "complement": ComplementBasedGenerator,
    "nfa": NFAInvalidGenerator,
    "mixed": MixedInvalidGenerator,
    "predefined": PredefinedInvalidGenerator,
}

GENERATORS = {
    "grammar": GrammarRegexGenerator,
    "database": DatabaseRegexGenerator,
    "dfa": DFARegexGenerator,
    "single": None,  # Just pass a regex to use
}
