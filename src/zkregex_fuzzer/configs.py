from zkregex_fuzzer.grammar import BASIC_REGEX_GRAMMAR, OLD_GRAMMAR
from zkregex_fuzzer.invinpgen import (
    ComplementBasedGenerator,
    MutationBasedGenerator,
    NFAInvalidGenerator,
)
from zkregex_fuzzer.invinpgen import (
    MixedGenerator as MixedInvalidGenerator,
)
from zkregex_fuzzer.invinpgen import (
    PredefinedGenerator as PredefinedInvalidGenerator,
)
from zkregex_fuzzer.regexgen import (
    DatabaseRegexGenerator,
    DFARegexGenerator,
    GrammarRegexGenerator,
)
from zkregex_fuzzer.runner import CircomRunner, NoirRunner, PythonReRunner
from zkregex_fuzzer.vinpgen import (
    ExrexGenerator,
    GrammarBasedGenerator,
    MixedGenerator,
    NFAValidGenerator,
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
    "basic": BASIC_REGEX_GRAMMAR,
    "old": OLD_GRAMMAR,
}

VALID_INPUT_GENERATORS = {
    "grammar": GrammarBasedGenerator,
    "rstr": RstrGenerator,
    "exrex": ExrexGenerator,
    "nfa": NFAValidGenerator,
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
