"""
Implements the logic for generating regexes.

We have two generators:
- A grammar-based generator that uses The Fuzzing Book's GrammarFuzzer.
- Pre-seeded regexes.

TODO:
- Add DatabaseRegexGenerator that uses a database of regexes to generate new ones.
    - The database should be minted from here: https://github.com/zkemail/zk-regex/tree/main/packages/circom/circuits/common
    - The database should include in the future any good seeds that help us find bugs.
- Add logging and statistics to the generator.
- Add a DFA-based generator?
"""

import random, pathlib, glob, json
from abc import ABC, abstractmethod
from typing import List

from zkregex_fuzzer.utils import is_valid_regex, check_zkregex_rules_basic
from zkregex_fuzzer.utils import grammar_fuzzer
from zkregex_fuzzer.logger import logger
from fuzzingbook.Grammars import Grammar


class RegexGenerator(ABC):
    """
    Base abstract class for regex generators.
    """

    @abstractmethod
    def generate_unsafe(self) -> str:
        """
        Generate a regex without any checks.
        """
        pass

    def generate(self) -> str:
        """
        Generate a regex.
        """
        while True:
            regex = self.generate_unsafe()
            if not is_valid_regex(regex):
                continue
            if not check_zkregex_rules_basic(regex):
                continue
            logger.debug(f"Generated regex: {regex}")
            return regex

    def generate_many(self, num: int) -> List[str]:
        """
        Generate `num` regexes.
        """
        logger.debug(f"Generating {num} regexes.")
        return [self.generate() for _ in range(num)]


class GrammarRegexGenerator(RegexGenerator):
    """
    Generate regexes using a grammar.
    """

    def __init__(self, grammar: Grammar, start_symbol: str, max_nonterminals: int = 10, max_expansion_trials: int = 100):
        self.grammar = grammar
        self.start_symbol = start_symbol
        self.max_nonterminals = max_nonterminals
        self.max_expansion_trials = max_expansion_trials

    def generate_unsafe(self) -> str:
        """
        Generate a regex using a grammar.
        """
        return grammar_fuzzer(self.grammar, self.start_symbol, self.max_nonterminals, self.max_expansion_trials)

class DatabaseRegexGenerator(RegexGenerator):
    """
    Generate regexes using a database of regexes.
    """

    def __init__(self, dir_path: str = ""):
        dir_path = dir_path or self._get_default_path()
        self.database = self._get_database_from_path(dir_path)

    def _get_default_path(self) -> str:
        """
        Get the default path for the database.
        """
        current_path = pathlib.Path(__file__).parent.parent.parent
        database_path = current_path / "database"
        return str(database_path)

    def _get_database_from_path(self, dir_path: str) -> List[str]:
        """
        Get the database from a path.
        """
        database = []
        for file in glob.glob(f"{dir_path}/*.json"):
            with open(file, "r") as f:
                content = json.loads(f.read())
                regex = ""
                for part in content["parts"]:
                    regex += r"{}".format(part['regex_def'])

                database.append(regex)

        return database

    def generate_unsafe(self) -> str:
        """
        Generate a regex using a database.
        """
        return random.choice(self.database)
    
    def generate_many(self, num):
        
        if num >= len(self.database):
            return self.database
        else:
            result = []
            for _ in range(num):
                while True:
                    generated = self.generate()
                    if generated not in result:
                        result.append(generated)
                        break
                
            return result