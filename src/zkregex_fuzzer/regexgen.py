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

import concurrent.futures
import gc
import glob
import json
import os
import pathlib
import random
from abc import ABC, abstractmethod
from typing import List

from fuzzingbook.Grammars import Grammar
from tqdm import tqdm

from zkregex_fuzzer.dfa import (
    generate_random_dfa,
    transform_dfa_to_regex,
)
from zkregex_fuzzer.logger import logger
from zkregex_fuzzer.utils import (
    check_zkregex_rules_basic,
    grammar_fuzzer,
    is_valid_regex,
    timeout_decorator,
)

# Default number of max tries multiplier for regex generation
DEFAULT_MAX_TRIES_MULTIPLIER = 10


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

    @timeout_decorator(5, "Regex generation timeout")
    def generate(self) -> str:
        """
        Generate a regex.
        """
        while True:
            regex = self.generate_unsafe()
            if not is_valid_regex(regex):
                continue
            correct, _ = check_zkregex_rules_basic(regex)
            if not correct:
                # TODO: We should try to fix the regex if it has multiple accepting states
                continue
            logger.debug(f"Generated regex: {regex}")
            return regex

    def generate_many(self, num: int) -> List[str]:
        """
        Generate `num` regexes.
        """
        initial_max_tries = num * DEFAULT_MAX_TRIES_MULTIPLIER
        max_tries = initial_max_tries
        logger.debug(f"Generating {num} regexes.")
        regexes = set()

        max_workers = max(1, os.cpu_count() or 1)
        max_workers = max_workers - 1 if max_workers > 1 else 1

        with tqdm(total=num, desc="Generating Regexes") as pbar:
            while len(regexes) < num:
                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=max_workers
                ) as executor:
                    future_to_idx = {
                        executor.submit(self.generate): i
                        for i in range(num - len(regexes))
                    }
                    for future in concurrent.futures.as_completed(future_to_idx):
                        try:
                            regex = future.result()
                            if regex not in regexes:
                                regexes.add(regex)
                                pbar.update(1)
                            else:
                                max_tries -= 1
                        except Exception as e:
                            logger.debug(f"Regex generation failed: {e}")
                            max_tries -= 1
                # Ensure garbage collection runs to clean up any lingering references
                gc.collect()
                if max_tries <= 0:
                    logger.warning(
                        f"Generated {len(regexes)} regexes with {initial_max_tries} max tries."
                    )
                    return list(regexes)
        return list(regexes)


class GrammarRegexGenerator(RegexGenerator):
    """
    Generate regexes using a grammar.
    """

    def __init__(
        self,
        grammar: Grammar,
        start_symbol: str,
        max_nonterminals: int = 25,
        max_expansion_trials: int = 100,
    ):
        self.grammar = grammar
        self.start_symbol = start_symbol
        self.max_nonterminals = max_nonterminals
        self.max_expansion_trials = max_expansion_trials

    def generate_unsafe(self) -> str:
        """
        Generate a regex using a grammar.
        """
        return grammar_fuzzer(
            self.grammar,
            self.start_symbol,
            self.max_nonterminals,
            self.max_expansion_trials,
        )


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
                    regex += r"{}".format(part["regex_def"])

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


class DFARegexGenerator(RegexGenerator):
    """
    Generate regexes using a DFA.
    """

    def __init__(
        self,
        max_depth: int = 5,
        use_unicode: bool = False,
        single_final_state: bool = True,
    ):
        self.max_depth = max_depth
        self.use_unicode = use_unicode
        self.single_final_state = single_final_state

    def generate_unsafe(self) -> str:
        """
        Generate a regex using a DFA.
        """
        while True:
            try:
                dfa = generate_random_dfa(
                    self.max_depth, self.use_unicode, self.single_final_state
                )
                return transform_dfa_to_regex(dfa)
            except Exception as e:
                logger.debug(f"Error generating DFA: {e}")
                continue
