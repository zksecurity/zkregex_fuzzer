import string
from dataclasses import dataclass


def create_range(start_char: str, end_char: str) -> set[str]:
    """
    Create a set of characters from start_char to end_char.
    """
    return {chr(i) for i in range(ord(start_char), ord(end_char) + 1)}


# TODO singleton
LATIN_EXT_CHARS = create_range("¡", "ƿ")
GREEK_CHARS = create_range("Ͱ", "Ͽ")
CYRILLIC_CHARS = create_range("Ѐ", "ӿ")
ASCII = set(string.printable)
CONTROLLED_UTF8_CHARS = (
    ASCII.union(LATIN_EXT_CHARS).union(GREEK_CHARS).union(CYRILLIC_CHARS)
)
UNCONTROLLED_UTF8_CHARS = {
    chr(codepoint)
    for codepoint in range(0x110000)
    if not (0xD800 <= codepoint <= 0xDFFF)
}

# All supported characters and escape all the regex characters that need to be escaped
ESCAPE_CHARS = ["\\", "^", "$", ".", "|", "?", "*", "+", "()", "[]", "{", "}"]
ESCAPED_CHARS = [f"\\{c}" for c in ESCAPE_CHARS]


@dataclass
class SupportedChars:
    all_chars: set[str]
    non_escaped_chars: set[str]
    including_escaped_chars: set[str]


ASCII_CHARS = SupportedChars(
    all_chars=ASCII,
    non_escaped_chars=ASCII.difference(ESCAPE_CHARS),
    including_escaped_chars=ASCII.difference(ESCAPE_CHARS).union(ESCAPED_CHARS),
)

CONTROLLED_UTF8_CHARS = SupportedChars(
    all_chars=CONTROLLED_UTF8_CHARS,
    non_escaped_chars=CONTROLLED_UTF8_CHARS.difference(ESCAPE_CHARS),
    including_escaped_chars=CONTROLLED_UTF8_CHARS.difference(ESCAPE_CHARS).union(
        ESCAPED_CHARS
    ),
)

UNCONTROLLED_UTF8_CHARS = SupportedChars(
    all_chars=UNCONTROLLED_UTF8_CHARS,
    non_escaped_chars=UNCONTROLLED_UTF8_CHARS.difference(ESCAPE_CHARS),
    including_escaped_chars=UNCONTROLLED_UTF8_CHARS.difference(ESCAPE_CHARS).union(
        ESCAPED_CHARS
    ),
)


class SupportedCharsManager:
    """Singleton for supported characters."""

    _instance = None

    def __new__(cls, char_set="ascii"):
        if cls._instance is None:
            cls._instance = super(SupportedCharsManager, cls).__new__(cls)
            cls._instance.chars = None  # Initialize the attribute
            cls._instance._set_chars(char_set)

        return cls._instance

    def _set_chars(self, char_set):
        """Set the character set based on the provided name."""
        if char_set == "ascii":
            self.chars = ASCII_CHARS
        elif char_set == "controlled_utf8":
            self.chars = CONTROLLED_UTF8_CHARS
        elif char_set == "uncontrolled_utf8":
            self.chars = UNCONTROLLED_UTF8_CHARS
        else:
            raise ValueError(f"Invalid character set: {char_set}")

    def get_chars(self):
        """Get the supported characters."""
        return self.chars

    @classmethod
    def override(cls, char_set):
        """
        Override the character set of the singleton instance.
        If the instance doesn't exist, it will be created.

        Args:
            char_set: The name of the character set to use

        Returns:
            The singleton instance
        """
        # Create the instance if it doesn't exist
        if cls._instance is None:
            return cls(char_set)

        # Override the existing instance's character set
        cls._instance._set_chars(char_set)
        return cls._instance
