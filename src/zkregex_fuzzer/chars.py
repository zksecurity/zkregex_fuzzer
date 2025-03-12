import string


def create_range(start_char: str, end_char: str) -> set[str]:
    """
    Create a set of characters from start_char to end_char.
    """
    return {chr(i) for i in range(ord(start_char), ord(end_char) + 1)}


LATIN_EXT_CHARS = create_range("¡", "ƿ")
GREEK_CHARS = create_range("Ͱ", "Ͽ")
CYRILLIC_CHARS = create_range("Ѐ", "ӿ")
ASCII_CHARS = set(string.printable)
ALL_CHARS = ASCII_CHARS.union(LATIN_EXT_CHARS).union(GREEK_CHARS).union(CYRILLIC_CHARS)
SUPPORTED_CHARS = ASCII_CHARS
# All supported characters and escape all the regex characters that need to be escaped
ESCAPE_CHARS = ["\\", "^", "$", ".", "|", "?", "*", "+", "()", "[]", "{", "}"]
ESCAPED_CHARS = [f"\\{c}" for c in ESCAPE_CHARS]
SUPPORTED_ESCAPE_CHARS = ASCII_CHARS.difference(ESCAPE_CHARS).union(ESCAPED_CHARS)
