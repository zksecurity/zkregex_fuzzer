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
