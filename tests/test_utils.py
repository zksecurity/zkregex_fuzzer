from zkregex_fuzzer.utils import is_valid_regex


def test_valid_regex():
    """Test that valid regexes return True."""
    valid_patterns = [
        r"abc",
        r"[a-zA-Z]",
        r"^start",
        r"end$",
        r"hello|world",
    ]
    for pattern in valid_patterns:
        assert is_valid_regex(pattern), f"Expected {pattern} to be valid"


def test_invalid_regex():
    """Test that invalid regexes return False."""
    invalid_patterns = [
        r"[a-Z]",
        r"(",
        r"[abc",
        r"{1,3}",
        r"hello)",
        r"**",
    ]
    for pattern in invalid_patterns:
        assert not is_valid_regex(pattern), f"Expected {pattern} to be invalid"
