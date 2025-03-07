from zkregex_fuzzer.utils import (
    check_zkregex_rules_basic,
    correct_carret_position,
    has_lazy_quantifier,
    is_valid_regex,
)


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


def test_has_lazy_quantifier():
    """Test that has_lazy_quantifier returns True for patterns with lazy quantifiers."""
    patterns = [
        (r"ab*c", False),
        (r"a+?", True),
        (r"(abc){2,5}?", True),
        (r"xyz", False),
        (r"[a-z]*", False),
        (r".+?", True),
    ]
    for pattern, expected in patterns:
        assert has_lazy_quantifier(pattern) == expected, (
            f"Expected {pattern} to have lazy quantifier: {expected}"
        )


def test_correct_carret_position():
    """
    Test the correct_carret_position function with various corner cases.
    """
    # Test cases with expected results
    test_cases = [
        # Basic cases
        (r"^abc", True),  # Start of regex
        (r"abc", True),  # No caret
        (r"abc^", False),  # Invalid position at end
        # Capturing group cases
        (r"(^abc)", False),  # Start of capturing group
        (r"(|^)", True),  # Alternative with caret
        (r"(abc|^def)", False),  # Caret in middle of alternative
        (r"(|^)", True),  # Simple alternative with caret
        (r"(\n|^)", True),  # Newline alternative
        (r"abc(\n|^)", False),  # Not at start of regex
        (r"(\r|^)", True),  # Carriage return alternative
        (r"(\r\n|^)", True),  # CRLF alternative
        (r"(\n\r|^)", True),  # CRLF alternative
        (r"(  |^)", True),  # Spaces before alternative
        # Character class cases
        (r"[^abc]", True),  # Simple negated character class
        (r"abc[^xyz]def", True),  # Negated character class in middle
        (r"[abc^]", False),  # Caret not at start of character class
        (r"[[^]]", True),  # Nested character class
        (r"[^]", True),  # Empty negated character class
        # Multiple caret cases
        (r"^abc[^xyz]", True),  # Valid multiple carets
        (r"^abc^", False),  # Invalid multiple carets
        (r"[^abc][^xyz]", True),  # Multiple negated character classes
        # Edge cases
        (r"", True),  # Empty string
        (r"^", True),  # Just caret
        (r"[]^]", False),  # Invalid character class
        (r"(^)|^", False),  # Multiple start anchors
        (r"(^abc|^def)", False),  # Multiple start anchors in group
        # Complex cases
        (r"(|^)abc[^xyz]123", True),  # Combination of valid cases
        (r"^abc[^xyz](|^)def", False),  # Invalid multiple start anchors
        (r"[^abc]^[^xyz]", False),  # Invalid caret between character classes
        (r"(  \r\n  |^)abc", True),  # Complex whitespace before alternative
        # Escaped caret cases
        (r"abc\^", True),
        (r"abc\^def", True),
    ]
    for regex, expected in test_cases:
        assert correct_carret_position(regex) == expected, (
            f"Expected {regex} to have correct caret position: {expected}"
        )


def test_check_zkregex_rules_basic():
    """
    Test the check_zkregex_rules_basic function with various test cases.
    """
    # Test cases with expected results
    test_cases = [
        # 1. Dollar sign tests
        (r"abc$", (True, True)),  # Valid dollar sign at end,
        (r"abc$def", (True, True)),  # Valid dollar sign in middle
        (r"abc", (True, True)),  # No dollar sign
        (r"$abc", (True, True)),  # Dollar sign at start
        # 2. Caret position tests
        (r"^abc", (True, True)),  # Valid caret at start
        (r"(|^)abc", (True, True)),  # Valid caret in alternative
        (r"(\r\n|^)abc", (True, True)),  # Valid caret with CRLF alternative
        (r"[^abc]", (True, True)),  # Valid caret in character class
        (r"abc^", (False, True)),  # Invalid caret at end
        (r"abc^def", (False, True)),  # Invalid caret in middle
        # 3. Lazy quantifier tests
        (r"abc*", (True, True)),  # Valid greedy quantifier
        (r"abc*?", (False, True)),  # Invalid lazy star quantifier
        (r"abc+?", (False, True)),  # Invalid lazy plus quantifier
        (r"abc??", (False, True)),  # Invalid lazy question mark quantifier
        (r"abc{1,2}?", (False, True)),  # Invalid lazy range quantifier
        # 4. Combined valid cases
        (r"^abc$", (True, True)),  # Valid start and end anchors
        (r"(|^)abc$", (True, True)),  # Valid alternative and end anchor
        (r"[^abc].*$", (True, True)),  # Valid character class and end anchor
        # 5. Combined invalid cases
        (r"^abc$def", (True, True)),  # Valid dollar position with caret
        (r"abc^def$", (False, True)),  # Invalid caret with dollar
        (r"[^abc]*?$", (False, True)),  # Invalid lazy quantifier with valid anchors
        # 6. Complex cases
        (r"(|^)abc[^xyz]*$", (True, True)),  # Complex valid regex
        (r"^abc[^xyz]+def$", (True, True)),  # Complex valid regex with quantifiers
        (
            r"(|^)abc*?[^xyz]$",
            (False, True),
        ),  # Complex invalid regex with lazy quantifier
        (r"[a-zA-Z0-9._%+-]+", (True, True)),
        (r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", (True, True)),
        # 7. The common regexes from zkemail
        (r">[^<>]+<.*", (True, True)),
        (r"(\r\n|^)to:[^\r\n]+\r\n", (True, True)),
        (r"(\r\n|^)subject:[^\r\n]+\r\n", (True, True)),
        (r"[A-Za-z0-9!#$%&'*+=?\-\^_`{|}~.\/]+@[A-Za-z0-9.\-@]+", (True, True)),
        (r"[A-Za-z0-9!#$%&'*+=?\-\^_`{|}~.\/@]+@[A-Za-z0-9.\-]+", (True, True)),
        (r"(\r\n|^)from:[^\r\n]+\r\n", (True, True)),
        (r"(\r\n|^)dkim-signature:([a-z]+=[^;]+; )+bh=[a-zA-Z0-9+/=]+;", (True, True)),
        (r"(\r\n|^)dkim-signature:([a-z]+=[^;]+; )+t=[0-9]+;", (True, True)),
        (r"(\r\n|^)message-id:<[A-Za-z0-9=@\.\+_-]+>\r\n", (True, True)),
    ]
    for regex, expected in test_cases:
        assert check_zkregex_rules_basic(regex) == expected, (
            f"Expected {regex} to have correct zk-regex rules: {expected}"
        )
