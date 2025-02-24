import sre_parse
import string
from typing import Dict, List, Tuple, Any, Union
from fuzzingbook.Grammars import Grammar, Expansion
def regex_to_grammar(regex: str) -> Grammar:
    """
    Convert a Python-style regex into a Fuzzing Book–style grammar
    that covers the same subset of features as the original grammar:
      - Union (|)
      - Concatenation
      - Grouping (...)
      - * and +
      - Dot (.)
      - End of string ($)
      - Character sets [abc] or [^xyz]
      - Ranges (a-z, 0-9)
    
    Returns a dictionary mapping nonterminal -> list of expansions.
    The top-level rule is <start>, which references <REGEX_0>,
    and that rule expands into the pattern represented by `regex`.
    
    NOTE:
      - This code does not handle every Python regex feature. 
      - Large repetition ranges are approximated.
      - Negative sets are supported in a basic way.
      - Additional expansions may be needed to fully replicate
        your original grammar's logic (e.g. capturing vs. non-capturing groups).
    """
    # Parse the regex via Python's built-in parser
    parsed = sre_parse.parse(regex)
    parsed_tokens: List[Tuple[Any, Any]] = parsed.data
    
    # The grammar dictionary we'll build
    grammar: Dict[str, List[Expansion]] = {}

    # We'll keep a counter to generate unique rule names
    rule_counter = [0]

    def new_rule_name(prefix="REGEX") -> str:
        name = f"<{prefix}_{rule_counter[0]}>"
        rule_counter[0] += 1
        return name

    # Create a top-level rule
    top_rule = new_rule_name()
    grammar["<start>"] = [top_rule]

    # We'll define a function that recursively walks the parse tree
    # and returns a rule name representing that fragment.
    def handle_token_list(token_list: List[Tuple[Any, Any]]) -> str:
        """
        Convert a list of parsed tokens (from sre_parse) 
        into a grammar nonterminal that references expansions 
        matching the concatenation of those tokens.
        
        In your original grammar, this corresponds roughly to <concat>.
        If we encounter unions, we handle them specially.
        """
        # We'll produce a single rule that yields exactly one expansion
        # containing the concatenation of sub-rules or literals
        # that the token_list represents.
        rule_name = new_rule_name("CONCAT")
        
        # We'll collect expansions from each token in a row
        expansion_parts = []
        
        for (token_type, token_value) in token_list:
            if token_type == sre_parse.LITERAL:
                # Single literal char, e.g. 'a'
                ch = chr(token_value)
                # Just append it directly to the expansion
                expansion_parts.append(ch)
            
            elif token_type == sre_parse.ANY:
                # Dot (.)
                expansion_parts.append(".")  # matches your <any> rule
            
            elif token_type == sre_parse.IN:
                # Character set [abc] or [^abc]
                set_rule = handle_in(token_value)
                expansion_parts.append(set_rule)
            
            elif token_type == sre_parse.SUBPATTERN:
                # Grouped subpattern: ( ... )
                # token_value is (group_num, flags, sub_tokens)
                (_, _flags, sub_tokens) = token_value
                sub_rule = handle_token_list(sub_tokens)
                # wrap it with parentheses
                group_rule = new_rule_name("GROUP")
                # in your grammar, a group is literally (<regex>)
                # So we define group_rule -> "(" sub_rule ")"
                grammar[group_rule] = [f"({sub_rule})"]
                expansion_parts.append(group_rule)
            
            elif token_type == sre_parse.BRANCH:
                # Union, e.g. (foo|bar|baz)
                # token_value is (None, [branch1_tokens, branch2_tokens, ...])
                _, branches = token_value
                # We'll create a single rule that expands to sub-rules joined by '|'
                union_rule = new_rule_name("UNION")
                union_expansion_variants = []
                for b_tokens in branches:
                    # each branch is a separate list of tokens
                    b_rule = handle_token_list(b_tokens)
                    union_expansion_variants.append(b_rule)
                
                # In your grammar, a union is <regex>|<concat>, so we produce expansions that combine with '|'
                # We'll do a single expansion that references each branch separated by '|'
                # But The Fuzzing Book expects expansions as separate lines, e.g. 
                #   union_rule -> b_rule1 | b_rule2 | ...
                # So let's do that:
                grammar[union_rule] = [" | ".join(union_expansion_variants)]
                
                # Alternatively, to produce multiple expansions, each referencing one branch, we could do:
                # grammar[union_rule] = union_expansion_variants
                # but that differs from your original approach of single <regex> -> <regex>|<concat> or <concat>.
                
                expansion_parts.append(union_rule)
            
            elif token_type == sre_parse.MAX_REPEAT:
                # e.g. (min_count, max_count, sub_tokens)
                (min_count, max_count, sub_tokens) = token_value
                repeated_sub_rule = handle_token_list(sub_tokens)
                
                # We check if (min_count, max_count) matches star (0,∞), plus (1,∞), or exact?
                if min_count == 0 and max_count == sre_parse.MAXREPEAT:
                    # star
                    # in your grammar: <basic> -> <elementary>*
                    # let's produce a new rule that references repeated_sub_rule with '*'
                    star_rule = new_rule_name("STAR")
                    grammar[star_rule] = [f"{repeated_sub_rule}*"]
                    expansion_parts.append(star_rule)
                elif min_count == 1 and max_count == sre_parse.MAXREPEAT:
                    # plus
                    plus_rule = new_rule_name("PLUS")
                    grammar[plus_rule] = [f"{repeated_sub_rule}+"]
                    expansion_parts.append(plus_rule)
                else:
                    # For now, handle other ranges or exact repeats in a simplistic way.
                    # e.g. a{2,4}, or a?
                    # We'll produce an expansion that duplicates repeated_sub_rule
                    # a certain minimal number of times, or allow a small range.
                    # In your grammar, you only had star, plus (and implicitly single).
                    # So let's do a short approximation:
                    
                    # If (min_count, max_count) = (0, 1), interpret as optional => sub_rule?
                    # But your original grammar doesn't have '?'. We'll produce expansions for 0 times or 1 time, etc.
                    
                    # We'll clamp extremely large max_count to 4 for demonstration:
                    if max_count > 4 and max_count != sre_parse.MAXREPEAT:
                        max_count = 4
                    
                    multi_rule = new_rule_name("MULTI")
                    expansions: List[Expansion] = []
                    for repeat_count in range(min_count, max_count+1):
                        expansions.append(repeated_sub_rule * repeat_count)  
                        # e.g. if repeated_sub_rule = <CONCAT_3> and repeat_count=3,
                        # expansions -> ["<CONCAT_3><CONCAT_3><CONCAT_3>"]
                    
                    if not expansions:
                        expansions = [""]  # if min_count=0, we can produce empty string
                    grammar[multi_rule] = expansions  # Keep using strings directly
                    expansion_parts.append(multi_rule)
            
            elif token_type == sre_parse.AT:
                # Usually AT is start/end of string anchors.
                # If it's AT_END, that means '$'
                if token_value == sre_parse.AT_END:
                    expansion_parts.append("$")  # in your grammar, <eos> -> "$"
                # If needed, handle ^ or others similarly.
                # In your original grammar, you haven't shown ^, but you can add it:
                elif token_value == sre_parse.AT_BEGINNING:
                    expansion_parts.append("^")
                else:
                    # skip or handle other anchors
                    pass
            else:
                # skip or handle other tokens (e.g. CATEGORY, GROUPREF, etc.)
                pass
        
        # Now we have expansion_parts, a list of references or literal chars that represent
        # this concatenation. We'll define grammar[rule_name] as a single expansion that concatenates them.
        grammar[rule_name] = ["".join(expansion_parts)]
        return rule_name

    def handle_in(token_list_in: List[Tuple[Any, Any]]) -> str:
        """
        Convert a list of tokens representing a character set or bracket expression
        into a rule that yields something like [<set_items>] or [^<set_items>].
        """
        negate = False
        items: List[Tuple[str, str]] = []  # (RANGE, 'a-z') or (CHAR, 'x') ...
        
        # token_list_in might look like: [(LITERAL, 97), (RANGE, (98, 122)), (NEGATE, None)], etc.
        
        for (op, val) in token_list_in:
            if op == sre_parse.NEGATE:
                negate = True
            elif op == sre_parse.LITERAL:
                items.append(("CHAR", chr(val)))
            elif op == sre_parse.RANGE:
                # e.g. val = (97, 122) => 'a'..'z'
                start, end = val
                items.append(("RANGE", f"{chr(start)}-{chr(end)}"))
            # Could handle other op types if needed (e.g., CATEGORY)
        
        set_rule_name = new_rule_name("SET")
        
        # We'll create a separate rule for <set_items> that enumerates each item
        # e.g. <SETITEMS_1> -> <SETITEM_1><SETITEMS_1> | <SETITEM_1>
        # but for simplicity, we can produce a single expansion that lumps them together.
        # Something like "[abc0-9]" or "[^abc0-9]".
        # We'll build a string that enumerates them. e.g. 'abc0-9'
        item_strs = []
        for (kind, s) in items:
            if kind == "CHAR":
                item_strs.append(s)
            elif kind == "RANGE":
                item_strs.append(s)  # e.g. "a-z"
        
        set_contents = "".join(item_strs) if item_strs else "xyz"  # fallback if empty
        # If your grammar wants <range> expansions separately, you can break these out further.
        
        if negate:
            grammar[set_rule_name] = [f"[^{set_contents}]"]
        else:
            grammar[set_rule_name] = [f"[{set_contents}]"]
        
        return set_rule_name

    # Build expansions for the top-level rule
    parse_token_list = handle_token_list  # rename for clarity
    top_expansion_rule = parse_token_list(parsed_tokens)
    # In your original grammar, <start> -> <regex>. We'll map <start> to that top_expansion_rule:
    grammar[top_rule] = [top_expansion_rule]
    return grammar
