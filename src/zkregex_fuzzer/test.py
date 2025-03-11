def extract_parts(s):
    result = []
    current_part = []
    in_brackets = False
    in_parentheses = False

    for char in s:
        # Detect start of brackets
        if char == "[":
            if current_part:
                result.append("".join(current_part))
                current_part = []
            in_brackets = True

        elif char == "]":
            current_part.append(char)
            result.append("".join(current_part))
            current_part = []
            in_brackets = False
            continue

        # Detect start of parentheses
        elif char == "(":
            if current_part:
                result.append("".join(current_part))
                current_part = []
            in_parentheses = True

        elif char == ")":
            current_part.append(char)
            result.append("".join(current_part))
            current_part = []
            in_parentheses = False
            continue

        # Capture characters inside brackets/parentheses
        if in_brackets or in_parentheses:
            current_part.append(char)
        # Capture outside text
        elif char.isalnum() or char in "_ ":
            current_part.append(char)
        elif current_part:
            result.append("".join(current_part))
            current_part = []

    # Add last captured part if any
    if current_part:
        result.append("".join(current_part))

    return result


# Example Usage
test_string = "(abc)xyz [hello] 123-world"
print(extract_parts(test_string))
