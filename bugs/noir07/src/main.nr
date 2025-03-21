mod regex;

global MAX_INPUT_SIZE: u32 = 600;


fn main(input: [u8; MAX_INPUT_SIZE]) -> pub [Field; MAX_INPUT_SIZE] {
    let matches = regex::regex_match(input);
    let substring = regex::extract_substring::<MAX_INPUT_SIZE, MAX_INPUT_SIZE>(matches.get(0), input);
    let mut result: [Field; MAX_INPUT_SIZE] = [0; MAX_INPUT_SIZE];
    for i in 0..MAX_INPUT_SIZE {
        let r = substring.get_unchecked(i);
        result[i] = Field::from(r);
    }
    print("output: ");
    println(result);
    result
}
