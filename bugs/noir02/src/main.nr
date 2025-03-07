mod regex;

global MAX_INPUT_SIZE: u32 = 600;

fn main(input: [u8; MAX_INPUT_SIZE]) { regex::regex_match(input); }