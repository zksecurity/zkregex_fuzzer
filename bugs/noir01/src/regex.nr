


global table: [Field; 768] = comptime { make_lookup_table() };

comptime fn make_lookup_table() -> [Field; 768] {
    let mut table = [0; 768];
        table[0 * 256 + 255] = 1;
    table[1 * 256 + 48] = 2;
    table[1 * 256 + 49] = 2;
    table[1 * 256 + 50] = 2;
    table[1 * 256 + 51] = 2;
    table[1 * 256 + 52] = 2;
    table[1 * 256 + 53] = 2;
    table[1 * 256 + 54] = 2;
    table[1 * 256 + 55] = 2;
    table[1 * 256 + 56] = 2;
    table[1 * 256 + 57] = 2;
    table[2 * 256 + 48] = 2;
    table[2 * 256 + 49] = 2;
    table[2 * 256 + 50] = 2;
    table[2 * 256 + 51] = 2;
    table[2 * 256 + 52] = 2;
    table[2 * 256 + 53] = 2;
    table[2 * 256 + 54] = 2;
    table[2 * 256 + 55] = 2;
    table[2 * 256 + 56] = 2;
    table[2 * 256 + 57] = 2;

    table
}


pub fn regex_match<let N: u32>(input: [u8; N]) -> BoundedVec<Sequence, 0> {
    let substrings = unsafe { __regex_match(input) };
    
    // "Previous" state
    let mut s: Field = 0;
    s = table[255];
    // "Next"/upcoming state
    let mut s_next: Field = 0;
    let mut start_range = 0;
    let mut end_range = 0;

    // check the match
    for i in 0..N {
        // state transition
        let temp = input[i] as Field;
        s_next = table[s * 256 + temp];
        let potential_s_next = table[temp];
        if s_next == 0 {
            s = 0;
            s_next = potential_s_next;
        }
        std::as_witness(s_next);

        // range conditions for substring matches
        if ((start_range == 0) & (end_range == 0)) {
            start_range = i as Field;
        }
        if (((s == 2) & (s_next == 2)) & (end_range == 0)) {
            end_range = i as Field + 1;
        }
        



        let substring_range_check = []
            .all(|case| case == true);
    
        assert(substring_range_check, "substr array ranges wrong");
                
    
        s = s_next;
    }
    // check final state
    
    assert((s == 2), "Match not found");
            
    // constrain extracted substrings to be in match range
    //let full_match = Sequence::new(start_range as u32, end_range as u32 - start_range as u32);
    //let full_match_end = full_match.end();
    // for i in 0..0 {
    //     let substring = substrings.get_unchecked(i);
    //     let is_not_valid = i >= substrings.len();
    //     let index_check = substring.index >= full_match.index;
    //     let length_check = substring.end() <= full_match_end;
    //     let check = (index_check) | is_not_valid;
    //     assert(check, f"Substring {i} range is out of bounds of the full match found");
    // }
    substrings
}
    

pub unconstrained fn __regex_match<let N: u32>(input: [u8; N]) ->  BoundedVec<Sequence, 0> {
    // regex: ^[0-9]+$
    let mut substrings: BoundedVec<Sequence, 0> = BoundedVec::new();
    let mut current_substring = Sequence::default();
    let mut full_match = Sequence::default();

    // "Previous" state
    let mut s: Field = 0;
    s = table[255];
    // "Next"/upcoming state
    let mut s_next: Field = 0;

    let mut consecutive_substr = 0;
    let mut complete = false;

    for i in 0..input.len() {
        let temp = input[i] as Field;
        let mut reset = false;
        s_next = table[s * 256 + temp];
        let potential_s_next = table[temp];
        if s_next == 0 {
            reset = true;
            s = 0;
            s_next = potential_s_next;
        }
        // If a substring was in the making, but the state was reset
        // we disregard previous progress because apparently it is invalid
        if (reset & (consecutive_substr == 1)) {
            current_substring = Sequence::default();
            consecutive_substr = 0;
        }
        // Fill up substrings

         else if ((consecutive_substr == 1) & (s_next == 0)) {
            current_substring = Sequence::default();
            full_match = Sequence::default();
            substrings = BoundedVec::new();
            consecutive_substr = 0;
        } else if (s == 2) & (s_next == 2) {
            full_match.length = i - full_match.index + 1;
            complete = true;
        } else if (consecutive_substr == 1) {
            // The substring is done so "save" it
            substrings.push(current_substring);
            // reset the substring holder for next use
            current_substring = Sequence::default();
            consecutive_substr = 0;
        }
        s = s_next;
        if complete == true {
            break;
        }
    }
    assert((s == 2), f"no match: {s}");
    // Add pending substring that hasn't been added
    if consecutive_substr == 1 {
        substrings.push(current_substring);
        full_match.length = input.len() - full_match.index;
    }

    

    substrings
}
    
            
        

    
// points to a seque
pub struct Sequence {
    index: u32,
    length: u32,
    end: u32
}

impl Sequence {
    pub fn new(index: u32, length: u32) -> Self {
        Self { index, length, end: index + length }
    }

    pub fn default() -> Self {
        Self { index: 0, length: 0, end: 0 }
    }

    pub fn initialized(self) -> bool {
        self.length > 0
    }

    pub fn index(self) -> u32 {
        self.index
    }

    pub fn length(self) -> u32 {
        self.length
    }

    pub fn end(self) -> u32 {
        self.end
    }

    pub fn in_range(self, index: u32) -> bool {
        // if index + length == 0, index < self.end implicitly returns false if uninitialized
        index >= self.index & index < self.end
    }
}

    
/**
 * Extracts all substrings from a pattern match
 * @dev not super optimal - all substrings will be assumed to be of the length of longest substring.
 *      often this will be the size of the input. Use at discretion.
 * 
 * @param input - the input array to extract from
 * @param sequences - the sequences to extract from the input
 * @returns the extracted substrings
 */
pub fn extract_all_substrings<
    let INPUT_LENGTH: u32,
    let NUM_SUBSTRINGS: u32,
    let MAX_SUBSTRING_LENGTH: u32
>(
    input: [u8; INPUT_LENGTH],
    sequences: BoundedVec<Sequence, NUM_SUBSTRINGS>,
) -> BoundedVec<BoundedVec<u8, MAX_SUBSTRING_LENGTH>, NUM_SUBSTRINGS> {{
    let mut substrings: BoundedVec<BoundedVec<u8, MAX_SUBSTRING_LENGTH>, NUM_SUBSTRINGS> = BoundedVec::new();
    for i in 0..NUM_SUBSTRINGS {{
        let substring = sequences.get_unchecked(i);
        let mut extracted_substring = extract_substring(substring, input);
        let mut len = substrings.len() + 1;
        if i >= sequences.len() {{
            extracted_substring = BoundedVec::new();
            len = substrings.len();
        }}
        substrings.len = len;
        substrings.storage[i] = extracted_substring;
    }}
    substrings
}}

/**
 * Optimized algorithm for extracting a subsequence from an input array
 * 
 * @param substring_sequence - the sequence to extract from the input
 * @param input - the input array to extract from
 * @returns the extracted subsequence
 */
pub fn extract_substring<let INPUT_LENGTH: u32, let MAX_SUBSTRING_LENGTH: u32>(
    substring_sequence: Sequence,
    input: [u8; INPUT_LENGTH],
) -> BoundedVec<u8, MAX_SUBSTRING_LENGTH> {
    let mut substring: BoundedVec<u8, MAX_SUBSTRING_LENGTH> = unsafe { __extract_substring(substring_sequence, input) };
    assert(substring_sequence.length == substring.len(), "length mismatch");
    for i in 0..MAX_SUBSTRING_LENGTH {
        // hack for index to never exceed array bounds
        // must be constrained to be true when matching is required to prevent 0's passing when shouldn't
        // @dev while this adds constraints in worse case it can be more efficient if MAX_SUBSTRING_LENGTH < INPUT_LENGTH
        let input_range_check = substring_sequence.index + i < INPUT_LENGTH;
        let index = (substring_sequence.index + i) as Field * input_range_check as Field;

        // range where input should match substring
        let sequence_range_check = i >= substring_sequence.length;
        
        // constrain array construction if in range
        let expected_byte = input[index];
        let byte = substring.get_unchecked(i);
        let matched = (expected_byte as Field == byte as Field);
        assert(matched | sequence_range_check, "incorrect substring construction");
    }
    substring
}

/**
 * Unconstrained helper to build the extracted substring
 * @dev must be checked by extract_substring to constrain construction of substring
 * 
 * @param substring_sequence - the sequence to extract from the input
 * @param input - the input array to extract from
 * @returns the extracted subsequence
 */
unconstrained fn __extract_substring<let INPUT_LENGTH: u32, let MAX_SUBSTRING_LENGTH: u32>(
    substring_sequence: Sequence,
    input: [u8; INPUT_LENGTH],
) -> BoundedVec<u8, MAX_SUBSTRING_LENGTH> {
    let mut substring: BoundedVec<u8, MAX_SUBSTRING_LENGTH> = BoundedVec::new();
    for i in 0..substring_sequence.length {
        let byte = input[substring_sequence.index + i];
        substring.push(byte);
    }
    substring
}
    
    
// pub fn mask_input<let INPUT_LENGTH: u32, let MAX_SUBSTRING_LENGTH: u32>(
//     substring_sequences: BoundedVec<Sequence, MAX_SUBSTRING_LENGTH>,
//     input: [u8; INPUT_LENGTH],
// ) -> [u8; INPUT_LENGTH] {
//     let masked: [u8; INPUT_LENGTH] = unsafe { __mask_input(substring_sequences, input) };
//     for i in 0..INPUT_LENGTH {
//         let any_in_range = substring_sequences
//             .storage()
//             .any(|sequence: Sequence| sequence.in_range(i));
//         let expected_byte = input[i] as Field * any_in_range as Field;
//         assert(masked[i] as Field == expected_byte, "Incorrect masking");
//     }
//     masked
// }

unconstrained fn __mask_input<let INPUT_LENGTH: u32, let MAX_SUBSTRING_LENGTH: u32>(
    substring_sequences: BoundedVec<Sequence, MAX_SUBSTRING_LENGTH>,
    input: [u8; INPUT_LENGTH],
) -> [u8; INPUT_LENGTH] {
    let mut masked_input: [u8; INPUT_LENGTH] = [0; INPUT_LENGTH];
    for i in 0..substring_sequences.len() {
        let sequence = substring_sequences.get_unchecked(i);
        for j in sequence.index..sequence.end() {
            masked_input[j] = input[j];
        }
    }
    masked_input
}

    
/**
 * Optimized reversal of a BoundedVector with preservation of 0-padding at end
 * 
 * @param input - the input vector to reverse
 * @returns the reversed vector
 */
fn reverse_vec<let N: u32>(input: BoundedVec<u8, N>) -> BoundedVec<u8, N> {
    let mut reversed = unsafe { __reverse_vec(input) };
    for i in 0..N {
        let in_range = (i < reversed.len()) as Field;
        // if in range choose opposite index, otherwise choose same index to check 0's
        // yeah I know this is ugly show me a more efficient version and I'll use it
        let index = (((input.len() as Field) - (i as Field * in_range) - 1) * in_range as Field + (i as Field * (1 - in_range))) as Field;
        let expected_byte = input.get_unchecked(index as u32) as Field * in_range as Field;
        let byte = reversed.get_unchecked(i) as Field;
        assert(byte == expected_byte, "Incorrect reverse");
    }
    reversed
}

/**
 * Unconstrained helper to build the reversed vector without using mutable RAM tables
 * @dev SHOULD NOT BE CALLED BY ANYTHING EXCEPT `reverse_vec`
 * 
 * @param input - the input vector to reverse
 * @output - the reversed vector
 **/
unconstrained fn __reverse_vec<let N: u32>(input: BoundedVec<u8, N>) -> BoundedVec<u8, N> {
    let mut reversed: BoundedVec<u8, N> = BoundedVec::new();
    for i in 0..input.len() {
        reversed.push(input.get(input.len() - i - 1));
    }
    reversed
}

    
            