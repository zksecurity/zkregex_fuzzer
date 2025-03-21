


global table: [Field; 512] = comptime { make_lookup_table() };

comptime fn make_lookup_table() -> [Field; 512] {
    let mut table = [0; 512];
        table[0 * 256 + 0] = 1;
    table[1 * 256 + 0] = 1;
    table[0 * 256 + 1] = 1;
    table[1 * 256 + 1] = 1;
    table[0 * 256 + 2] = 1;
    table[1 * 256 + 2] = 1;
    table[0 * 256 + 3] = 1;
    table[1 * 256 + 3] = 1;
    table[0 * 256 + 4] = 1;
    table[1 * 256 + 4] = 1;
    table[0 * 256 + 5] = 1;
    table[1 * 256 + 5] = 1;
    table[0 * 256 + 6] = 1;
    table[1 * 256 + 6] = 1;
    table[0 * 256 + 7] = 1;
    table[1 * 256 + 7] = 1;
    table[0 * 256 + 8] = 1;
    table[1 * 256 + 8] = 1;
    table[0 * 256 + 9] = 1;
    table[1 * 256 + 9] = 1;
    table[0 * 256 + 10] = 1;
    table[1 * 256 + 10] = 1;
    table[0 * 256 + 11] = 1;
    table[1 * 256 + 11] = 1;
    table[0 * 256 + 12] = 1;
    table[1 * 256 + 12] = 1;
    table[0 * 256 + 13] = 1;
    table[1 * 256 + 13] = 1;
    table[0 * 256 + 14] = 1;
    table[1 * 256 + 14] = 1;
    table[0 * 256 + 15] = 1;
    table[1 * 256 + 15] = 1;
    table[0 * 256 + 16] = 1;
    table[1 * 256 + 16] = 1;
    table[0 * 256 + 17] = 1;
    table[1 * 256 + 17] = 1;
    table[0 * 256 + 18] = 1;
    table[1 * 256 + 18] = 1;
    table[0 * 256 + 19] = 1;
    table[1 * 256 + 19] = 1;
    table[0 * 256 + 20] = 1;
    table[1 * 256 + 20] = 1;
    table[0 * 256 + 21] = 1;
    table[1 * 256 + 21] = 1;
    table[0 * 256 + 22] = 1;
    table[1 * 256 + 22] = 1;
    table[0 * 256 + 23] = 1;
    table[1 * 256 + 23] = 1;
    table[0 * 256 + 24] = 1;
    table[1 * 256 + 24] = 1;
    table[0 * 256 + 25] = 1;
    table[1 * 256 + 25] = 1;
    table[0 * 256 + 26] = 1;
    table[1 * 256 + 26] = 1;
    table[0 * 256 + 27] = 1;
    table[1 * 256 + 27] = 1;
    table[0 * 256 + 28] = 1;
    table[1 * 256 + 28] = 1;
    table[0 * 256 + 29] = 1;
    table[1 * 256 + 29] = 1;
    table[0 * 256 + 30] = 1;
    table[1 * 256 + 30] = 1;
    table[0 * 256 + 31] = 1;
    table[1 * 256 + 31] = 1;
    table[0 * 256 + 32] = 1;
    table[1 * 256 + 32] = 1;
    table[0 * 256 + 33] = 1;
    table[1 * 256 + 33] = 1;
    table[0 * 256 + 34] = 1;
    table[1 * 256 + 34] = 1;
    table[0 * 256 + 35] = 1;
    table[1 * 256 + 35] = 1;
    table[0 * 256 + 36] = 1;
    table[1 * 256 + 36] = 1;
    table[0 * 256 + 37] = 1;
    table[1 * 256 + 37] = 1;
    table[0 * 256 + 38] = 1;
    table[1 * 256 + 38] = 1;
    table[0 * 256 + 39] = 1;
    table[1 * 256 + 39] = 1;
    table[0 * 256 + 40] = 1;
    table[1 * 256 + 40] = 1;
    table[0 * 256 + 41] = 1;
    table[1 * 256 + 41] = 1;
    table[0 * 256 + 42] = 1;
    table[1 * 256 + 42] = 1;
    table[0 * 256 + 43] = 1;
    table[1 * 256 + 43] = 1;
    table[0 * 256 + 44] = 1;
    table[1 * 256 + 44] = 1;
    table[0 * 256 + 45] = 1;
    table[1 * 256 + 45] = 1;
    table[0 * 256 + 46] = 1;
    table[1 * 256 + 46] = 1;
    table[0 * 256 + 47] = 1;
    table[1 * 256 + 47] = 1;
    table[0 * 256 + 48] = 1;
    table[1 * 256 + 48] = 1;
    table[0 * 256 + 49] = 1;
    table[1 * 256 + 49] = 1;
    table[0 * 256 + 50] = 1;
    table[1 * 256 + 50] = 1;
    table[0 * 256 + 51] = 1;
    table[1 * 256 + 51] = 1;
    table[0 * 256 + 52] = 1;
    table[1 * 256 + 52] = 1;
    table[0 * 256 + 53] = 1;
    table[1 * 256 + 53] = 1;
    table[0 * 256 + 54] = 1;
    table[1 * 256 + 54] = 1;
    table[0 * 256 + 55] = 1;
    table[1 * 256 + 55] = 1;
    table[0 * 256 + 56] = 1;
    table[1 * 256 + 56] = 1;
    table[0 * 256 + 57] = 1;
    table[1 * 256 + 57] = 1;
    table[0 * 256 + 58] = 1;
    table[1 * 256 + 58] = 1;
    table[0 * 256 + 59] = 1;
    table[1 * 256 + 59] = 1;
    table[0 * 256 + 60] = 1;
    table[1 * 256 + 60] = 1;
    table[0 * 256 + 61] = 1;
    table[1 * 256 + 61] = 1;
    table[0 * 256 + 62] = 1;
    table[1 * 256 + 62] = 1;
    table[0 * 256 + 63] = 1;
    table[1 * 256 + 63] = 1;
    table[0 * 256 + 64] = 1;
    table[1 * 256 + 64] = 1;
    table[0 * 256 + 65] = 1;
    table[1 * 256 + 65] = 1;
    table[0 * 256 + 66] = 1;
    table[1 * 256 + 66] = 1;
    table[0 * 256 + 67] = 1;
    table[1 * 256 + 67] = 1;
    table[0 * 256 + 68] = 1;
    table[1 * 256 + 68] = 1;
    table[0 * 256 + 69] = 1;
    table[1 * 256 + 69] = 1;
    table[0 * 256 + 70] = 1;
    table[1 * 256 + 70] = 1;
    table[0 * 256 + 71] = 1;
    table[1 * 256 + 71] = 1;
    table[0 * 256 + 72] = 1;
    table[1 * 256 + 72] = 1;
    table[0 * 256 + 73] = 1;
    table[1 * 256 + 73] = 1;
    table[0 * 256 + 74] = 1;
    table[1 * 256 + 74] = 1;
    table[0 * 256 + 75] = 1;
    table[1 * 256 + 75] = 1;
    table[0 * 256 + 76] = 1;
    table[1 * 256 + 76] = 1;
    table[0 * 256 + 77] = 1;
    table[1 * 256 + 77] = 1;
    table[0 * 256 + 78] = 1;
    table[1 * 256 + 78] = 1;
    table[0 * 256 + 79] = 1;
    table[1 * 256 + 79] = 1;
    table[0 * 256 + 80] = 1;
    table[1 * 256 + 80] = 1;
    table[0 * 256 + 81] = 1;
    table[1 * 256 + 81] = 1;
    table[0 * 256 + 82] = 1;
    table[1 * 256 + 82] = 1;
    table[0 * 256 + 83] = 1;
    table[1 * 256 + 83] = 1;
    table[0 * 256 + 84] = 1;
    table[1 * 256 + 84] = 1;
    table[0 * 256 + 85] = 1;
    table[1 * 256 + 85] = 1;
    table[0 * 256 + 86] = 1;
    table[1 * 256 + 86] = 1;
    table[0 * 256 + 87] = 1;
    table[1 * 256 + 87] = 1;
    table[0 * 256 + 88] = 1;
    table[1 * 256 + 88] = 1;
    table[0 * 256 + 89] = 1;
    table[1 * 256 + 89] = 1;
    table[0 * 256 + 90] = 1;
    table[1 * 256 + 90] = 1;
    table[0 * 256 + 91] = 1;
    table[1 * 256 + 91] = 1;
    table[0 * 256 + 92] = 1;
    table[1 * 256 + 92] = 1;
    table[0 * 256 + 93] = 1;
    table[1 * 256 + 93] = 1;
    table[0 * 256 + 94] = 1;
    table[1 * 256 + 94] = 1;
    table[0 * 256 + 95] = 1;
    table[1 * 256 + 95] = 1;
    table[0 * 256 + 96] = 1;
    table[1 * 256 + 96] = 1;
    table[0 * 256 + 97] = 1;
    table[1 * 256 + 97] = 1;
    table[0 * 256 + 98] = 1;
    table[1 * 256 + 98] = 1;
    table[0 * 256 + 99] = 1;
    table[1 * 256 + 99] = 1;
    table[0 * 256 + 100] = 1;
    table[1 * 256 + 100] = 1;
    table[0 * 256 + 101] = 1;
    table[1 * 256 + 101] = 1;
    table[0 * 256 + 102] = 1;
    table[1 * 256 + 102] = 1;
    table[0 * 256 + 103] = 1;
    table[1 * 256 + 103] = 1;
    table[0 * 256 + 104] = 1;
    table[1 * 256 + 104] = 1;
    table[0 * 256 + 105] = 1;
    table[1 * 256 + 105] = 1;
    table[0 * 256 + 106] = 1;
    table[1 * 256 + 106] = 1;
    table[0 * 256 + 107] = 1;
    table[1 * 256 + 107] = 1;
    table[0 * 256 + 108] = 1;
    table[1 * 256 + 108] = 1;
    table[0 * 256 + 109] = 1;
    table[1 * 256 + 109] = 1;
    table[0 * 256 + 110] = 1;
    table[1 * 256 + 110] = 1;
    table[0 * 256 + 111] = 1;
    table[1 * 256 + 111] = 1;
    table[0 * 256 + 112] = 1;
    table[1 * 256 + 112] = 1;
    table[0 * 256 + 113] = 1;
    table[1 * 256 + 113] = 1;
    table[0 * 256 + 114] = 1;
    table[1 * 256 + 114] = 1;
    table[0 * 256 + 115] = 1;
    table[1 * 256 + 115] = 1;
    table[0 * 256 + 116] = 1;
    table[1 * 256 + 116] = 1;
    table[0 * 256 + 117] = 1;
    table[1 * 256 + 117] = 1;
    table[0 * 256 + 118] = 1;
    table[1 * 256 + 118] = 1;
    table[0 * 256 + 119] = 1;
    table[1 * 256 + 119] = 1;
    table[0 * 256 + 120] = 1;
    table[1 * 256 + 120] = 1;
    table[0 * 256 + 121] = 1;
    table[1 * 256 + 121] = 1;
    table[0 * 256 + 122] = 1;
    table[1 * 256 + 122] = 1;
    table[0 * 256 + 123] = 1;
    table[1 * 256 + 123] = 1;
    table[0 * 256 + 124] = 1;
    table[1 * 256 + 124] = 1;
    table[0 * 256 + 125] = 1;
    table[1 * 256 + 125] = 1;
    table[0 * 256 + 126] = 1;
    table[1 * 256 + 126] = 1;
    table[0 * 256 + 127] = 1;
    table[1 * 256 + 127] = 1;
    table[0 * 256 + 128] = 1;
    table[1 * 256 + 128] = 1;
    table[0 * 256 + 129] = 1;
    table[1 * 256 + 129] = 1;
    table[0 * 256 + 130] = 1;
    table[1 * 256 + 130] = 1;
    table[0 * 256 + 131] = 1;
    table[1 * 256 + 131] = 1;
    table[0 * 256 + 132] = 1;
    table[1 * 256 + 132] = 1;
    table[0 * 256 + 133] = 1;
    table[1 * 256 + 133] = 1;
    table[0 * 256 + 134] = 1;
    table[1 * 256 + 134] = 1;
    table[0 * 256 + 135] = 1;
    table[1 * 256 + 135] = 1;
    table[0 * 256 + 136] = 1;
    table[1 * 256 + 136] = 1;
    table[0 * 256 + 137] = 1;
    table[1 * 256 + 137] = 1;
    table[0 * 256 + 138] = 1;
    table[1 * 256 + 138] = 1;
    table[0 * 256 + 139] = 1;
    table[1 * 256 + 139] = 1;
    table[0 * 256 + 140] = 1;
    table[1 * 256 + 140] = 1;
    table[0 * 256 + 141] = 1;
    table[1 * 256 + 141] = 1;
    table[0 * 256 + 142] = 1;
    table[1 * 256 + 142] = 1;
    table[0 * 256 + 143] = 1;
    table[1 * 256 + 143] = 1;
    table[0 * 256 + 144] = 1;
    table[1 * 256 + 144] = 1;
    table[0 * 256 + 145] = 1;
    table[1 * 256 + 145] = 1;
    table[0 * 256 + 146] = 1;
    table[1 * 256 + 146] = 1;
    table[0 * 256 + 147] = 1;
    table[1 * 256 + 147] = 1;
    table[0 * 256 + 148] = 1;
    table[1 * 256 + 148] = 1;
    table[0 * 256 + 149] = 1;
    table[1 * 256 + 149] = 1;
    table[0 * 256 + 150] = 1;
    table[1 * 256 + 150] = 1;
    table[0 * 256 + 151] = 1;
    table[1 * 256 + 151] = 1;
    table[0 * 256 + 152] = 1;
    table[1 * 256 + 152] = 1;
    table[0 * 256 + 153] = 1;
    table[1 * 256 + 153] = 1;
    table[0 * 256 + 154] = 1;
    table[1 * 256 + 154] = 1;
    table[0 * 256 + 155] = 1;
    table[1 * 256 + 155] = 1;
    table[0 * 256 + 156] = 1;
    table[1 * 256 + 156] = 1;
    table[0 * 256 + 157] = 1;
    table[1 * 256 + 157] = 1;
    table[0 * 256 + 158] = 1;
    table[1 * 256 + 158] = 1;
    table[0 * 256 + 159] = 1;
    table[1 * 256 + 159] = 1;
    table[0 * 256 + 160] = 1;
    table[1 * 256 + 160] = 1;
    table[0 * 256 + 161] = 1;
    table[1 * 256 + 161] = 1;
    table[0 * 256 + 162] = 1;
    table[1 * 256 + 162] = 1;
    table[0 * 256 + 163] = 1;
    table[1 * 256 + 163] = 1;
    table[0 * 256 + 164] = 1;
    table[1 * 256 + 164] = 1;
    table[0 * 256 + 165] = 1;
    table[1 * 256 + 165] = 1;
    table[0 * 256 + 166] = 1;
    table[1 * 256 + 166] = 1;
    table[0 * 256 + 167] = 1;
    table[1 * 256 + 167] = 1;
    table[0 * 256 + 168] = 1;
    table[1 * 256 + 168] = 1;
    table[0 * 256 + 169] = 1;
    table[1 * 256 + 169] = 1;
    table[0 * 256 + 170] = 1;
    table[1 * 256 + 170] = 1;
    table[0 * 256 + 171] = 1;
    table[1 * 256 + 171] = 1;
    table[0 * 256 + 172] = 1;
    table[1 * 256 + 172] = 1;
    table[0 * 256 + 173] = 1;
    table[1 * 256 + 173] = 1;
    table[0 * 256 + 174] = 1;
    table[1 * 256 + 174] = 1;
    table[0 * 256 + 175] = 1;
    table[1 * 256 + 175] = 1;
    table[0 * 256 + 176] = 1;
    table[1 * 256 + 176] = 1;
    table[0 * 256 + 177] = 1;
    table[1 * 256 + 177] = 1;
    table[0 * 256 + 178] = 1;
    table[1 * 256 + 178] = 1;
    table[0 * 256 + 179] = 1;
    table[1 * 256 + 179] = 1;
    table[0 * 256 + 180] = 1;
    table[1 * 256 + 180] = 1;
    table[0 * 256 + 181] = 1;
    table[1 * 256 + 181] = 1;
    table[0 * 256 + 182] = 1;
    table[1 * 256 + 182] = 1;
    table[0 * 256 + 183] = 1;
    table[1 * 256 + 183] = 1;
    table[0 * 256 + 184] = 1;
    table[1 * 256 + 184] = 1;
    table[0 * 256 + 185] = 1;
    table[1 * 256 + 185] = 1;
    table[0 * 256 + 186] = 1;
    table[1 * 256 + 186] = 1;
    table[0 * 256 + 187] = 1;
    table[1 * 256 + 187] = 1;
    table[0 * 256 + 188] = 1;
    table[1 * 256 + 188] = 1;
    table[0 * 256 + 189] = 1;
    table[1 * 256 + 189] = 1;
    table[0 * 256 + 190] = 1;
    table[1 * 256 + 190] = 1;
    table[0 * 256 + 191] = 1;
    table[1 * 256 + 191] = 1;
    table[0 * 256 + 192] = 1;
    table[1 * 256 + 192] = 1;
    table[0 * 256 + 193] = 1;
    table[1 * 256 + 193] = 1;
    table[0 * 256 + 194] = 1;
    table[1 * 256 + 194] = 1;
    table[0 * 256 + 195] = 1;
    table[1 * 256 + 195] = 1;
    table[0 * 256 + 196] = 1;
    table[1 * 256 + 196] = 1;
    table[0 * 256 + 197] = 1;
    table[1 * 256 + 197] = 1;
    table[0 * 256 + 198] = 1;
    table[1 * 256 + 198] = 1;
    table[0 * 256 + 199] = 1;
    table[1 * 256 + 199] = 1;
    table[0 * 256 + 200] = 1;
    table[1 * 256 + 200] = 1;
    table[0 * 256 + 201] = 1;
    table[1 * 256 + 201] = 1;
    table[0 * 256 + 202] = 1;
    table[1 * 256 + 202] = 1;
    table[0 * 256 + 203] = 1;
    table[1 * 256 + 203] = 1;
    table[0 * 256 + 204] = 1;
    table[1 * 256 + 204] = 1;
    table[0 * 256 + 205] = 1;
    table[1 * 256 + 205] = 1;
    table[0 * 256 + 206] = 1;
    table[1 * 256 + 206] = 1;
    table[0 * 256 + 207] = 1;
    table[1 * 256 + 207] = 1;
    table[0 * 256 + 208] = 1;
    table[1 * 256 + 208] = 1;
    table[0 * 256 + 209] = 1;
    table[1 * 256 + 209] = 1;
    table[0 * 256 + 210] = 1;
    table[1 * 256 + 210] = 1;
    table[0 * 256 + 211] = 1;
    table[1 * 256 + 211] = 1;
    table[0 * 256 + 212] = 1;
    table[1 * 256 + 212] = 1;
    table[0 * 256 + 213] = 1;
    table[1 * 256 + 213] = 1;
    table[0 * 256 + 214] = 1;
    table[1 * 256 + 214] = 1;
    table[0 * 256 + 215] = 1;
    table[1 * 256 + 215] = 1;
    table[0 * 256 + 216] = 1;
    table[1 * 256 + 216] = 1;
    table[0 * 256 + 217] = 1;
    table[1 * 256 + 217] = 1;
    table[0 * 256 + 218] = 1;
    table[1 * 256 + 218] = 1;
    table[0 * 256 + 219] = 1;
    table[1 * 256 + 219] = 1;
    table[0 * 256 + 220] = 1;
    table[1 * 256 + 220] = 1;
    table[0 * 256 + 221] = 1;
    table[1 * 256 + 221] = 1;
    table[0 * 256 + 222] = 1;
    table[1 * 256 + 222] = 1;
    table[0 * 256 + 223] = 1;
    table[1 * 256 + 223] = 1;
    table[0 * 256 + 224] = 1;
    table[1 * 256 + 224] = 1;
    table[0 * 256 + 225] = 1;
    table[1 * 256 + 225] = 1;
    table[0 * 256 + 226] = 1;
    table[1 * 256 + 226] = 1;
    table[0 * 256 + 227] = 1;
    table[1 * 256 + 227] = 1;
    table[0 * 256 + 228] = 1;
    table[1 * 256 + 228] = 1;
    table[0 * 256 + 229] = 1;
    table[1 * 256 + 229] = 1;
    table[0 * 256 + 230] = 1;
    table[1 * 256 + 230] = 1;
    table[0 * 256 + 231] = 1;
    table[1 * 256 + 231] = 1;
    table[0 * 256 + 232] = 1;
    table[1 * 256 + 232] = 1;
    table[0 * 256 + 233] = 1;
    table[1 * 256 + 233] = 1;
    table[0 * 256 + 234] = 1;
    table[1 * 256 + 234] = 1;
    table[0 * 256 + 235] = 1;
    table[1 * 256 + 235] = 1;
    table[0 * 256 + 236] = 1;
    table[1 * 256 + 236] = 1;
    table[0 * 256 + 237] = 1;
    table[1 * 256 + 237] = 1;
    table[0 * 256 + 238] = 1;
    table[1 * 256 + 238] = 1;
    table[0 * 256 + 239] = 1;
    table[1 * 256 + 239] = 1;
    table[0 * 256 + 240] = 1;
    table[1 * 256 + 240] = 1;
    table[0 * 256 + 241] = 1;
    table[1 * 256 + 241] = 1;
    table[0 * 256 + 242] = 1;
    table[1 * 256 + 242] = 1;
    table[0 * 256 + 243] = 1;
    table[1 * 256 + 243] = 1;
    table[0 * 256 + 244] = 1;
    table[1 * 256 + 244] = 1;
    table[0 * 256 + 245] = 1;
    table[1 * 256 + 245] = 1;
    table[0 * 256 + 246] = 1;
    table[1 * 256 + 246] = 1;
    table[0 * 256 + 247] = 1;
    table[1 * 256 + 247] = 1;
    table[0 * 256 + 248] = 1;
    table[1 * 256 + 248] = 1;
    table[0 * 256 + 249] = 1;
    table[1 * 256 + 249] = 1;
    table[0 * 256 + 250] = 1;
    table[1 * 256 + 250] = 1;
    table[0 * 256 + 251] = 1;
    table[1 * 256 + 251] = 1;
    table[0 * 256 + 252] = 1;
    table[1 * 256 + 252] = 1;
    table[0 * 256 + 253] = 1;
    table[1 * 256 + 253] = 1;
    table[0 * 256 + 254] = 1;
    table[1 * 256 + 254] = 1;
    table[0 * 256 + 53] = 0;

    table
}


pub fn regex_match<let N: u32>(input: [u8; N]) -> BoundedVec<Sequence, 1> {
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
        if (((s == 0) & (s_next == 1)) & (end_range == 0)) {
            end_range = i as Field + 1;
        }
        

        let range_0 = substrings.get_unchecked(0).in_range(i);
        let case_0 = [
            (s_next == 0) & ((s == 0))
        ].any(|case| case == true) | !range_0;



        let substring_range_check = [case_0]
            .all(|case| case == true);
    
        assert(substring_range_check, "substr array ranges wrong");
                
    
        s = s_next;
    }
    // check final state
    
    assert((s == 0) | (s == 1), "Match not found");
            
    // constrain extracted substrings to be in match range
    //let full_match = Sequence::new(start_range as u32, end_range as u32 - start_range as u32);
    //let full_match_end = full_match.end();
    // for i in 0..1 {
    //     let substring = substrings.get_unchecked(i);
    //     let is_not_valid = i >= substrings.len();
    //     let index_check = substring.index >= full_match.index;
    //     let length_check = substring.end() <= full_match_end;
    //     let check = (index_check) | is_not_valid;
    //     assert(check, f"Substring {i} range is out of bounds of the full match found");
    // }
    substrings
}
    

pub unconstrained fn __regex_match<let N: u32>(input: [u8; N]) ->  BoundedVec<Sequence, 1> {
    // regex: 5*
    let mut substrings: BoundedVec<Sequence, 1> = BoundedVec::new();
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


        if ((s == 0) & (s_next == 0)) {
    
            if (consecutive_substr == 0) {
            current_substring.index = i;
            };
            current_substring.length += 1;
            consecutive_substr = 1; 
        } else if ((consecutive_substr == 1) & (s_next == 0)) {
            current_substring = Sequence::default();
            full_match = Sequence::default();
            substrings = BoundedVec::new();
            consecutive_substr = 0;
        } else if (s == 0) & (s_next == 1) {
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
    assert((s == 0) | (s == 1), f"no match: {s}");
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

    
            