# Sublime Malware Research Tool
This is a Plugin for Sublime Text 3 to provide a number of commonly used tools related to malware analysis and research.  The original version for Sublime Text 2 can be found in the SublimeText2 branch, but it is unlikely development will continue on that branch.

## Installation
Recommended installation is to git clone into the Packages directory of Sublime Text 3

## Prerequisites
You must have libmagic installed for the PE related functions.

Examples:

OSX: `brew install libmagic`

Windows: https://github.com/pidydx/libmagicwin64

## Current Commands
- SMRT: Unix Timestamp From Int
- SMRT: Base64 Encode
- SMRT: Base32 Encode
- SMRT: Base64 Decode
- SMRT: Base32 Decode
- SMRT: Rot13 Encode
- SMRT: RotX Encode (Prompts for integer distance to rotate text)
- SMRT: Swap Char (prompts for substitution map in Xx:Yy format)
- SMRT: MD5
- SMRT: SHA1
- SMRT: SHA256
- SMRT: Hex to Int 
- SMRT: Int to Hex
- SMRT: Byte Format Hex
- SMRT: Word Format Hex
- SMRT: DWord Format Hex
- SMRT: Base64 Encode Binary
- SMRT: Base64 Decode Binary
- SMRT: Hex Encode ASCII
- SMRT: Hex Encode UTF-8
- SMRT: Hex Encode UTF-16
- SMRT: Hex Decode ASCII
- SMRT: Hex Decode UTF-8
- SMRT: Hex Decode UTF-16
- SMRT: Zlib Decompress Binary (Expects Hex Text)
- SMRT: Zlib Compress Binary (Expects Hex Text)
- SMRT: Gzip Decompress Binary (Expects Hex Text)
- SMRT: Gzip Compress Binary (Expects Hex Text)
- SMRT: INFLATE Binary (Expects Hex Text)
- SMRT: DEFLATE Binary (Expects Hex Text)
- SMRT: URL Quote
- SMRT: URL Unquote
- SMRT: NBO Int to IP
- SMRT: HBO Int to IP
- SMRT: IP to NBO Int
- SMRT: IP to HBO Int
- SMRT: Switch Endianness (Expects Hex Text)
- SMRT: PE Scanner (Expects Hex Text)
- SMRT: Apply XOR (Prompts for hex key or range. Examples: FF, 00-FF, DEAD, 0000-FFFF)
- SMRT: Apply XOR Skip Zero and Key (Prompts for hex key or range. Examples: FF, 00-FF, DEAD, 0000-FFFF)
- SMRT: Binary Text to Hex (Expects string of 1's and 0's)
- SMRT: Int to Alpha (Converts 1->A, 2->B, 3->C, etc. Expects ints 1-26 separated by spaces)
- SMRT: Alpha to Int (Converts Aa->1, Bb->2, Cc->3, etc. Expects upper/lower alpha a-z)

## Coming Soon

- Find PE in Hex
- Brute Force XOR Find PE in Hex
- Custom BaseXX Encode/Decodes
- Hex Math (ADD,SUB,NEG,INV,ROR,ROL)
- Int Math (ADD,SUB,MULT,DIV)
- Mail Extraction
- Strings on PE
- Magic on data
