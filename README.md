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
- SMRT: RotX Encode
- SMRT: Swap Char
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
- SMRT: Zlib Decompress Binary
- SMRT: Zlib Compress Binary
- SMRT: Gzip Decompress Binary
- SMRT: Gzip Compress Binary
- SMRT: INFLATE Binary
- SMRT: DEFLATE Binary
- SMRT: URL Quote
- SMRT: URL Unquote
- SMRT: NBO Int to IP
- SMRT: HBO Int to IP
- SMRT: IP to NBO Int
- SMRT: IP to HBO Int
- SMRT: Switch Endianness
- SMRT: PE Scanner

## Coming Soon

- XOR Transforms (with 00 skips)
- Find PE in Hex
- Brute Force XOR Find PE in Hex
- Custom BaseXX Encode/Decodes
- Hex Math (ADD,SUB,NEG,INV,ROR,ROL)
- Int Math (ADD,SUB,MULT,DIV)
- Mail Extraction
- Strings on PE
- Magic
