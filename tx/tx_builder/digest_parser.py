# Parser for bitcoin segwit (bip 143) tx digest preimage
# Example usage:
# $ python digest_parser.py 02000000ac02275ebfba2212b1bba2e771f6a8cf85a9e2ea806
#    c62e688f5ede51af4b0773bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b7229079
#    5e70665044d1753c03046386ae78ae81a6c5f05442daaf1da9cc80bede07b0b2080ea9b4510
#    000000047522102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643
#    ce902103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752a
#    efff6cb3c00000000ffffffff621bb27a05ddf2402caa49842f91b382ef82232ccce455ab0a
#    74922fb850e2460000000001000000

import sys

preimage = bytes.fromhex(sys.argv[1])

def pop_first_n(my_list, n):
    '''Return first n bytes of my_list in "popped", and remove from "my_list"'''
    popped = my_list[:n]
    my_list = my_list[n:]
    return (popped, my_list)

# "little" is short for "little endian"
version_little, preimage = pop_first_n(preimage, 4)
hashPrevOuts, preimage = pop_first_n(preimage, 32)
hashSequence, preimage = pop_first_n(preimage, 32)
txid_little, preimage = pop_first_n(preimage, 32)
index_little, preimage = pop_first_n(preimage, 4)
scriptcode_len, preimage = pop_first_n(preimage, 1)
scriptcode, preimage = pop_first_n(preimage, int.from_bytes(scriptcode_len, "big"))
input_amount_little, preimage = pop_first_n(preimage, 8)
sequence_little, preimage = pop_first_n(preimage, 4)
hashOutputs, preimage = pop_first_n(preimage, 32)
locktime_little, preimage = pop_first_n(preimage, 4)
sighash_little, preimage = pop_first_n(preimage, 4)

# Create dict and convert everything to big endian
parsed = {}
parsed["version"] = version_little[::-1]
parsed["hashPrevOuts"] = hashPrevOuts
parsed["hashSequence"] = hashSequence
parsed["txid"] = txid_little[::-1]
parsed["index"] = index_little[::-1]
parsed["scriptcode_len"] = scriptcode_len
parsed["scriptcode"] = scriptcode
parsed["input_amount"] = input_amount_little[::-1]
parsed["sequence"] = sequence_little[::-1]
parsed["hashOutputs"] = hashOutputs
parsed["locktime"] = locktime_little[::-1]
parsed["sighash"] = sighash_little[::-1]

# Print out key value pairs
for i in parsed:
    if len(i) < 6:
        # two tabs if key name is short (< 6)
        print(i + ":\t\t", parsed[i].hex())
    else:
        print(i + ":\t", parsed[i].hex())
