# Parser for bitcoin segwit (bip 143) tx digest preimage
# Example usage:
# python digest_parser.py 02000000ac02275ebfba2212b1bba2e771f6a8cf85a9e2ea806c62e688f5ede51af4b0773bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044d1753c03046386ae78ae81a6c5f05442daaf1da9cc80bede07b0b2080ea9b4510000000047522102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce902103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752aefff6cb3c00000000ffffffff621bb27a05ddf2402caa49842f91b382ef82232ccce455ab0a74922fb850e2460000000001000000

import sys

# preimage = "02000000ac02275ebfba2212b1bba2e771f6a8cf85a9e2ea806c62e688f5ede51af4b0773bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044d1753c03046386ae78ae81a6c5f05442daaf1da9cc80bede07b0b2080ea9b4510000000047522102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce902103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752aefff6cb3c00000000ffffffff621bb27a05ddf2402caa49842f91b382ef82232ccce455ab0a74922fb850e2460000000001000000"
preimage = bytes.fromhex(sys.argv[1])

def pop_first_n(my_list, n):
    popped = my_list[:n]
    my_list = my_list[n:]
    return (popped, my_list)

def printhex(b):
    print(b.hex())

def show_vals(vals, name):
    print("Name:", name, "val:", vals[name])

version, preimage = pop_first_n(preimage, 4)
hashPrevOuts, preimage = pop_first_n(preimage, 32)
hashSequence, preimage = pop_first_n(preimage, 32)
txid_little_en, preimage = pop_first_n(preimage, 32)
index_little_en, preimage = pop_first_n(preimage, 4)
scriptcode_len, preimage = pop_first_n(preimage, 1)
scriptcode, preimage = pop_first_n(preimage, int.from_bytes(scriptcode_len, "big"))
input_amount_little_en, preimage = pop_first_n(preimage, 8)
sequence, preimage = pop_first_n(preimage, 4)
hashOutputs, preimage = pop_first_n(preimage, 32)
locktime, preimage = pop_first_n(preimage, 4)
sighash, preimage = pop_first_n(preimage, 4)

parsed = {}
parsed["version"] = version[::-1]
parsed["hashPrevOuts"] = hashPrevOuts
parsed["hashSequence"] = hashSequence
parsed["txid"] = txid_little_en[::-1]
parsed["index"] = index_little_en[::-1]
parsed["scriptcode_len"] = scriptcode_len
parsed["scriptcode"] = scriptcode
parsed["input_amount"] = input_amount_little_en[::-1]
parsed["sequence"] = sequence[::-1]
parsed["hashOutputs"] = hashOutputs
parsed["locktime"] = locktime[::-1]
parsed["sighash"] = sighash[::-1]

for i in parsed:
    if len(i) < 6:
        print(i + ":\t\t", parsed[i].hex())
    else:
        print(i + ":\t", parsed[i].hex())
