import sys

def pop_first_n(string, n):
    '''Return first n bytes of my_list in "popped", and remove from "string"'''
    popped = string[:n]
    string = string[n:]
    return (popped, string)

def parse_tx(tx):
    '''This function assumes only one input and one output'''
    # "little" is short for "little endian"
    version_little, tx = pop_first_n(tx, 4)
    marker, tx = pop_first_n(tx, 1)
    flag, tx = pop_first_n(tx, 1)
    tx_in_count, tx = pop_first_n(tx, 1)
    txid_little, tx = pop_first_n(tx, 32)
    index_little, tx = pop_first_n(tx, 4)
    len_scriptSig, tx = pop_first_n(tx, 1)
    scriptSig, tx = pop_first_n(tx, int.from_bytes(len_scriptSig, "big"))
    sequence_little, tx = pop_first_n(tx, 4)
    tx_out_count, tx = pop_first_n(tx, 1)
    output_value_little, tx = pop_first_n(tx, 8)
    len_outputs, tx = pop_first_n(tx, 1)
    output_script, tx = pop_first_n(tx, int.from_bytes(len_outputs, "big"))
    witness = tx[:-4]
    locktime_little = tx[-4:]

    # Create dict and convert everything to big endian
    parsed = {}
    parsed["version"] = version_little
    parsed["marker"] = marker
    parsed["flag"] = flag
    parsed["tx_in_count"] = tx_in_count
    parsed["input"] = (
        txid_little
        + index_little
        + len_scriptSig
        + scriptSig
        + sequence_little
        )
    parsed["tx_out_count"] = tx_out_count
    parsed["output"] = (
        output_value_little
        + len_outputs
        + output_script
        )
    parsed["witness"] = witness
    parsed["locktime_little"] = locktime_little

    return parsed
#
# input1 = "02000000000101958915d3aac24205c6cc25028cbe085ea7ea0ef629fc40e3f00f27d702f0226e0000000000ffffffff0100c2eb0b00000000220020c3fae9ae705465ac132b128c84fc011be28c21bff28e165f7cfb776dfbb117ff0400483045022100fd79510b6855b1d1a1b7a4161f7b06a2e2d6969c908eb6b0763960d4fbed019a0220221a9b26f801599878f11b638957fee967596eba7f6c805e79dc5a039628249c83473044022033059b525473cb8f8e41364e23bcb097f7216eac2d0a3ed702a0bbf849fbb33102203c5bf37cd367a2ad27092b13d36883ced4d7f44424c524cff19cd093cdb412cf8347522102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce902103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae00000000"
# tx1 = bytes.fromhex(input1)
#
# input2 = "02000000000101c693a5512a10938de1a070e8a2e7e8030641ed71ba42ce8e8207fd65725445870000000000ffffffff0100e1f505000000001600146a8cbbddc82aafb86a166ab0e2c464c3a5e8766b0247304402206c2c479fbd96c5ee3733f2aff6ae08af29fb907b0a76d6c1ed36860b989725d202205f517d733a506e220a3b830b965ad4519f53e73ccc297cf7fa37b275278d19c7832102c0947a47a59cb42316750ddd23d506d4c23ca997fbe40e9cb813970940501f4f00000000"
# tx2 = bytes.fromhex(input2)

tx1 = bytes.fromhex(sys.argv[1])
tx2 = bytes.fromhex(sys.argv[2])


tx1_dict = parse_tx(tx1)
tx2_dict = parse_tx(tx2)

final_tx = (
    tx1_dict["version"]
    + tx1_dict["marker"]
    + tx1_dict["flag"]

    # inputs
    + bytes.fromhex("02") # tx_in_count
    + tx1_dict["input"]
    + tx2_dict["input"]

    # outputs
    + bytes.fromhex("02") # tx_out_count
    + tx1_dict["output"]
    + tx2_dict["output"]

    # witness fields
    + tx1_dict["witness"]
    + tx2_dict["witness"]
    + tx1_dict["locktime_little"]
)

print(final_tx.hex())
