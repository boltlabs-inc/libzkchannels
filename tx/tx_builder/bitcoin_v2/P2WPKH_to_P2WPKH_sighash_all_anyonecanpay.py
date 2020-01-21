# p2wpkh input
# This has been tested and works

import argparse
import hashlib
import ecdsa
import sys

def dSHA256(data):
    hash_1 = hashlib.sha256(data).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    return hash_2

def hash160(s):
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def privkey_to_pubkey(privkey):
    signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()

    x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32] # The first 32 bytes are the x coordinate
    y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:] # The last 32 bytes are the y coordinate
    if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0: # We need to turn the y_cor into a number.
        public_key = bytes.fromhex("02" + x_cor.hex())
    else:
        public_key = bytes.fromhex("03" + x_cor.hex())
    return public_key

def pop_first_n(string, n):
    '''Return first n bytes of my_list in "popped", and remove from "string
    used in parse_tx function"'''
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
    parsed["input_outpoint"] = (
        txid_little
        + index_little
        )
    parsed["scriptSig"] = (
        len_scriptSig
        + scriptSig
        )
    parsed["sequence"] = sequence_little
    parsed["tx_out_count"] = tx_out_count
    parsed["output"] = (
        output_value_little
        + len_outputs
        + output_script
        )
    parsed["witness"] = witness
    parsed["locktime_little"] = locktime_little

    return parsed

parser = argparse.ArgumentParser()

# debug on to print full tx details
parser.add_argument("--debug", "-db", action='store_true', help="debug mode: print out all tx details")

parser.add_argument("--txid_str", "-tx", help="txid of input as string")
parser.add_argument("--index", "-ind", help="index of outpoint")
parser.add_argument("--input_amount_btc", "-a", help="amount of btc in")
parser.add_argument("--privkey", "-sk", help="private key of outpoint as hex string")
parser.add_argument("--sighash_type", "-sh", help="sighash type for signatures")
parser.add_argument("--output_value_btc", "-o", help="btc to output")
parser.add_argument("--payout_pubkey", "-opk", help="pubkey of output as hex string")

parser.add_argument("--merch_close_tx", "-mct", help="signed (with sighash 0x83) merch close tx. note, this could also be made to work with unsigned tx")

# parser.add_argument("--privkey", "-sk", help="private key of outpoint as hex string")
# parser.add_argument("--txid", "-tx", help="txid of outpoint as hex string")
# parser.add_argument("--index", "-ind", help="index of outpoint")
# parser.add_argument("--payout_pubkey", "-opk", help="pubkey of output as hex string")
# parser.add_argument("--output_value_btc", "-o", help="btc to output")
args = parser.parse_args()

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) < 5:
    txID_str = "1222222222222222222222222222222233333333333333333333333333333333"
    tx_index = 0
    input_amount_sat = int(float(2.0) * 100000000)
    privkey = bytes.fromhex("7911111111111111111111111111111111111111111111111111111111111111")
    input_pubkey = privkey_to_pubkey(privkey)
    sighash_type = bytes.fromhex("83")
    output_value_sat = int(float(2.0) * 100000000)
    payout_pubkey = bytes.fromhex("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")

    merch_close_tx = bytes.fromhex("02000000000101618881a938db8e7e8ad5048fe054076ddddea97b1da71ca0586d279a225d15610000000000ffffffff0100c2eb0b00000000220020c3fae9ae705465ac132b128c84fc011be28c21bff28e165f7cfb776dfbb117ff040047304402203e9792840c89c780fabb7bd479f6fb6a5ac4fc90472202fe7f9f06c6d80bcd0d02200fe0b6651317d23334155f980829dbc0141007d0c6ef2781e9e265b815d463f182463043022052b0d3293a9679a51fb04a4e2f1caacbb9808c93b33e27a7e7ebd4552d49fb61021f5803a87db267960aa83e8113e3addf703fcb50abc3af3d37b9224a8d1c10218247522102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce902103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae00000000")
else:
    txID_str = args.txid_str
    tx_index = int(args.index)
    input_amount_sat = int(float(args.input_amount_btc) * 100000000)
    privkey = bytes.fromhex(args.privkey)
    input_pubkey = privkey_to_pubkey(privkey)
    sighash_type = bytes.fromhex(args.sighash_type)
    output_value_sat = int(float(args.output_value_btc) * 100000000)
    payout_pubkey = bytes.fromhex(args.payout_pubkey)

    merch_close_tx = bytes.fromhex(args.merch_close_tx)

# These are hard coded tx variables
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")
sequence = bytes.fromhex("ffff ffff") # little endian?
locktime = bytes.fromhex("0000 0000") # little endian
tx_in_count = bytes.fromhex("01")
tx_out_count = bytes.fromhex("01")

# Convert txid, index, amounts, and to_self_delay to little endian
txid = (bytes.fromhex(txID_str))[::-1]
index = tx_index.to_bytes(4, byteorder="little", signed=False)
input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)
output_value = output_value_sat.to_bytes(8, byteorder="little", signed=True)

sighash = sighash_type + bytes.fromhex("00 00 00")
sighash_type_flag = sighash_type

merch_close_tx_dict = parse_tx(merch_close_tx)


# P2WPKH scriptPubKey
output_scriptPK = bytes.fromhex("0014") + hash160(payout_pubkey)

##########################################
# Put together the tx digest preimage

# if sighash is set to ANYONECANPAY (don't sign inputs):
if sighash_type.hex()[0] == "8":
    hashPrevOuts = (0).to_bytes(32, byteorder="little", signed=False)
    hashSequence = (0).to_bytes(32, byteorder="little", signed=False)
else:
    hashPrevOuts = dSHA256(merch_close_tx_dict["input_outpoint"] + txid + index)
    hashSequence = dSHA256(merch_close_tx_dict["sequence"] + sequence)

outputs = (
    output_value
    + (len(output_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output_scriptPK
)

# if sighash is set to NONE (don't sign outputs):
if sighash_type.hex()[1] == "2":
    hashOutputs = (0).to_bytes(32, byteorder="little", signed=False)
else:
    hashOutputs = dSHA256(merch_close_tx_dict["output"] + outputs)

locking_script = (
    bytes.fromhex("76 a9 14")
    + hash160(input_pubkey)
    + bytes.fromhex("88 ac")
)

scriptcode = (
    (len(locking_script)).to_bytes(1, byteorder="little", signed=False)
    + locking_script
)

tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + txid + index
    + scriptcode
    + input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)

tx_digest = dSHA256(tx_digest_preimage)

signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
signature = signing_key.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

witness = (
    # indicate the number of stack items for the txin
    # 2 items for signature and pubkey
    bytes.fromhex("02")

    # signature
    + (len(signature)+1).to_bytes(1, byteorder="little", signed=False)
    + signature
    + sighash_type_flag

    # public key
    + (len(input_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + input_pubkey
)

scriptSig = (
    bytes.fromhex("00") # length of empty scriptSig
)

final_tx = (
    version
    + marker
    + flag
    + tx_in_count
    + txid
    + index
    + scriptSig
    + sequence
    + tx_out_count
    + outputs
    + witness
    + locktime
)

print(final_tx.hex())


##########################################
# Print out tx digest details if debug flag was set
if args.debug:
# if 1:

    print("\ntx digest preimage")
    print(tx_digest_preimage.hex())

    print("\nbreakdown of tx digest preimage")
    print("version: ", version.hex())
    print("hashPrevOuts: ", hashPrevOuts.hex())
    print("hashSequence: ", hashSequence.hex())
    print("txid little endian: ",txid.hex())
    print("index: ",index.hex())
    print("scriptcode: ",scriptcode.hex())
    print("input_amount: ",input_amount.hex())
    print("sequence: ",sequence.hex())
    print("hashOutputs: ", hashOutputs.hex())
    print("locktime: ", locktime.hex())
    print("sighash: ",sighash.hex())

    # Calculate txid of the tx we have just created:
    # Convert to pre-segwit format, double sha256, reverse bytes (little endian)
    final_tx_legacy = (
        version
        + tx_in_count
        + txid
        + index
        + scriptSig
        + sequence
        + tx_out_count
        + outputs
        + locktime
    )

    new_txid = dSHA256(final_tx_legacy)[::-1]

    print("\nfinal_tx_legacy: ", final_tx_legacy.hex())
    print("\nDouble SHA256 final_tx_legacy: ", dSHA256(final_tx_legacy).hex())
    print("\ntxid of this tx: ",new_txid.hex())
