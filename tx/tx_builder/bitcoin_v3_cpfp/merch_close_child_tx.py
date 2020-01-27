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

parser = argparse.ArgumentParser()

# debug on to print full tx details
parser.add_argument("--debug", "-db", action='store_true', help="debug mode: print out all tx details")

parser.add_argument("--child_txid_str", "-chtx", help="txid of child input as string")
parser.add_argument("--child_index", "-cind", help="index of child outpoint")
parser.add_argument("--child_privkey", "-csk", help="private key of child outpoint as hex string")
parser.add_argument("--child_input_amount_btc", "-ca", help="amount of btc in from child")

parser.add_argument("--merch_txid_str", "-mtx", help="txid of merch input as string")
parser.add_argument("--merch_index", "-mind", help="index of merch outpoint")
parser.add_argument("--merch_privkey", "-msk", help="private key of merch outpoint as hex string")
parser.add_argument("--merch_input_amount_btc", "-ma", help="amount of btc in from merch")


parser.add_argument("--output_value_btc", "-o", help="btc to output")

parser.add_argument("--payout_pubkey", "-opk", help="pubkey of output as hex string")

# parser.add_argument("--privkey", "-sk", help="private key of outpoint as hex string")
# parser.add_argument("--txid", "-tx", help="txid of outpoint as hex string")
# parser.add_argument("--index", "-ind", help="index of outpoint")
# parser.add_argument("--payout_pubkey", "-opk", help="pubkey of output as hex string")
# parser.add_argument("--output_value_btc", "-o", help="btc to output")
args = parser.parse_args()

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) < 5:
    child_txID_str = "1222222222222222222222222222222233333333333333333333333333333333"
    child_tx_index = 0
    child_privkey = bytes.fromhex("7911111111111111111111111111111111111111111111111111111111111111")
    child_pubkey = privkey_to_pubkey(child_privkey)
    child_input_amount_sat = int(float(2.0) * 100000000)

    merch_txID_str = "3322222222222222222222222222222233333333333333333333333333333333"
    merch_tx_index = 0
    merch_privkey = bytes.fromhex("7933111111111111111111111111111111111111111111111111111111111111")
    merch_pubkey = privkey_to_pubkey(merch_privkey)
    merch_input_amount_sat = int(float(2.0) * 100000000)

    output_value_sat = int(float(2.0) * 100000000)

    payout_pubkey = bytes.fromhex("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")

else:
    child_txID_str = args.child_txid_str
    child_tx_index = int(args.child_index)
    child_privkey = bytes.fromhex(args.child_privkey)
    child_pubkey = privkey_to_pubkey(child_privkey)
    child_input_amount_sat = int(float(args.child_input_amount_btc) * 100000000)

    merch_txID_str = args.merch_txid_str
    merch_tx_index = int(args.merch_index)
    merch_privkey = bytes.fromhex(args.merch_privkey)
    merch_pubkey = privkey_to_pubkey(merch_privkey)
    merch_input_amount_sat = int(float(args.merch_input_amount_btc) * 100000000)

    output_value_sat = int(float(args.output_value_btc) * 100000000)

    payout_pubkey = bytes.fromhex(args.payout_pubkey)


# These are hard coded tx variables
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")
sequence = bytes.fromhex("ffff ffff")
locktime = bytes.fromhex("0000 0000")
sighash = bytes.fromhex("0100 0000")
sighash_type_flag = bytes.fromhex("01")
tx_in_count = bytes.fromhex("02")
tx_out_count = bytes.fromhex("01")

# Convert txid, index, amounts, and to_self_delay to little endian
child_txid = (bytes.fromhex(child_txID_str))[::-1]
child_index = child_tx_index.to_bytes(4, byteorder="little", signed=False)
child_input_amount = child_input_amount_sat.to_bytes(8, byteorder="little", signed=True)

merch_txid = (bytes.fromhex(merch_txID_str))[::-1]
merch_index = merch_tx_index.to_bytes(4, byteorder="little", signed=False)
merch_input_amount = merch_input_amount_sat.to_bytes(8, byteorder="little", signed=True)

output_value = output_value_sat.to_bytes(8, byteorder="little", signed=True)


# P2WPKH scriptPubKey
output_scriptPK = bytes.fromhex("0014") + hash160(payout_pubkey)

##########################################
# Put together the tx digest preimage

hashPrevOuts = dSHA256(
    child_txid
    + child_index
    + merch_txid
    + merch_index
)

hashSequence = dSHA256(sequence + sequence) # assuming both inputs have the same sequence value

outputs = (
    output_value
    + (len(output_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output_scriptPK
)

hashOutputs = dSHA256(outputs)


########## Create digest for child input signature
child_locking_script = (
    bytes.fromhex("76 a9 14")
    + hash160(child_pubkey)
    + bytes.fromhex("88 ac")
)

child_scriptcode = (
    (len(child_locking_script)).to_bytes(1, byteorder="little", signed=False)
    + child_locking_script
)

child_tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + child_txid
    + child_index
    + child_scriptcode
    + child_input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)

child_tx_digest = dSHA256(child_tx_digest_preimage)

child_signing_key = ecdsa.SigningKey.from_string(child_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
child_signature = child_signing_key.sign_digest(child_tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)


########## Create digest for merch input signature
merch_locking_script = (
    bytes.fromhex("76 a9 14")
    + hash160(merch_pubkey)
    + bytes.fromhex("88 ac")
)

merch_scriptcode = (
    (len(merch_locking_script)).to_bytes(1, byteorder="little", signed=False)
    + merch_locking_script
)

merch_tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + merch_txid
    + merch_index
    + merch_scriptcode
    + merch_input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)

merch_tx_digest = dSHA256(merch_tx_digest_preimage)

merch_signing_key = ecdsa.SigningKey.from_string(merch_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
merch_signature = merch_signing_key.sign_digest(merch_tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)


witness = (
    # indicate the number of stack items for the first input
    # 2 items for signature and pubkey
    bytes.fromhex("02")

    # child signature
    + (len(child_signature)+1).to_bytes(1, byteorder="little", signed=False)
    + child_signature
    + sighash_type_flag

    # child public key
    + (len(child_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + child_pubkey

    # Number of stack items for the second input
    + bytes.fromhex("02")

    # merch signature
    + (len(merch_signature)+1).to_bytes(1, byteorder="little", signed=False)
    + merch_signature
    + sighash_type_flag

    # merch public key
    + (len(merch_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + merch_pubkey
)

scriptSig = (
    bytes.fromhex("00") # length of empty scriptSig
)

child_input = (
    child_txid
    + child_index
    + scriptSig
    + sequence
)

merch_input = (
    merch_txid
    + merch_index
    + scriptSig
    + sequence
)

final_tx = (
    version
    + marker
    + flag
    + tx_in_count
    + child_input
    + merch_input
    + tx_out_count
    + outputs
    + witness
    + locktime
)

print(final_tx.hex())


##########################################
# Print out tx digest details if debug flag was set
if args.debug:

    print("\nchild_tx digest preimage")
    print(child_tx_digest_preimage.hex())

    print("\nmerch_tx digest preimage")
    print(merch_tx_digest_preimage.hex())

    print("\nbreakdown of tx digest preimage")
    print("version: ", version.hex())
    print("hashPrevOuts: ", hashPrevOuts.hex())
    print("hashSequence: ", hashSequence.hex())
    print("child_txid little endian: ",child_txid.hex())
    print("child_index: ",child_index.hex())
    print("child_scriptcode: ",child_scriptcode.hex())
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
        + child_input
        + merch_input
        + tx_out_count
        + outputs
        + locktime
    )

    new_txid = dSHA256(final_tx_legacy)[::-1]

    print("\nfinal_tx_legacy: ", final_tx_legacy.hex())
    print("\nDouble SHA256 final_tx_legacy: ", dSHA256(final_tx_legacy).hex())
    print("\ntxid of this tx: ",new_txid.hex())
