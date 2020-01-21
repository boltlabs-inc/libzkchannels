# Based on tutorial from:
# https://github.com/zeltsi/segwit_tutorial/tree/master/transactions

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

# tx details
parser.add_argument("--txid_str", "-tx", help="txid of input as string")
parser.add_argument("--index", "-ind", help="index of outpoint")
parser.add_argument("--input_amount_btc", "-a", help="amount of btc held by the previous outpoint")
parser.add_argument("--cust_privkey", "-csk", help="private key of customer for escrow")
parser.add_argument("--merch_privkey", "-msk", help="private key of merchant for escrow")
parser.add_argument("--sighash_type", "-sh", help="sighash type for signatures")
parser.add_argument("--output_value_btc", "-o", help="btc to output")
parser.add_argument("--merch_payout_pubkey", "-mcpk", help="public key of merchant close to-self output")
parser.add_argument("--to_self_delay", "-tsd", help="to_self_delay (in unit of blocks) for the merchant's to-self output")

args = parser.parse_args()

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) < 5:
    txID_str = "2222222222222222222222222222222233333333333333333333333333333333"
    tx_index = 0
    input_amount_sat = int(float(2.0) * 100000000)
    cust_privkey = bytes.fromhex("7911111111111111111111111111111111111111111111111111111111111111")
    merch_privkey = bytes.fromhex("3711111111111111111111111111111111111111111111111111111111111111")
    sighash_type = bytes.fromhex("82")
    output_value_sat = int(float(2.0) * 100000000)
    merch_payout_pubkey = bytes.fromhex("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")
    to_self_delay_big_e = bytes.fromhex("05cf")
else:
    txID_str = args.txid_str
    tx_index = int(args.index)
    input_amount_sat = int(float(args.input_amount_btc) * 100000000)
    cust_privkey = bytes.fromhex(args.cust_privkey)
    merch_privkey = bytes.fromhex(args.merch_privkey)
    sighash_type = bytes.fromhex(args.sighash_type)
    output_value_sat = int(float(args.output_value_btc) * 100000000)
    merch_payout_pubkey = bytes.fromhex(args.merch_payout_pubkey)
    to_self_delay_big_e = bytes.fromhex(args.to_self_delay)

# keys for the funding tx 2-of-2 multisig
merch_pubkey = privkey_to_pubkey(merch_privkey)
cust_pubkey = privkey_to_pubkey(cust_privkey)

# These are hard coded tx variables
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")
sequence = bytes.fromhex("ffffffff")
locktime = bytes.fromhex("0000 0000")
tx_in_count = bytes.fromhex("01")
tx_out_count = bytes.fromhex("01")

# Convert txid, index, amounts, and to_self_delay to little endian
txid = (bytes.fromhex(txID_str))[::-1]
index = tx_index.to_bytes(4, byteorder="little", signed=False)
input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)
output_value = output_value_sat.to_bytes(8, byteorder="little", signed=True)

sighash = sighash_type + bytes.fromhex("00 00 00")
sighash_type_flag = sighash_type

to_self_delay_little_e = to_self_delay_big_e[::-1]

##########################################
# INPUT (witness script): escrow script op_codes
# 0x52      OP_2
# 0x21      OP_DATA - len(merch_pubkey)
# merch_pubkey
# 0x21      OP_DATA - len(cust_pubkey)
# cust_pubkey
# 0x52      OP_2
# 0xae      OP_CHECKMULTISIG
escrow_script = (
    bytes.fromhex("5221")
    + merch_pubkey
    + bytes.fromhex("21")
    + cust_pubkey
    + bytes.fromhex("52ae")
)

# OUTPUT: merch-close script op_codes
# 0x63      OP_IF
# 0x52      OP_2
# 0x21      OP_DATA - len(merch_pubkey)
# merch_pubkey
# 0x21      OP_DATA - len(cust_pubkey)
# cust_pubkey
# 0x52      OP_2
# 0xae      OP_CHECKMULTISIG
# 0x67      OP_ELSE
# 0x__      OP_DATA - len(to_self_delay) (probably 0x02)
# to_self_delay
# 0xb2      OP_CHECKSEQUENCEVERIFY
# 0x75      OP_DROP
# 0x21      OP_DATA - len(merch_payout_pubkey)
# merch_close_pk
# 0xac      OP_CHECKSIG
# 0x68      OP_ENDIF
merch_close_script = (
    bytes.fromhex("63 52 21")
    + merch_pubkey
    + bytes.fromhex("21")
    + cust_pubkey
    + bytes.fromhex("52 ae 67")
    + len(to_self_delay_little_e).to_bytes(1, byteorder="little", signed=False)
    + to_self_delay_little_e
    + bytes.fromhex("b2 75 21")
    + merch_payout_pubkey
    + bytes.fromhex("ac68")
)

script_sha32 = hashlib.sha256(merch_close_script).digest()
merch_close_scriptPK = bytes.fromhex("0020") + script_sha32

##########################################
# Put together the tx digest preimage

# if sighash is set to ANYONECANPAY (don't sign inputs):
if sighash_type.hex()[0] == "8":
    hashPrevOuts = (0).to_bytes(32, byteorder="little", signed=False)
    hashSequence = (0).to_bytes(32, byteorder="little", signed=False)
else:
    hashPrevOuts = dSHA256(txid + index)
    hashSequence = dSHA256(sequence)

# hashOutputs and output
outputs = (
    output_value
    + (len(merch_close_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + merch_close_scriptPK
)

# if sighash is set to NONE (don't sign outputs):
if sighash_type.hex()[1] == "2":
    hashOutputs = (0).to_bytes(32, byteorder="little", signed=False)
else:
    hashOutputs = dSHA256(outputs)

scriptcode = (
    (len(escrow_script)).to_bytes(1, byteorder="little", signed=False)
    + escrow_script
)

tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + txid
    + index
    + scriptcode
    + input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)

tx_digest = dSHA256(tx_digest_preimage)

##########################################
# Produce signatures for 2-of-2 multisig

signing_key_merch = ecdsa.SigningKey.from_string(merch_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
signature_merch = signing_key_merch.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

signing_key_cust = ecdsa.SigningKey.from_string(cust_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
signature_cust = signing_key_cust.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

##########################################
# Create witness field with 2-of-2 multisig signatures (in specific order)

witness_field = (
    # indicate the number of stack items for the txin
    bytes.fromhex("04")

    # OP_CHECKMULTISIG bug
    + bytes.fromhex("00")

    # signature 1
    + (len(signature_merch)+1).to_bytes(1, byteorder="little", signed=False)
    + signature_merch
    + sighash_type_flag

    # signature 2
    + (len(signature_cust)+1).to_bytes(1, byteorder="little", signed=False)
    + signature_cust
    + sighash_type_flag

    # witnessScript
    # This is the script that the creator of this transaction needs to privide, and
    # solve, in order to redeem the UTXO listed in the input
    + (len(escrow_script)).to_bytes(1, byteorder="little", signed=False)
    + escrow_script
)

##########################################
# Create final tx with signatures

scriptSig = (
    bytes.fromhex("00") # length of empty scriptSig (since it's a witness output)
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
    + witness_field
    + locktime
)

print(final_tx.hex())


##########################################
# Print out tx digest details if debug flag was set
if args.debug:
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

    print("\ncust escrow pubkey: ", cust_pubkey.hex())
    print("merch escrow pubkey: ", merch_pubkey.hex())

    print("\nhashOutputs preimage (outputs)")
    print("outputs: ", outputs.hex())

    print("merch-close-script (p2wsh preimage): ", merch_close_script.hex())
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

    print("\nversion: ", version.hex())
    print("tx_in_count: ", tx_in_count.hex())
    print("txid little endian: ",txid.hex())
    print("index: ",index.hex())
    print("scriptSig: ",scriptSig.hex())
    print("sequence: ",sequence.hex())
    print("tx_out_count: ", tx_out_count.hex())
    print("outputs: ",outputs.hex())
    print("locktime: ", locktime.hex())

    print("\nDouble SHA256 final_tx_legacy: ", dSHA256(final_tx_legacy).hex())
    print("\ntxid of this tx: ",new_txid.hex())
