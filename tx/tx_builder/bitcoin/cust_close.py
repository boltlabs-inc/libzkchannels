# Code based on tutorial by
# https://github.com/zeltsi/segwit_tutorial/blob/master/transactions/txdemo.py

# one input:
#   p2wsh (2-of-2 multisig) from escrow or merch-close
# three outputs:
#   delayed to customer p2wsh
#   immediate to merchant p2wpkh
#   OP_RETURN with revocation lock and customer pubkey hash

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
# spend from escrow or merch-close?
parser.add_argument("--spend_fromm", "-sf", help="options: escrow or merch-close")

# debug on to print full tx details
parser.add_argument("--debug", "-db", action='store_true', help="debug mode: print out all tx details")

# tx details
parser.add_argument("--txid_str", "-tx", help="txid of outpoint as string")
parser.add_argument("--index", "-ind", help="index of outpoint")
parser.add_argument("--input_amount_btc", "-a", help="amount of btc held by the previous outpoint")
parser.add_argument("--cust_privkey", "-csk", help="private key of customer for escrow")
parser.add_argument("--merch_privkey", "-msk", help="private key of merchant for escrow")
parser.add_argument("--cust_script_value_btc", "-cso", help="btc to cust close script output")
parser.add_argument("--to_cust_pubkey", "-ccpk", help="public key of cust close to-self output")
parser.add_argument("--to_merch_value_btc", "-mo", help="btc to merchant close output")
parser.add_argument("--to_merch_pubkey", "-mcpk", help="public key of merchant output")
parser.add_argument("--revocation_lock", "-rl", help="revocation lock (hash160{revocation_secret})")
parser.add_argument("--merch_dispute_pubkey", "-mdpk", help="public key of merchant dispute")
parser.add_argument("--to_self_delay", "-tsd", help="to_self_delay (in unit of blocks) for the merchant's to-self output")
args = parser.parse_args()


if args.spend_fromm:
    spend_from = args.spend_fromm
else:
    spend_from = "escrow"

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) < 5:
    txID_str = "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1"
    tx_index = 0
    input_amount_sat = int(float(2.0) * 100000000)
    cust_privkey = bytes.fromhex("7911111111111111111111111111111111111111111111111111111111111111")
    merch_privkey = bytes.fromhex("3711111111111111111111111111111111111111111111111111111111111111")
    cust_script_value_sat = int(float(1.0) * 100000000)
    to_cust_pubkey = bytes.fromhex("03195e272df2310ded35f9958fd0c2847bf73b5b429a716c005d465009bd768641")
    to_merch_value_sat = int(float(1.0) * 100000000)
    to_merch_pubkey = bytes.fromhex("0342da23a1de903cd7a141a99b5e8051abfcd4d2d1b3c2112bac5c8997d9f12a00")
    revocation_lock = bytes.fromhex("f8345a21a55dc665b65c8dcfb49488b8e4f337d5c9bb843603f7222a892ce941")
    merch_dispute_pubkey = bytes.fromhex("0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c")
    to_self_delay_big_e = bytes.fromhex("05cf")

# Otherwise, read in values from command line arguments
else:
    txID_str = args.txid_str
    tx_index = int(args.index)
    input_amount_sat = int(float(args.input_amount_btc) * 100000000)
    cust_privkey = bytes.fromhex(args.cust_privkey)
    merch_privkey = bytes.fromhex(args.merch_privkey)
    cust_script_value_sat = int(float(args.cust_script_value_btc) * 100000000)
    to_cust_pubkey = bytes.fromhex(args.to_cust_pubkey)
    to_merch_value_sat = int(float(args.to_merch_value_btc) * 100000000)
    to_merch_pubkey = bytes.fromhex(args.to_merch_pubkey)
    revocation_lock = bytes.fromhex(args.revocation_lock)
    merch_dispute_pubkey = bytes.fromhex(args.merch_dispute_pubkey)
    to_self_delay_big_e = bytes.fromhex(args.to_self_delay)

# generate public keys for the 2-of-2 multisig input
merch_pubkey = privkey_to_pubkey(merch_privkey)
cust_pubkey = privkey_to_pubkey(cust_privkey)

# These are hard coded tx variables
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")
sequence = bytes.fromhex("ffffffff")
locktime = bytes.fromhex("0000 0000")
sighash = bytes.fromhex("0100 0000")
sighash_type_flag = bytes.fromhex("01")
tx_in_count = bytes.fromhex("01")
tx_out_count = bytes.fromhex("03")

# Convert txid, index, amounts, and to_self_delay to little endian
txid = (bytes.fromhex(txID_str))[::-1]
index = tx_index.to_bytes(4, byteorder="little", signed=False)
input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)

merch_output_value = to_merch_value_sat.to_bytes(8, byteorder="little", signed=True)
cust_script_output_value = cust_script_value_sat.to_bytes(8, byteorder="little", signed=True)
op_return_output_value = (0).to_bytes(8, byteorder="little", signed=True)

to_self_delay_little_e = to_self_delay_big_e[::-1]

##########################################
# Define witness script to spend from the previous tx,
# either escrow or merch-close

if spend_from == "escrow":
    # escrow script op_codes
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

    witness_script = escrow_script

elif spend_from == "merch-close":
    # merch-close script op_codes
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
    # 0x21      OP_DATA - len(merch_close_pubkey)
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
        + to_merch_pubkey
        + bytes.fromhex("ac68")
    )

    witness_script = merch_close_script
else:
    raise Exception("specify '--spend_from' argument with either 'escrow' or 'merch-close'")

##########################################
# Define our three outputs

# Delayed to-customer p2wsh output
# script op codes
# 0x63      OP_IF
# 0xa8      OP_SHA256
# 0x20      OP_DATA - len(single SHA256 on revocation secret)
# revocation_lock
# 0x88      OP_EQUALVERIFY
# 0x21      OP_DATA - len(merch_disp_pubkey)
# merch_disp_pubkey
# 0x67      OP_ELSE
# 0x__      OP_DATA - len(to_self_delay) (probably ~0x02)
# to_self_delay
# 0xb2      OP_CHECKSEQUENCEVERIFY
# 0x75      OP_DROP
# 0x21      OP_DATA - len(cust_close_pubkey)
# cust_close_pk
# 0x68      OP_ENDIF
# 0xac      OP_CHECKSIG

to_cust_script = (
    bytes.fromhex("63 a8 20")
    + revocation_lock
    + bytes.fromhex("88 21")
    + merch_dispute_pubkey
    + bytes.fromhex("67")
    + len(to_self_delay_little_e).to_bytes(1, byteorder="little", signed=False)
    + to_self_delay_little_e
    + bytes.fromhex("b2 75 21")
    + to_cust_pubkey
    + bytes.fromhex("68 ac")
)

cust_script_sha32 = hashlib.sha256(to_cust_script).digest()
cust_scriptPK = bytes.fromhex("0020") + cust_script_sha32

# Immediate to-merchant output
to_merch_scriptPK = bytes.fromhex("0014") + hash160(to_merch_pubkey)

# OP_RETURN output
op_return_scriptPK = (
    # 0x6a OP_RETURN
    bytes.fromhex("6a")
    # OP_DATA - needs to cover the length of the RL and cust_close_pk (32 bytes)
    + (len(revocation_lock) + 33).to_bytes(1, byteorder="little", signed=False)
    + revocation_lock
    + to_cust_pubkey
)

##########################################
# Put together the tx digest preimage

hashPrevOuts = dSHA256(txid + index)
hashSequence = dSHA256(sequence)

outputs = (
    cust_script_output_value
    + (len(cust_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + cust_scriptPK

    + merch_output_value
    + (len(to_merch_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + to_merch_scriptPK

    + op_return_output_value
    + (len(op_return_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + op_return_scriptPK
)

hashOutputs = dSHA256(outputs)

scriptcode = (
    (len(witness_script)).to_bytes(1, byteorder="little", signed=False)
    + witness_script
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

signing_key_cust = ecdsa.SigningKey.from_string(cust_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
signature_cust = signing_key_cust.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

signing_key_merch = ecdsa.SigningKey.from_string(merch_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
signature_merch = signing_key_merch.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

##########################################
# Create witness field with 2-of-2 multisig signatures (in specific order)

witness_field = (
    # indicate the number of stack items for the txin
    bytes.fromhex("05")

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

    # "01" So that we enter OP_IF in the script
    # 0x01 for the length of the following "01" byte
    + bytes.fromhex("01")
    + bytes.fromhex("01")

    # witnessScript
    # This is the script that the creator of this transaction needs to privide, and
    # solve, in order to redeem the UTXO listed in the input
    + (len(witness_script)).to_bytes(1, byteorder="little", signed=False)
    + witness_script
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

##########################################]
if args.debug:
    print("\ntx digest preimage")
    print(tx_digest_preimage.hex())

    print(version.hex())
    print(hashPrevOuts.hex())
    print(hashSequence.hex())
    print(txid.hex())
    print(index.hex())
    print(scriptcode.hex())
    print(input_amount.hex())
    print(sequence.hex())
    print(hashOutputs.hex())
    print(locktime.hex())
    print(sighash.hex())

    print("\nhashPrevOuts preimage (outputs)")
    print(outputs.hex())

    print(cust_script_output_value.hex())
    print((len(cust_scriptPK)).to_bytes(1, byteorder="little", signed=False).hex())
    print(cust_scriptPK.hex())

    print(merch_output_value.hex())
    print((len(to_merch_scriptPK)).to_bytes(1, byteorder="little", signed=False).hex())
    print(to_merch_scriptPK.hex())

    print(op_return_output_value.hex())
    print((len(op_return_scriptPK)).to_bytes(1, byteorder="little", signed=False).hex())
    print(op_return_scriptPK.hex())

    print("\nto cust script")
    print(to_cust_script.hex())

    print("63a820")
    print(revocation_lock.hex())
    print("8821")
    print(merch_dispute_pubkey.hex())
    print("67")
    print(len(to_self_delay_little_e).to_bytes(1, byteorder="little", signed=False).hex()
        + to_self_delay_little_e.hex())
    print("b27521")
    print(to_cust_pubkey.hex())
    print("68ac")
