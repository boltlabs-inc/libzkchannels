# This code was based on an example provided by
# https://github.com/zeltsi/segwit_tutorial/blob/master/transactions/txdemo.py

# This script creates a signed funding-tx spending from a p2sh-p2wsh address

# include standard modules

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
parser.add_argument("--input_privkey", "-fsk", help="private key of outpoint as hex string")

parser.add_argument("--payout_value_btc", "-c", help="output value in btc")
parser.add_argument("--payout_pubkey", "-chpk", help="pubkey for p2wpkh output")
args = parser.parse_args()

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) < 5:
    # txID_str = "0000000000000000000000000000000099999999999999999999999999999999"
    txID_str = "cf6f93e3367f9925de957303af97b4be67060437bde3785d6b465d19ebac861b"
    tx_index = 0
    input_amount_sat = int(float(3.0) * 100000000)
    input_privkey = bytes.fromhex("1111111111111111111111111111111100000000000000000000000000000000")
    input_pubkey = privkey_to_pubkey(input_privkey)

    payout_value_sat = int(float(1.0) * 100000000)
    payout_privkey = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    payout_pubkey = privkey_to_pubkey(payout_privkey)

else:
    txID_str = args.txid_str
    tx_index = int(args.index)
    input_amount_sat = int(float(args.input_amount_btc) * 100000000)
    input_privkey = bytes.fromhex(args.input_privkey)
    input_pubkey = privkey_to_pubkey(input_privkey)

    payout_value_sat = int(float(args.payout_value_btc) * 100000000)
    payout_pubkey = bytes.fromhex(args.payout_pubkey)


# These are hard coded tx variables
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")
sequence = bytes.fromhex("ffffffff")
locktime = bytes.fromhex("0000 0000")
sighash = bytes.fromhex("0100 0000")
sighash_type_flag = bytes.fromhex("01")
tx_in_count = bytes.fromhex("01")
tx_out_count = bytes.fromhex("01")


# Convert txid, index, amounts, and to_self_delay to little endian
txid = (bytes.fromhex(txID_str))[::-1]
index = tx_index.to_bytes(4, byteorder="little", signed=False)
input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)

# escrow_value = escrow_value_sat.to_bytes(8, byteorder="little", signed=True)
payout_value = payout_value_sat.to_bytes(8, byteorder="little", signed=True)

##########################################

# P2WPKH scriptPubKey
payout_scriptPK = bytes.fromhex("0014") + hash160(payout_pubkey)

##########################################
# Put together the tx digest preimage

hashPrevOuts = dSHA256(txid + index)
hashSequence = dSHA256(sequence)

outputs = (
    payout_value
    + (len(payout_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + payout_scriptPK
)

hashOutputs = dSHA256(outputs)

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

signing_key = ecdsa.SigningKey.from_string(input_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
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

# redeem script
# This is the script that the creator of this transaction needs to provide, and
# solve, in order to redeem the UTXO listed in the input

# 0x0014 is because we are using a (P2SH)-P2WPKH
# 0x00 = OP_0, 0x14 is to push 20 bytes of the keyhash onto the stack
# redeemScript = bytes.fromhex(f"0014{keyhash.hex()}")
redeemScript = (
    bytes.fromhex("0014")
    + hash160(input_pubkey)
)

scriptSig = (
    # length of redeem script + 1, length of redeem script
    (len(redeemScript)+ 1).to_bytes(1, byteorder="little", signed=False)
    + (len(redeemScript)).to_bytes(1, byteorder="little", signed=False)
    + redeemScript
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
