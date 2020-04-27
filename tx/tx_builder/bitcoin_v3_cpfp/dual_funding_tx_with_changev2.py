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
parser.add_argument("--cust_txid_str", "-ctx", help="txid of cust input as string")
parser.add_argument("--cust_index", "-cind", help="index of cust outpoint")
parser.add_argument("--cust_input_amount_btc", "-ca", help="amount of btc held by the previous cust outpoint")
parser.add_argument("--cust_funding_privkey", "-cfsk", help="private key of cust outpoint as hex string")

parser.add_argument("--merch_txid_str", "-mtx", help="txid of merch input as string")
parser.add_argument("--merch_index", "-mind", help="index of merch outpoint")
parser.add_argument("--merch_input_amount_btc", "-ma", help="amount of btc held by the previous merch outpoint")
parser.add_argument("--merch_funding_privkey", "-mfsk", help="private key of merch outpoint as hex string")

parser.add_argument("--escrow_value_btc", "-e", help="btc to be sent to escrow output")
parser.add_argument("--cust_pubkey", "-cpk", help="pubkey of customer for escrow")
parser.add_argument("--merch_pubkey", "-mpk", help="pubkey of merchant for escrow")

parser.add_argument("--cust_change_value_btc", "-c", help="cust change transaction btc")
parser.add_argument("--cust_change_pubkey", "-chpk", help="pubkey for customer's change output")

parser.add_argument("--merch_change_value_btc", "-m", help="merch change transaction btc")
parser.add_argument("--merch_change_pubkey", "-mchpk", help="pubkey for merchant's change output")
args = parser.parse_args()

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) < 5:
    cust_txID_str = "cf6f93e3367f9925de957303af97b4be67060437bde3785d6b465d19ebac861b"
    cust_tx_index = 0
    cust_input_amount_sat = int(float(3.0) * 100000000)
    cust_funding_privkey = bytes.fromhex("1111111111111111111111111111111100000000000000000000000000000000")
    cust_funding_pubkey = privkey_to_pubkey(cust_funding_privkey)

    merch_txID_str = "bf6f93e3367f9925de957303af97b4be67060437bde3785d6b465d19ebac861f"
    merch_tx_index = 0
    merch_input_amount_sat = int(float(4.0) * 100000000)
    merch_funding_privkey = bytes.fromhex("4911111111111111111111111111111100000000000000000000000000000000")
    merch_funding_pubkey = privkey_to_pubkey(cust_funding_privkey)

    escrow_value_sat = int(float(4.0) * 100000000)
    cust_privkey = bytes.fromhex("1111111111111111111111111111111133333333333333333333333333333333")
    cust_pubkey = privkey_to_pubkey(cust_privkey)
    merch_privkey = bytes.fromhex("2222222222222222222222222222222233333333333333333333333333333333")
    merch_pubkey = privkey_to_pubkey(merch_privkey)

    cust_change_value_sat = int(float(1.0) * 100000000)
    cust_change_privkey = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    cust_change_pubkey = privkey_to_pubkey(cust_change_privkey)

    merch_change_value_sat = int(float(2.0) * 100000000)
    merch_change_privkey = bytes.fromhex("6666111111111111111111111111111111111111111111111111111111111111")
    merch_change_pubkey = privkey_to_pubkey(merch_change_privkey)

else:
    cust_txID_str = args.cust_txid_str
    cust_tx_index = int(args.cust_index)
    cust_input_amount_sat = int(float(args.cust_input_amount_btc) * 100000000)
    cust_funding_privkey = bytes.fromhex(args.cust_funding_privkey)
    cust_funding_pubkey = privkey_to_pubkey(cust_funding_privkey)

    merch_txID_str = args.merch_txid_str
    merch_tx_index = int(args.merch_index)
    merch_input_amount_sat = int(float(args.merch_input_amount_btc) * 100000000)
    merch_funding_privkey = bytes.fromhex(args.merch_funding_privkey)
    merch_funding_pubkey = privkey_to_pubkey(merch_funding_privkey)

    escrow_value_sat = int(float(args.escrow_value_btc) * 100000000)
    cust_pubkey = bytes.fromhex(args.cust_pubkey)
    merch_pubkey = bytes.fromhex(args.merch_pubkey)

    cust_change_value_sat = int(float(args.cust_change_value_btc) * 100000000)
    cust_change_pubkey = bytes.fromhex(args.cust_change_pubkey)

    merch_change_value_sat = int(float(args.merch_change_value_btc) * 100000000)
    merch_change_pubkey = bytes.fromhex(args.merch_change_pubkey)


# These are hard coded tx variables
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")
sequence = bytes.fromhex("ffffffff")
locktime = bytes.fromhex("0000 0000")
sighash = bytes.fromhex("0100 0000")
sighash_type_flag = bytes.fromhex("01")
tx_in_count = bytes.fromhex("02")
tx_out_count = bytes.fromhex("03")


# Convert txid, index, amounts, and to_self_delay to little endian
cust_txid = (bytes.fromhex(cust_txID_str))[::-1]
cust_index = cust_tx_index.to_bytes(4, byteorder="little", signed=False)
cust_input_amount = cust_input_amount_sat.to_bytes(8, byteorder="little", signed=True)

merch_txid = (bytes.fromhex(merch_txID_str))[::-1]
merch_index = merch_tx_index.to_bytes(4, byteorder="little", signed=False)
merch_input_amount = merch_input_amount_sat.to_bytes(8, byteorder="little", signed=True)

escrow_value = escrow_value_sat.to_bytes(8, byteorder="little", signed=True)
cust_change_value = cust_change_value_sat.to_bytes(8, byteorder="little", signed=True)
merch_change_value = merch_change_value_sat.to_bytes(8, byteorder="little", signed=True)

##########################################
# Define three output scriptPubKeys: escrow, cust change, merch change

# OUTPUT[0]: escrow script op_codes
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

script_sha32 = hashlib.sha256(escrow_script).digest()
escrow_scriptPK = bytes.fromhex("0020") + script_sha32

# OUTPUT[1]: cust change P2WPKH
cust_change_scriptPK = bytes.fromhex("0014") + hash160(cust_change_pubkey)

# OUTPUT[2]: merch change P2WPKH
merch_change_scriptPK = bytes.fromhex("0014") + hash160(merch_change_pubkey)

##########################################
# Put together the tx digest preimages (one for cust, one for merch)

hashPrevOuts = dSHA256(cust_txid + cust_index + merch_txid + merch_index)
hashSequence = dSHA256(sequence + sequence)

outputs = (
    escrow_value
    + (len(escrow_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + escrow_scriptPK

    + cust_change_value
    + (len(cust_change_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + cust_change_scriptPK

    + merch_change_value
    + (len(merch_change_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + merch_change_scriptPK
)

hashOutputs = dSHA256(outputs)

##### Create cust signature
cust_locking_script = (
    bytes.fromhex("76 a9 14")
    + hash160(cust_funding_pubkey)
    + bytes.fromhex("88 ac")
)

cust_scriptcode = (
    (len(cust_locking_script)).to_bytes(1, byteorder="little", signed=False)
    + cust_locking_script
)

cust_tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + cust_txid
    + cust_index
    + cust_scriptcode
    + cust_input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)

cust_tx_digest = dSHA256(cust_tx_digest_preimage)

cust_signing_key = ecdsa.SigningKey.from_string(cust_funding_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
cust_signature = cust_signing_key.sign_digest(cust_tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

##### Create merch signature
merch_locking_script = (
    bytes.fromhex("76 a9 14")
    + hash160(merch_funding_pubkey)
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

merch_signing_key = ecdsa.SigningKey.from_string(merch_funding_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
merch_signature = merch_signing_key.sign_digest(merch_tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

##### Create witness

witness = (
    # indicate the number of stack items for the FIRST input
    # 2 items for (signature, pubkey)
    bytes.fromhex("02")

    # signature
    + (len(cust_signature)+1).to_bytes(1, byteorder="little", signed=False)
    + cust_signature
    + sighash_type_flag

    # public key
    + (len(cust_funding_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + cust_funding_pubkey

    # Number of stack items for the SECOND input
    + bytes.fromhex("02")

    # signature
    + (len(merch_signature)+1).to_bytes(1, byteorder="little", signed=False)
    + merch_signature
    + sighash_type_flag

    # public key
    + (len(merch_funding_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + merch_funding_pubkey
)

# redeem script
# This is the script that the creator of this transaction needs to provide, and
# solve, in order to redeem the UTXO listed in the input

# 0x0014 is because we are using a (P2SH)-P2WPKH
# 0x00 = OP_0, 0x14 is to push 20 bytes of the keyhash onto the stack
# redeemScript = bytes.fromhex(f"0014{keyhash.hex()}")
cust_redeemScript = (
    bytes.fromhex("0014")
    + hash160(cust_funding_pubkey)
)

merch_redeemScript = (
    bytes.fromhex("0014")
    + hash160(merch_funding_pubkey)
)

cust_scriptSig = (
    # length of redeem script + 1, length of redeem script
    (len(cust_redeemScript) + 1).to_bytes(1, byteorder="little", signed=False)
    + (len(cust_redeemScript)).to_bytes(1, byteorder="little", signed=False)
    + cust_redeemScript
)

cust_input = (
    cust_txid
    + cust_index
    + cust_scriptSig
    + sequence
)

merch_scriptSig = (
    # length of redeem script + 1, length of redeem script
    (len(merch_redeemScript) + 1).to_bytes(1, byteorder="little", signed=False)
    + (len(merch_redeemScript)).to_bytes(1, byteorder="little", signed=False)
    + merch_redeemScript
)

merch_input = (
    merch_txid
    + merch_index
    + merch_scriptSig
    + sequence
)


final_tx = (
    version
    + marker
    + flag
    + tx_in_count
    + cust_input
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

    # Calculate txid of the tx we have just created:
    # Convert to pre-segwit format, double sha256, reverse bytes (little endian)
    final_tx_legacy = (
        version
        + tx_in_count
        + cust_input
        + merch_input
        + tx_out_count
        + outputs
        + locktime
    )

    new_txid = dSHA256(final_tx_legacy)[::-1]
    print("\nfinal_tx_legacy: ", final_tx_legacy.hex())
    print("\nBreakdown of final_tx_legacy")
    print("\nversion: ", version.hex())
    print("\ntx_in_count: ", tx_in_count.hex())
    print("\ncust_input: ", cust_input.hex())
    print("\nmerch_input: ", merch_input.hex())
    print("\ntx_out_count: ", tx_out_count.hex())
    print("\noutputs: ", outputs.hex())
    print("\nlocktime: ", locktime.hex())
    print("\n\nDouble SHA256 final_tx_legacy: ", dSHA256(final_tx_legacy).hex())
    print("\ntxid of this tx: ",new_txid.hex())
