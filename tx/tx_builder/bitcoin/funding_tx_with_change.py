# p2sh-p2wpkh  input
# p2wsh (2-of-2 multisig) output
# Input and change address work
# multisig output has not been successfully spent from
# include standard modules

import argparse
import hashlib
import ecdsa

def dSHA256(data):
    hash_1 = hashlib.sha256(data).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    return hash_2

def hash160(s):
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def privkey_to_pubkey(privkey):
    signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
    verifying_key = signing_key.get_verifying_key()

    # Use this code block if the address you gave corresponds to the compressed public key
    x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32] # The first 32 bytes are the x coordinate
    y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:] # The last 32 bytes are the y coordinate
    if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0: # We need to turn the y_cor into a number.
        public_key = bytes.fromhex("02" + x_cor.hex())
    else:
        public_key = bytes.fromhex("03" + x_cor.hex())
    return public_key

################################

parser = argparse.ArgumentParser()
parser.add_argument("--funding_privkey", "-fsk", help="private key of outpoint as hex string", required=True)
parser.add_argument("--txid", "-tx", help="txid of outpoint as hex string", required=True)
parser.add_argument("--index", "-ind", help="index of outpoint", required=True)
parser.add_argument("--amount_btc", "-a", help="amount of btc in", required=True)
parser.add_argument("--cust_pubkey", "-cpk", help="pubkey of customer for escrow", required=True)
parser.add_argument("--merch_pubkey", "-mpk", help="pubkey of merchant for escrow", required=True)
parser.add_argument("--change_pubkey", "-chpk", help="pubkey for change output", required=True)
parser.add_argument("--escrow_btc", "-e", help="escrow transaction btc", required=True)
parser.add_argument("--change_btc", "-c", help="change transaction btc", required=True)
parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
args = parser.parse_args()

################################
verbose = args.verbose
if verbose:
    print("<============Tx Details============>")

# version is 4-bytes little endian. Version 2 should be default
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00") # this must be 00
flag = bytes.fromhex("01") # this must be 01

# txID_str = "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1"
# tx_index = 0   # index starts at 0
txID_str = args.txid
txid = (bytes.fromhex(txID_str))[::-1]
tx_index = int(args.index)
index = tx_index.to_bytes(4, byteorder="little", signed=False)

# private key for input
# private_key_str = "AF933A6C602069F1CBC85990DF087714D7E86DF0D0E48398B7D8953E1F03534A"
private_key_str = args.funding_privkey

private_key = bytes.fromhex(private_key_str)

nSequence_str = "ffffffff"
sequence = bytes.fromhex(nSequence_str)

input_amount_sat = int(float(args.amount_btc) * 100000000)
output1_value_sat = int(float(args.escrow_btc) * 100000000)
output2_value_sat = int(float(args.change_btc) * 100000000)
# input_amount_sat = int(40 * 100000000)
# output1_value_sat = int(39 * 100000000)
# output2_value_sat = int(0.5 * 100000000)

input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)
output1_value = output1_value_sat.to_bytes(8, byteorder="little", signed=True)
output2_value = output2_value_sat.to_bytes(8, byteorder="little", signed=True)

# # public keys for the funding tx 2-of-2 multisig
merch_pubkey = bytes.fromhex(args.merch_pubkey)
cust_pubkey = bytes.fromhex(args.cust_pubkey)

# MultiSigSize 71 bytes
# - 0x52 OP_2: 1 byte
# - 0x21 OP_DATA: 1 byte (pubKeyAlice length)
# - merchPubKey: 33 bytes
# - 0x21 OP_DATA: 1 byte (pubKeyBob length)
# - custPubKeyBob: 33 bytes
# - 0x52 OP_2: 1 byte
# - 0xae OP_CHECKMULTISIG: 1 byte
escrow_script = (
    bytes.fromhex("5221")
    + merch_pubkey
    + bytes.fromhex("21")
    + cust_pubkey
    + bytes.fromhex("52ae")
)

# P2WSH scriptPubKey
script_sha32 = hashlib.sha256(escrow_script).digest()
output1_scriptPK = bytes.fromhex("0020") + script_sha32

# P2WPKH scriptPubKey
change_pubkey = bytes.fromhex(args.change_pubkey)
output2_scriptPK = bytes.fromhex("0014") + hash160(change_pubkey)

locktime = bytes.fromhex("00000000")

sighash = bytes.fromhex("01000000")
sighash_type_flag = bytes.fromhex("01")

tx_in_count = bytes.fromhex("01")
tx_out_count = bytes.fromhex("02")

##########################################

# hashPrevOuts and outpoint
outpoint = (
    txid
     + index
)

hashPrevOuts = dSHA256(outpoint)
if verbose:
    print("txid: ", txid.hex())
    print("index: ", index.hex())
    print("hashPrevOuts: ", hashPrevOuts.hex())

# hashSequence
hashSequence = dSHA256(sequence)
if verbose:
    print("hashSequence: ", hashSequence.hex())

# hashOutputs and output
output = (
    output1_value
    + (len(output1_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output1_scriptPK

    + output2_value
    + (len(output2_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output2_scriptPK
)
if verbose:
    print("")
    print("output1_scriptPubKey: ", (output1_value
    + (len(output1_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output1_scriptPK).hex())

    print("output2_scriptPubKey: ", (output2_value
    + (len(output2_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output2_scriptPK).hex())
    print("Full tx output preimage: ", output.hex())
    print("")

hashOutputs = dSHA256(output)
if verbose:
    print("hashOutputs: ", hashOutputs.hex())
signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1) # Don't forget to specify the curve

public_key = privkey_to_pubkey(private_key)

keyhash = hash160(public_key)

scriptcode = bytes.fromhex(f"1976a914{keyhash.hex()}88ac")
if verbose:
    print("Script code: ", scriptcode.hex())

# serialized bip_143 object
bip_143 = (
    version
    + hashPrevOuts
    + hashSequence
    + outpoint
    + scriptcode
    + input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)
if verbose:
    print("\nTx preimage: ", bip_143.hex())
    print()

hashed_bip_143 = dSHA256(bip_143)
signature = signing_key.sign_digest(hashed_bip_143, sigencode=ecdsa.util.sigencode_der_canonize)

witness = (
    # indicate the number of stack items for the txin
    # 2 items for signature and pubkey
    bytes.fromhex("02")

    # signature
    + (len(signature)+1).to_bytes(1, byteorder="little", signed=False)
    + signature

    # "01" represents the single sighash flag SIGHASH_ALL and it just indicates
    # that this signature covers the entirety of the transaction (all ins, all outs)
    + sighash_type_flag

    # public key
    + (len(public_key)).to_bytes(1, byteorder="little", signed=False)
    + public_key
)
if verbose:
    print("Witness: ", witness.hex())

# redeem script
# This is the script that the creator of this transaction needs to provide, and
# solve, in order to redeem the UTXO listed in the input

# 0x0014 is because we are using a (P2SH)-P2WPKH
# 0x00 = OP_0, 0x14 is to push 20 bytes of the keyhash onto the stack
redeemScript = bytes.fromhex(f"0014{keyhash.hex()}")
if verbose:
    print("Redeem script: ", redeemScript.hex())
    print("<============Tx Details============>\n")

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
    + outpoint
    + scriptSig
    + sequence
    + tx_out_count
    + output
    + witness
    + locktime
)

print("Raw Transaction Hex: ", final_tx.hex())


# Calculate txid of the tx we have just created:
# Convert to pre-segwit format, double sha256, reverse bytes (little endian)

# final_tx_legacy = (
#     version
#     + tx_in_count
#     + outpoint
#     + scriptSig
#     + sequence
#     + tx_out_count
#     + output
#     + locktime
# )
#
# new_txid = dSHA256(final_tx_legacy)[::-1]
# print(new_txid.hex())
