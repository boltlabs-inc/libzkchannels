# p2wsh input (2-of-2 multisig)
# p2wpkh output

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
parser.add_argument("--merch_pubkey", "-mpk", help="pubkey of merchant for merch-close")
parser.add_argument("--cust_pubkey", "-cpk", help="pubkey of cust for merch-close")
parser.add_argument("--merch_close_privkey", "-mcpk", help="private key of merchant close to-self output")
parser.add_argument("--output_pubkey", "-opk", help="public key for the transaction output p2wpkh")
parser.add_argument("--to_self_delay", "-tsd", help="to_self_delay (in unit of blocks) for the merchant's to-self output")
parser.add_argument("--txid", "-tx", help="txid of outpoint as hex string")
parser.add_argument("--index", "-ind", help="index of outpoint")
parser.add_argument("--amount_btc", "-a", help="amount of btc in")
parser.add_argument("--output_btc", "-o", help="btc to output")
args = parser.parse_args()

################################

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

txid = (bytes.fromhex(txID_str))[::-1]
index = tx_index.to_bytes(4, byteorder="little", signed=False)

nSequence_as_blocks = int(args.to_self_delay, 16)
sequence = nSequence_as_blocks.to_bytes(4, byteorder="little", signed=False)

input_amount_sat = int(float(args.amount_btc) * 100000000)
output_value_sat = int(float(args.output_btc) * 100000000)

input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)
output_value = output_value_sat.to_bytes(8, byteorder="little", signed=True)

# # public keys for the merch-close tx 2-of-2 multisig
merch_pubkey = bytes.fromhex(args.merch_pubkey)
cust_pubkey = bytes.fromhex(args.cust_pubkey)

# merch_close_pubkey for the to_self_delay output
merch_close_privkey_hex = args.merch_close_privkey
merch_close_privkey = bytes.fromhex(merch_close_privkey_hex)
merch_close_pubkey = privkey_to_pubkey(merch_close_privkey)

# P2WSH merch-close scriptPubKey
# 0x63      OP_IF
# 0x52      OP_2
# 0x21      OP_DATA - len(merch_pubkey)
# merch_pubkey
# 0x21      OP_DATA - len(cust_pubkey)
# cust_pubkey
# 0x52      OP_2
# 0xae      OP_CHECKMULTISIG
# 0x67      OP_ELSE
# 0x__      OP_DATA - len(to_self_delay) (probably ~0x02)
# to_self_delay
# 0xb2      OP_CHECKSEQUENCEVERIFY
# 0x75      OP_DROP
# 0x21      OP_DATA - len(merch_close_pubkey)
# merch_close_pk
# 0xac      OP_CHECKSIG
# 0x68      OP_ENDIF


# todo: find a nicer way to do this
l = int(len(args.to_self_delay)/2)
short_sequence = nSequence_as_blocks.to_bytes(l, byteorder="little", signed=False)

merch_close_script = (
    bytes.fromhex("63 52 21")
    + merch_pubkey
    + bytes.fromhex("21")
    + cust_pubkey
    + bytes.fromhex("52 ae 67")
    + (len(short_sequence)).to_bytes(1, byteorder="little", signed=False)
    + short_sequence
    + bytes.fromhex("b2 75 21")
    + merch_close_pubkey
    + bytes.fromhex("ac68")
)


# send output to another P2WPKH address
output_pubkey = bytes.fromhex(args.output_pubkey)
output_scriptPK = bytes.fromhex("0014") + hash160(output_pubkey)

locktime = bytes.fromhex("00000000")

sighash = bytes.fromhex("01000000")
sighash_type_flag = bytes.fromhex("01")

tx_in_count = bytes.fromhex("01")
tx_out_count = bytes.fromhex("01")

##########################################

# hashPrevOuts and outpoint
outpoint = (
    txid
     + index
)

hashPrevOuts = dSHA256(outpoint)

# hashSequence
hashSequence = dSHA256(sequence)

# hashOutputs and output
output = (
    output_value
    + (len(output_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output_scriptPK
)

hashOutputs = dSHA256(output)

scriptcode = (
    (len(merch_close_script)).to_bytes(1, byteorder="little", signed=False)
    + merch_close_script
)

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

hashed_bip_143 = dSHA256(bip_143)

signing_key_merch_close = ecdsa.SigningKey.from_string(merch_close_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
signature_merch_close = signing_key_merch_close.sign_digest(hashed_bip_143, sigencode=ecdsa.util.sigencode_der_canonize)

witness = (
    # indicate the number of stack items for the txin
    bytes.fromhex("03")

    # signature
    + (len(signature_merch_close)+1).to_bytes(1, byteorder="little", signed=False)
    + signature_merch_close
    + sighash_type_flag

    # So that we enter OP_ELSE in the script
    + bytes.fromhex("00")

    # witnessScript
    # This is the script that the creator of this transaction needs to privide, and
    # solve, in order to redeem the UTXO listed in the input
    + (len(merch_close_script)).to_bytes(1, byteorder="little", signed=False)
    + merch_close_script
)

scriptSig = (
    bytes.fromhex("00") # length of empty scriptSig
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

print(final_tx.hex())
# print(merch_close_script.hex())
