# p2wpkh input
# This has been tested and works

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
parser.add_argument("--privkey", "-sk", help="private key of outpoint as hex string")
parser.add_argument("--txid", "-tx", help="txid of outpoint as hex string")
parser.add_argument("--index", "-ind", help="index of outpoint")
parser.add_argument("--out_pubkey", "-opk", help="pubkey of output as hex string")
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


nSequence_str = "ffffffff"
sequence = bytes.fromhex(nSequence_str)

input_amount_sat = int(float(args.amount_btc) * 100000000)
output_value_sat = int(float(args.output_btc) * 100000000)

input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)
output_value = output_value_sat.to_bytes(8, byteorder="little", signed=True)


# private key for input
# privkey_hex = "CF933A6C602069F1CBC85990DF087714D7E86DF0D0E48398B7D8953E1F03534B"
privkey_hex = args.privkey
privkey = bytes.fromhex(privkey_hex)
pubkey = privkey_to_pubkey(privkey)


# P2WPKH scriptPubKey
output_pubkey_hex = args.out_pubkey
output_pubkey = bytes.fromhex(output_pubkey_hex)
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

scriptcode = bytes.fromhex("1976a914" + hash160(pubkey).hex() + "88ac")

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

signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
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
    + (len(pubkey)).to_bytes(1, byteorder="little", signed=False)
    + pubkey
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
