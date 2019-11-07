# Funding tx as in Bolt 3 Appendix B
# 1 Input:
#     0.5 btc P2PKH
# 2 Outputs:
#     0.1 btc P2WSH - 2of2 MultiSig
#     0.49... btc  change address
#
# Link to Bolt 3
# https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#funding-transaction-output
#
# used code from  https://github.com/zeltsi/segwit_tutorial

import hashlib
import ecdsa

def dSHA256(data):
    hash_1 = hashlib.sha256(data).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    return hash_2

# nVersion = 2 allows use of relative timelocks
nVersion = 2
version = nVersion.to_bytes(4, byteorder="little", signed=False)

# # marker and flag are specific to spending from a segwit input
# marker = bytes.fromhex("00") # this must be 00
# flag = bytes.fromhex("01") # this must be 01

# LOCKTIME
locktime = 0
nLockTime = locktime.to_bytes(4, byteorder="little", signed=False)


# INPUT details
txid_str = "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
txid = (bytes.fromhex(txid_str))[::-1]

tx_index = 0   # index starts at 0
index = tx_index.to_bytes(4, byteorder="little", signed=False)

sequence_hex = "ffffffff"
nSequence = bytes.fromhex(sequence_hex)

input_priv_key_hex = "6bd078650fcee8444e4e09825227b801a1ca928debb750eb36e6d56124bb20e8"
private_key = bytes.fromhex(input_priv_key_hex)

input_scriptPubKey_hex = "76a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac"
input_scriptPubKey = bytes.fromhex(input_scriptPubKey_hex)

sighash_type = "01000000"
sighash = bytes.fromhex(sighash_type)

sighash_type_flag_hex = "01"
sighash_type_flag = bytes.fromhex(sighash_type_flag_hex)


# NUM INPUTS/OUTPUTS and values
# 1 input, 2 outputs (funding tx and change)
tx_in_count = (1).to_bytes(1, byteorder="little", signed=False)
tx_out_count = (2).to_bytes(1, byteorder="little", signed=False)

input_amount_sat = int(5000000000)
amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)

output1_value_sat = int(10000000)
output1_value = output1_value_sat.to_bytes(8, byteorder="little", signed=True)

output2_value_sat = int(4989986080)
output2_value = output2_value_sat.to_bytes(8, byteorder="little", signed=True)


# CREATE FUNDING SCRIPTPUKKEY - P2WSH (output 1)
# This has a 2 of 3 multisig redeem script. The 32 byte hash of this is used for
# scriptPubKey: OP_00 <32-byte-sha256(redeem_script)>
redeem_script_hex = "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"
redeem_script = bytes.fromhex(redeem_script_hex)
hash_rs = hashlib.sha256(redeem_script)
hash_redeem_script = hash_rs.digest()

fund_pk_script = (
    bytes.fromhex("00")
    + (len(hash_redeem_script)).to_bytes(1, byteorder="little", signed=False)
    + hash_redeem_script
)


# CREATE CHANGE SCRIPTPUBKEY - P2WPKH (output 2)
# scriptPubKey: "OP_00 <20-byte-hash160(pubkey)>"
change_pubkey_hex = "03535b32d5eb0a6ed0982a0479bbadc9868d9836f6ba94dd5a63be16d875069184"
change_pubkey = bytes.fromhex(change_pubkey_hex)

# Here I am trying to create the 20-byte pubkey hash for p2wpkh

sha256_1 = hashlib.sha256(change_pubkey)

ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha256_1.digest())
change_pubkeyhash = ripemd160.digest()

change_pk_script = (
    bytes.fromhex("00")
    + (len(change_pubkeyhash)).to_bytes(1, byteorder="little", signed=False)
    + change_pubkeyhash
)


###################################################################
# Below, we use the information above to create the temp tx to sign
###################################################################

outpoint = (
    txid
     + index
)

##### Create outputs
# funding tx output
output1 = (
    output1_value
    + (len(fund_pk_script)).to_bytes(1, byteorder="little", signed=False)
    + fund_pk_script
)

# change tx output
output2 = (
    output2_value
    + (len(change_pk_script)).to_bytes(1, byteorder="little", signed=False)
    + change_pk_script
)


# Serialized tx which gets double SHA256 and then signed.
# This is specific to spending from a pre-segwit tx
tx_to_sign = (
    version
    + tx_in_count
    + outpoint
    # For the sake of signing the transaction, the scriptSig is replaced
    # with the scriptPubKey of the utxo we want to spend from
    + len(input_scriptPubKey).to_bytes(1, byteorder="little", signed=False)
    + input_scriptPubKey
    + nSequence
    + tx_out_count
    + output1
    + output2
    + nLockTime
    + sighash
)

tx_digest = dSHA256(tx_to_sign)


##### From the private key, generate signing key and public key
signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1) # Don't forget to specify the curve

verifying_key = signing_key.get_verifying_key()

# Use this code block if the address you gave corresponds to the compressed public key
x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32] # The first 32 bytes are the x coordinate
y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:] # The last 32 bytes are the y coordinate
if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0: # We need to turn the y_cor into a number.
    public_key = bytes.fromhex("02" + x_cor.hex())
else:
    public_key = bytes.fromhex("03" + x_cor.hex())


##### Sign the temporary tx (with scriptSig replaced by input scripPubKey)
signature = signing_key.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

##### Now that we have the signature, we can create the scriptSig
scriptSig = (
    # length & signature
    (len(signature)+1).to_bytes(1, byteorder="little", signed=False)
    + signature
    # sighash flag (we use 01 for SIGHASH_ALL)
    + sighash_type_flag

    # length & public key (for p2pkh)
    + (len(public_key)).to_bytes(1, byteorder="little", signed=False)
    + public_key
)

##### Now we have all the parts to create the final tx
final_tx = (
    version
    + tx_in_count
    + outpoint
    + len(scriptSig).to_bytes(1, byteorder="little", signed=False)
    + scriptSig
    + nSequence
    + tx_out_count
    + output1
    + output2
    + nLockTime
)

print(final_tx.hex())
