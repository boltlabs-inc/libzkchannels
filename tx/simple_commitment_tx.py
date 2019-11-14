# Bolt 3
# Simple commitment tx with no HTLC as in BOLT 3 Appendix class
# https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#funding-transaction-output

# NOT FINAL
# Following fields are temporarily filled in
# nSequence
# nLockTime
# Revokation PubKey generation
# to_self_delay

# TX DETAILS
# funding_tx_id: 8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be
# funding_output_index: 0
# funding_amount_satoshi: 10000000
# commitment_number: 42
# local_delay: 144
# local_dust_limit_satoshi: 546

# to_local_msat: 7000000000
# to_remote_msat: 3000000000
# local_feerate_per_kw: 15000
#
# # base commitment transaction fee = 10860
# # actual commitment transaction fee = 10860
# # to_local amount 6989140 wscript 63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac
# # to_remote amount 3000000 P2WPKH(0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b)
# remote_signature = 3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0
# # local_signature = 3044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939
# output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c383693901483045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
# num_htlcs: 0

import hashlib
import ecdsa

def dSHA256(data):
    hash_1 = hashlib.sha256(data).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    return hash_2


# nVersion = 2 allows use of relative timelocks
nVersion = 2
version = nVersion.to_bytes(4, byteorder="little", signed=False)

# marker and flag are specific to spending from a segwit input
marker = bytes.fromhex("00") # this must be 00
flag = bytes.fromhex("01") # this must be 01

# LOCKTIME
# locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
nLockTime = bytes.fromhex("3e195220")

# 0xcf05 = delay of 1487 blocks
to_self_delay = bytes.fromhex("cf05")

# sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
sequence_hex = "38b02b80"
nSequence = bytes.fromhex(sequence_hex)

sighash_type = "01000000"
sighash = bytes.fromhex(sighash_type)

sighash_type_flag_hex = "01"
sighash_type_flag = bytes.fromhex(sighash_type_flag_hex)


# INPUT details
txid_str = "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
txid = (bytes.fromhex(txid_str))[::-1]

tx_index = 0   # index starts at 0
index = tx_index.to_bytes(4, byteorder="little", signed=False)

# funding tx redeem script
# This has a 2 of 3 multisig redeem script. The 32 byte hash of this is used for
# the output: OP_00 <
redeem_script_hex = "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"
redeem_script = bytes.fromhex(redeem_script_hex)
hash_rs = hashlib.sha256(redeem_script)
hash_redeem_script = hash_rs.digest()

# REMOTE SIGNATURE
remote_signature = bytes.fromhex("3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0")

# PRIVATE AND PUBLIC KEYS
# private_key = bytes.fromhex(local_funding_privkey_hex)
local_funding_privkey_hex = "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749"
local_funding_pubkey_hex = "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
input_scriptPubKey_hex = "76a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac"
remote_funding_pubkey_hex = "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"

local_privkey_hex = "bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f274694491"
localpubkey_hex = "030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7"
remotepubkey_hex = "0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b"
local_delayedpubkey_hex = "03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c"
local_revocation_pubkey_hex = "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19"

# Convert priv/pub keys from hex to bytes
local_funding_privkey = bytes.fromhex(local_funding_privkey_hex)
local_funding_pubkey = bytes.fromhex(local_funding_pubkey_hex)
input_scriptPubKey = bytes.fromhex(input_scriptPubKey_hex)
remote_funding_pubkey = bytes.fromhex(remote_funding_pubkey_hex)

local_privkey = bytes.fromhex(local_privkey_hex)
localpubkey = bytes.fromhex(localpubkey_hex)
remotepubkey = bytes.fromhex(remotepubkey_hex)
local_delayedpubkey = bytes.fromhex(local_delayedpubkey_hex)
local_revocation_pubkey = bytes.fromhex(local_revocation_pubkey_hex)


# NUM INPUTS/OUTPUTS and values
# 1 input, 2 outputs (funding tx and change)
tx_in_count = (1).to_bytes(1, byteorder="little", signed=False)
tx_out_count = (2).to_bytes(1, byteorder="little", signed=False)

input_amount_sat = int(10000000)
amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)

to_local_value_sat = int(6989140)
to_local_value = to_local_value_sat.to_bytes(8, byteorder="little", signed=True)

to_remote_value_sat = int(3000000)
to_remote_value = to_remote_value_sat.to_bytes(8, byteorder="little", signed=True)

# Redeem script and hash for funding tx output
fund_redeem_script_hex = "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"
fund_redeem_script = bytes.fromhex(fund_redeem_script_hex)
fund_hash_rs = hashlib.sha256(fund_redeem_script)
hash_fund_redeem_script = fund_hash_rs.digest()


# CREATE to_remote scriptPubKey - P2WPKH (output 1)
# No timelock on to_remote tx.
# scriptPubKey: OP_00 <len> <20 byte hash160(pubkey)>
sha_remote_pubkey = hashlib.sha256(remotepubkey)

ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha_remote_pubkey.digest())
hash160_remote_pubkey = ripemd160.digest()

to_remote_pk_script = (
    bytes.fromhex("00")
    + (len(hash160_remote_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + hash160_remote_pubkey
)


# CREATE to_local scriptPubKey - P2WSH (output 2)
# scriptPubKey: OP_00 <32-byte-sha256(redeem_script)>
# redeem_script:
# OP_IF
#     # Penalty transaction
#     <revocationpubkey>
# OP_ELSE
#     `to_self_delay`
#     OP_CHECKSEQUENCEVERIFY
#     OP_DROP
#     <local_delayedpubkey>
# OP_ENDIF
# OP_CHECKSIG
to_local_redeem_script = (
    bytes.fromhex("63") # OP_ENDIF
    + local_delayedpubkey # TODO - THIS SHOULD BE JOINT REVOCATION pubkey
    + bytes.fromhex("67") # OP_ELSE
    + to_self_delay
    + bytes.fromhex("b2") # OP_CHECKSEQUENCEVERIFY
    + bytes.fromhex("75")  # OP_DROP
    + local_delayedpubkey
    + bytes.fromhex("68") # OP_ENDIF
    + bytes.fromhex("ac") # OP_CHECKSIG
)

# NOTE:
# The output is spent by a transaction with nSequence field set to to_self_delay
# (which can only be valid after that duration has passed) and witness

hash_tlrs = hashlib.sha256(to_local_redeem_script)
hash_to_local_redeem_script = hash_tlrs.digest()

to_local_pk_script = (
    bytes.fromhex("00")
    + (len(hash_to_local_redeem_script)).to_bytes(1, byteorder="little", signed=False)
    + hash_to_local_redeem_script
)

###################################################################
# Below, we use the information above to create the temp tx to sign
###################################################################


outpoint = (
    txid
     + index
)


##### Create outputs=
to_remote_output = (
    to_remote_value
    + (len(to_remote_pk_script)).to_bytes(1, byteorder="little", signed=False)
    + to_remote_pk_script
)

to_local_output = (
    to_local_value
    + (len(to_local_pk_script)).to_bytes(1, byteorder="little", signed=False)
    + to_local_pk_script
)

hashPrevOuts = dSHA256(outpoint)
hashSequence = dSHA256(nSequence)
hashOutput = dSHA256(to_remote_output + to_local_output)

# Serialized tx which gets double SHA256 and then signed.
# This is specific to spending from a pre-segwit tx
bip143_tx_to_sign = (
    version
    + hashPrevOuts
    + hashSequence
    + outpoint
    # For the sake of signing the transaction, the scriptSig is replaced
    # with the scriptPubKey of the utxo we want to spend from
    + fund_redeem_script
    + amount
    + nSequence
    + hashOutput
    + nLockTime
    + sighash
)


hashed_bip_143 = dSHA256(bip143_tx_to_sign)

local_signing_key = ecdsa.SigningKey.from_string(local_funding_privkey, curve=ecdsa.SECP256k1) # Don't forget to specify the curve
local_signature = local_signing_key.sign_digest(hashed_bip_143, sigencode=ecdsa.util.sigencode_der_canonize)

witness = (
    # indicate the number of stack items for the txin
    # 4 items: OP_0, 2 signatures, witness script
    bytes.fromhex("04")

    # OP_00
    + bytes.fromhex("00")

    # local signature comes first
    + (len(local_signature)+1).to_bytes(1, byteorder="little", signed=False)
    + local_signature
    + sighash_type_flag

    # remote signature comes second
    + (len(remote_signature)+1).to_bytes(1, byteorder="little", signed=False)
    + remote_signature

    # "01" represents the single sighash flag SIGHASH_ALL and it just indicates
    # that this signature covers the entirety of the transaction (all ins, all outs)
    + sighash_type_flag

    # public key
    + (len(fund_redeem_script)).to_bytes(1, byteorder="little", signed=False)
    + fund_redeem_script
)

scriptSig = (
    # Since scriptSig is emtpy, we only encode it's length
    bytes.fromhex("00")
)

final_tx = (
    version
    + marker
    + flag
    + tx_in_count
    + outpoint
    + scriptSig
    + nSequence
    + tx_out_count
    + to_remote_output
    + to_local_output
    + witness
    + nLockTime
)

print(final_tx.hex())
