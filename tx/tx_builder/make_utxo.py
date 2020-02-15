import argparse
import base58
import bech32
import binascii
import ecdsa
import hashlib
import json
import os
import subprocess
import time

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

# Functions related to generating bitcoin addresses
def encode_base58(s):
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def encode_base58_checksum(b):
    return encode_base58(b + dSHA256(b)[:4])

def pk_to_p2pkh(compressed, network):
    '''Returns the address string'''
    pk_hash = hash160(compressed)
    if network == "testnet":
        prefix = b'\x6f'
    elif network == "simnet":
        prefix = b'\x3f'
    elif network == "mainnet":
        prefix = b'\x00'
    else:
        return "Enter the network: tesnet/simnet/mainnet"
    return encode_base58_checksum(prefix + pk_hash)

def pk_to_p2sh_p2wpkh(compressed, network):
    pk_hash = hash160(compressed)
    redeemScript = bytes.fromhex(f"0014{pk_hash.hex()}")
    rs_hash = hash160(redeemScript)
    if network == "testnet":
        prefix = b"\xc4"
    elif network == "simnet":
        prefix = b'\x7b'
    elif network == "mainnet":
        prefix = b"\x05"
    else:
        return "Enter the network: tesnet/simnet/mainnet"
    return encode_base58_checksum(prefix + rs_hash)


def pk_to_p2wpkh(compressed, network):
    pk_hash = hash160(compressed)
    redeemScript = bytes.fromhex(f"0014{pk_hash.hex()}")
    spk = binascii.unhexlify(redeemScript.hex())
    version = spk[0] - 0x50 if spk[0] else 0
    program = spk[2:]
    if network == "testnet":
        prefix = 'tb'
    elif network == "simnet":
        prefix = 'sb'
    elif network == "mainnet":
        prefix = 'bc'
    else:
        return "Enter the network: tesnet/simnet/mainnet"
    return bech32.encode(prefix, version, program)


# Example usage
# python make_utxo.py --cust_input_sk=5511111111111111111111111111111100000000000000000000000000000000

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cust_input_sk", "-sk", help="secret key used to generate pubkey output for coinbase tx")
    args = parser.parse_args()
    cust_input_sk = str(args.cust_input_sk)

    # Generate pubkey and p2sh_p2wpkh address
    miner_pubkey_bytes = privkey_to_pubkey(bytes.fromhex(cust_input_sk))
    # miner_p2wpkh_address = pk_to_p2wpkh(miner_pubkey_bytes, network = "simnet")
    miner_p2sh_p2wpkh_address = pk_to_p2sh_p2wpkh(miner_pubkey_bytes, network = "simnet")

    # Make sure btcd is not already running
    out = subprocess.getoutput("btcctl --simnet --rpcuser=kek --rpcpass=kek stop")
    # if btcd was not running already, it'll return "Post https://localhost:18556: dial tcp [::1]:18556: connect: connection refused"
    print(out)

    # start up btcd in simnet mode with Alice's address as coinbase tx output
    # NOTE: This needs to be run in a separate terminal, otherwise it'll get stuck here
    print("\nExecute this command in a separate terminal\n")
    print("btcd --txindex --simnet --rpcuser=kek --rpcpass=kek --minrelaytxfee=0 --miningaddr=" + miner_p2sh_p2wpkh_address)
    input("\nPress Enter to continue...")

    # generate 1 block to fund Alice
    # get block hash to find the coinbase transaction
    blockhash = json.loads(subprocess.getoutput("btcctl --simnet --rpcuser=kek --rpcpass=kek generate 1"))
    block = json.loads(subprocess.getoutput("btcctl --simnet --rpcuser=kek --rpcpass=kek getblock " + blockhash[0]))

    # mine 300 blocks so that segwit is active (incase blockchain is starting from scratch)
    # and so that the coinbase tx is spendable (>100 confirmations)
    subprocess.getoutput("btcctl --simnet --rpcuser=kek --rpcpass=kek generate 300");

    # get the coinbase txid
    mined_txid = block["tx"][0]
    print("new utxo txid (little Endian) => " + mined_txid)

main()
