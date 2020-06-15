# 
# To run the tests, execute the following:
# $: python3 test_scenarios_bitcoind.py --rpcuser kek --rpcpass kek
# include --ignore_fees to set minRelayTxFee = 0
#

import argparse
import base58
import ecdsa
import hashlib
import json
import re
import subprocess
import sys
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

def pk_to_p2sh_p2wpkh(compressed, network):
    pk_hash = hash160(compressed)
    redeemScript = bytes.fromhex(f"0014{pk_hash.hex()}")
    rs_hash = hash160(redeemScript)
    if network == "testnet":
        prefix = b"\xc4"
    if network == "regtest":
        prefix = b"\xc4"
    elif network == "simnet":
        prefix = b'\x7b'
    elif network == "mainnet":
        prefix = b"\x05"
    else:
        return "Enter the network: tesnet/simnet/mainnet"
    return encode_base58_checksum(prefix + rs_hash)


def gen_privkeys(n) -> list :
    privkeys = []
    # privkey_prefix is 30 bytes long. The last byte will be incremented to create other privkeys
    privkey_prefix = bytes.fromhex("111111111111111111111111111111111111111111111111111111111111")
    for i in range(n):
        privkey_n = (privkey_prefix + i.to_bytes(2, byteorder="big", signed=False))
        privkeys.append(privkey_n)

    return privkeys


def start_bitcoind(network, ignore_fees, auth_user, auth_pass, verbose):
    print("Starting bitcoin node ...")
    # Make sure bitcoind is not already running
    log("-> First stop existing bitcoind ...")
    out = subprocess.getoutput("bitcoin-cli -{net} stop".format(net=network))
    log("-> %s" % out, verbose)
    time.sleep(2)
    auth_creds = ""
    if auth_user != "" and auth_pass != "":
        auth_creds = "-rpcuser=%s -rpcpassword=%s " % (auth_user, auth_pass)
    if ignore_fees:
        out = subprocess.getoutput("bitcoind -{net} -daemon {auth}-deprecatedrpc=generate -fallbackfee=0.0002 -minrelaytxfee=0".format(net=network, auth=auth_creds))
    else: # specify specific minrelay
        out = subprocess.getoutput("bitcoind -{net} -daemon {auth}-deprecatedrpc=generate -fallbackfee=0.0002".format(net=network, auth=auth_creds))
    log("-> bitcoind started")
    time.sleep(2)
    if not check_for_sufficient_funds(network, verbose):
        generate_blocks(network,301)
    return

def check_for_sufficient_funds(network, verbose):
    funds_left = subprocess.getoutput("bitcoin-cli -{net} getwalletinfo".format(net=network))
    d = json.loads(funds_left)
    cur_balance = int(d["balance"])
    log("Miner balance: %s" % cur_balance)
    return cur_balance > 100

def generate_funded_np2wkh(input_sk, amount, network, verbose):
    pubkey = privkey_to_pubkey(bytes.fromhex(input_sk))
    np2wkh_addr = pk_to_p2sh_p2wpkh(pubkey, network)
    fund_tx_cmd = "bitcoin-cli -{net} sendtoaddress {addr} {amt} true".format(net=network, addr=np2wkh_addr, amt=amount)
    log("Transfer: %s" % fund_tx_cmd, verbose)
    txid = subprocess.getoutput(fund_tx_cmd)
    # check that txid is actually valid
    log(">> Spendable utxo => txid=%s" % txid)

    # find which index corresponds to the funded utxo (as opposed to change output)
    full_tx = subprocess.getoutput("bitcoin-cli -{net} getrawtransaction {txid}".format(net=network, txid=txid))
    log("Full Tx: %s" % full_tx, verbose)
    decoded = subprocess.getoutput("bitcoin-cli -{net} decoderawtransaction {tx}".format(net=network, tx=full_tx))
    log("Decoded Tx: %s" % decoded, verbose)
    d = json.loads(decoded)

    if d["vout"][0]["scriptPubKey"]["addresses"][0] == np2wkh_addr:
        index = 0
    else:
        index = 1

    return txid, index


EscrowTxFile = "txdata_%d/signed_escrow_%d.txt"
MerchCloseTxFile = "txdata_%d/signed_merch_close_%d.txt"
FirstCustCloseEscrowTxFile = "txdata_%d/signed_first_cust_close_escrow_tx_%d.txt"
MerchClaimViaFirstCustCloseEscrowTxFile = "txdata_%d/signed_merch_claim_first_close_escrow_tx_%d.txt"
MerchClaimViaFirstCustCloseMerchTxFile = "txdata_%d/signed_merch_claim_first_close_merch_tx_%d.txt"
FirstCustCloseMerchTxFile = "txdata_%d/signed_first_cust_close_merch_tx_%d.txt"
CustCloseEscrowTxFile = "txdata_%d/signed_cust_close_escrow_tx_%d.txt"
CustCloseFromMerchTxFile = "txdata_%d/signed_cust_close_merch_tx_%d.txt"
CustClaimFromCustCloseEscrowTxFile = "txdata_%d/signed_cust_claim_escrow_tx_%d.txt"
CustClaimFromCustCloseMerchTxFile = "txdata_%d/signed_cust_claim_merch_tx_%d.txt"
MerchClaimFromEscrowTxFile = "txdata_%d/signed_merch_claim_escrow_tx_%d.txt"
MerchClaimFromMerchTxFile = "txdata_%d/signed_merch_claim_merch_tx_%d.txt"
MerchDisputeFirstCustCloseTxFile = "txdata_%d/signed_dispute_from_escrow_tx_%d.txt"
MerchDisputeFirstCustCloseFromMerchTxFile = "txdata_%d/signed_dispute_from_merch_tx_%d.txt"
MerchClaimFromMerchCloseTxFile = "txdata_%d/signed_merch_claim_merch_close_tx_%d.txt"

PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

def log(msg, debug=True):
    if debug: print("%s[+] %s%s" % (PURPLE, msg, NC))

def get_status(bool_val):
    if bool_val:
        return "%sPASSED%s" % (GREEN, NC)
    else:
        return "%sFAILED%s" % (RED, NC)

def emphasize(msg):
    return "%s%s%s" % (BLUE, msg, NC)

def read_file(tx_file):
    f = open(tx_file)
    tx_hex = f.read()
    f.close()
    assert len(tx_hex) % 2 == 0
    return tx_hex

def check_transaction_on_chain(network, txid, tx_hex):
    full_tx = subprocess.getoutput("bitcoin-cli -{net} getrawtransaction {txid}".format(net=network, txid=txid))
    return full_tx == tx_hex

def broadcast_transaction(network, tx_hex, tx_type_str):
    txid = subprocess.getoutput("bitcoin-cli -{net} sendrawtransaction {tx_hex}".format(net=network, tx_hex=tx_hex))
    time.sleep(1)
    rc = check_transaction_on_chain(network, txid, tx_hex)
    # print("%s Tx: %s" % (tx_type_str, emphasize(tx_hex)))
    print("%s Txid: %s, Tx Status: %s" % (tx_type_str, emphasize(txid), get_status(rc)))
    return

def generate_blocks(network, blocks):
    version = get_btc_version()
    if int(version) < int("018"):
        # if bitcoin-cli is pre v0.18, use 'generate' command
        result = subprocess.getoutput("bitcoin-cli -{net} generate {blocks}".format(net=network, blocks=blocks))
    else:
        address = subprocess.getoutput("bitcoin-cli -{net} getnewaddress".format(net=network))
        result = subprocess.getoutput("bitcoin-cli -{net} generatetoaddress {blocks} {addr}".format(net=network, blocks=blocks, addr=address))
    if result != "":
        print("Generated %s blocks" % emphasize(blocks))
    else:
        print("Failed to advance chain! :-(")
    return

def get_btc_version():
    '''
    e.g. 'Bitcoin Core RPC client version v0.20.99.0-dec067f5a' returns ("020") 
    '''
    out = subprocess.getoutput("bitcoin-cli -version")
    version = re.search(r"version v(\d).(\d\d)", out, re.M).group(1,2)
    return "".join(version)



def run_gowrapper(utxo_txid, utxo_index, utxo_sk):
    cmd = "./run_gowrapper.sh {txid} {index} {sk}".format(txid=utxo_txid, index=utxo_index, sk=utxo_sk)
    log(">> Generate txs: %s" % cmd)
    return subprocess.getoutput(cmd)

def run_scenario_test1(network, utxo_index):
    print("==============================================")
    log(">> Scenario 1: cust close from merch-close without dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    merch_close_tx = read_file(MerchCloseTxFile % (utxo_index, utxo_index))
    cust_close_tx = read_file(CustCloseFromMerchTxFile % (utxo_index, utxo_index))
    cust_claim_tx = read_file(CustClaimFromCustCloseMerchTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromMerchTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, merch_close_tx, "Merch Close")
    broadcast_transaction(network, cust_close_tx, "Cust Close from Merch Close")
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)") # can be spent immediately
    generate_blocks(network, 1486)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer)") # should fail
    generate_blocks(network, 1)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer)") # now should succeed
    print("==============================================")

def run_scenario_test2(network, utxo_index):
    print("==============================================")
    log(">> Scenario 2: cust close from escrow without dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    cust_close_tx = read_file(CustCloseEscrowTxFile % (utxo_index, utxo_index))
    cust_claim_tx = read_file(CustClaimFromCustCloseEscrowTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromEscrowTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, cust_close_tx, "Cust Close from Escrow")
    generate_blocks(network, 1487)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer)")
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)")
    print("==============================================")

def run_scenario_test3(network, utxo_index):
    print("==============================================")
    log(">> Scenario 3: cust close from escrow with merch dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    first_cust_close_tx = read_file(FirstCustCloseEscrowTxFile % (utxo_index, utxo_index))
    merch_dispute_tx = read_file(MerchDisputeFirstCustCloseTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimViaFirstCustCloseEscrowTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, first_cust_close_tx, "Old Cust Close")
    broadcast_transaction(network, merch_dispute_tx, "Merch dispute the old Cust Close from Escrow (to_customer)")  
    broadcast_transaction(network, merch_claim_tx, "Merch claim from old Cust Close (to_merchant)")
    print("==============================================")

def run_scenario_test4(network, utxo_index):
    print("==============================================")
    log(">> Scenario 4: cust close from merch with merch dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    merch_close_tx = read_file(MerchCloseTxFile % (utxo_index, utxo_index))
    first_cust_close_tx = read_file(FirstCustCloseMerchTxFile % (utxo_index, utxo_index))
    merch_dispute_tx = read_file(MerchDisputeFirstCustCloseFromMerchTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimViaFirstCustCloseMerchTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, merch_close_tx, "Merch Close")
    broadcast_transaction(network, first_cust_close_tx, "Old Cust Close from Merch Close")
    broadcast_transaction(network, merch_dispute_tx, "Merch dispute the Cust Close from Merch")  
    broadcast_transaction(network, merch_claim_tx, "Merch claim from old Cust Close (to_merchant)")
    print("==============================================")

def run_scenario_test5(network, utxo_index):
    print("==============================================")
    log(">> Scenario 5: merch claim from merch close after timelock")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    merch_close_tx = read_file(MerchCloseTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromMerchCloseTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, merch_close_tx, "Merch Close")
    generate_blocks(network, 1487)
    broadcast_transaction(network, merch_claim_tx, "Merch claim from the Merch Close (after timelock)")
    print("==============================================")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output_btc", help="amount in btc to pay out to each output", default="1")
    parser.add_argument("--network", help="select the type of network", default="regtest")
    parser.add_argument("--ignore_fees", help="if flagged, set minRelayTxFee to 0", default=False,  action="store_true")
    parser.add_argument("--rpcuser", help="rpcuser for bitcoind ", default="")
    parser.add_argument("--rpcpass", help="rpcpassword for bitcoind", default="")

    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    args = parser.parse_args()

    network = str(args.network)
    output_btc = int(args.output_btc)
    ignore_fees = args.ignore_fees
    auth_user = args.rpcuser
    auth_pass = args.rpcpass
    verbose = args.verbose

    print("Network: ", network)
    print(subprocess.getoutput("bitcoin-cli -version"))

    start_bitcoind(network, ignore_fees, auth_user, auth_pass, verbose)

    tests_to_run = [run_scenario_test1, run_scenario_test2, run_scenario_test3, run_scenario_test4, run_scenario_test5]
    
    output_privkeys = gen_privkeys(len(tests_to_run)+1)

    for i, scenario in enumerate(tests_to_run):
        utxo_txid, tx_index = generate_funded_np2wkh(output_privkeys[i].hex(), output_btc, network, verbose)

        run_gowrapper(utxo_txid, tx_index, output_privkeys[i].hex())
        time.sleep(2)
        scenario(network, tx_index)

    out = subprocess.getoutput("bitcoin-cli -{net} stop".format(net=network))
    log("Stop bitcoind ... %s" % out)
    exit(0)

main()
