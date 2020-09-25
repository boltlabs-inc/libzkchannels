# 
# To run the tests, execute the following:
# $: python3 test_scenarios_bitcoind.py --rpcuser kek --rpcpass kek --timelock=187
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
    redeemScript = bytes.fromhex("0014"+str(pk_hash.hex()))
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


def gen_privkeys(n):
    privkeys = []
    # privkey_prefix is 30 bytes long. The last byte will be incremented to create other privkeys
    privkey_prefix = bytes.fromhex("111111111111111111111111111111111111111111111111111111111111")
    for i in range(n):
        privkey_n = (privkey_prefix + i.to_bytes(2, byteorder="big", signed=False))
        privkeys.append(privkey_n)

    return privkeys


def start_bitcoind(network, ignore_fees, small_blocks, auth_user, auth_pass, verbose):
    print("Starting bitcoin node ...")
    # Make sure bitcoind is not already running
    log("-> First stop existing bitcoind ...")
    out = subprocess.getoutput("bitcoin-cli -{net} stop".format(net=network))
    log("-> %s" % out, verbose)
    time.sleep(2)

    auth_creds = ""
    if auth_user != "" and auth_pass != "":
        auth_creds = "-rpcuser=%s -rpcpassword=%s " % (auth_user, auth_pass)
    minrelaytxfee = ""
    if ignore_fees: 
        minrelaytxfee = "-minrelaytxfee=0"
    blockmaxweight = ""
    if small_blocks:
        blockmaxweight = "-blockmaxweight=10000"

    out = subprocess.getoutput("bitcoind -{net} -daemon {auth}-deprecatedrpc=generate -fallbackfee=0.0002 {minfee} {blocksize}".format(net=network, auth=auth_creds, minfee=minrelaytxfee, blocksize=blockmaxweight))

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
MutualCloseTxFile = "txdata_%d/signed_mutual_close_tx_%d.txt"
SignBumpFeeChildTxFile = "txdata_%d/signed_bump_fee_child_tx_p2wpkh_%d.txt"

PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

def log(msg, debug=True):
    if debug: print("%s[+] %s%s" % (PURPLE, msg, NC))

def accepted_status(bool_val):
    if bool_val:
        return "%sACCEPTED%s" % (GREEN, NC)
    else:
        return "%sREJECTED%s" % (RED, NC)

def confirmed_status(bool_val):
    if bool_val:
        return "%sCONFIRMED%s" % (GREEN, NC)
    else:
        return "%sUNCONFIRMED%s" % (RED, NC)

def emphasize(msg):
    return "%s%s%s" % (BLUE, msg, NC)

def read_file(tx_file):
    f = open(tx_file)
    tx_hex = f.read()
    f.close()
    assert len(tx_hex) % 2 == 0
    return tx_hex

def check_transaction_accepted(network, txid, tx_hex):
    full_tx = subprocess.getoutput("bitcoin-cli -{net} getrawtransaction {txid}".format(net=network, txid=txid))
    return full_tx == tx_hex

def check_transaction_confirmed(network, tx_type_str, txid):
    details = subprocess.getoutput("bitcoin-cli -{net} gettxout {txid} 0".format(net=network, txid=txid))
    j = json.loads(details)
    is_confirmed = int(j["confirmations"]) > 0    
    print("%s Txid: %s, On-chain Status : %s" % (tx_type_str, emphasize(txid), confirmed_status(is_confirmed)))
    return is_confirmed

def get_mempool_size(network):    
    details = subprocess.getoutput("bitcoin-cli -{net} getmempoolinfo".format(net=network))
    j = json.loads(details)
    return int(j["size"])

def clear_mempool(network):
    '''
    clear_mempool produces blocks until the mempool is reduced to 0. Note that it can get stuck if 
    '''
    n = get_mempool_size(network)
    if n > 0:
        print("Generating blocks to clear mempool")
        generate_blocks(network, 10)
        if get_mempool_size(network) == n:
            print("Warning: Some transactions could not be mined.")
            return
        clear_mempool(network)
    return

def broadcast_transaction(network, tx_hex, tx_type_str):
    txid = subprocess.getoutput("bitcoin-cli -{net} sendrawtransaction {tx_hex}".format(net=network, tx_hex=tx_hex))
    # time.sleep(0.5)
    rc = check_transaction_accepted(network, txid, tx_hex)
    print("%s Tx: %s" % (tx_type_str, emphasize(tx_hex)))
    print("%s Txid: %s, Tx Status: %s" % (tx_type_str, emphasize(txid), accepted_status(rc)))
    return txid

# testmempoolaccept is a way to validate a transaction but without having to
# broadcast it. It would be useful for testing merchClaim with and without the
# child input.
def testmempoolaccept(network, tx_hex, tx_type_str):
    out = subprocess.getoutput("bitcoin-cli -{net} testmempoolaccept '[\"{tx_hex}\"]'".format(net=network, tx_hex=tx_hex))
    d = json.loads(out)
    allowed = d[0]["allowed"]
    # time.sleep(0.5)
    print("%s Tx: %s" % (tx_type_str, emphasize(tx_hex)))
    print("%s, Tx Mempool Status: %s" % (tx_type_str, accepted_status(allowed)))
    if not allowed:
        print("%REJECT REASON%: ", d[0]["reject-reason"])
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

def create_tx_backlog(network, n_tx):
    '''
    Creates and broadcasts many transactions which will cause the next block to
    become full. This is used to set up the situation where we can test CPFP as
    a method for bumping up the fee rate of a close tx.
    '''    
    print("Creating %s filler txs..." % n_tx)
    amount = 0.00001
    dummy_addr = subprocess.getoutput("bitcoin-cli -{net} getnewaddress".format(net=network))
    for _ in range(n_tx):
        dummy_tx = subprocess.getoutput("bitcoin-cli -{net} sendtoaddress {addr} {amt} true".format(net=network, addr=dummy_addr, amt=amount))
        if len(dummy_tx) != 64:
            print("%s%s" % (emphasize("Failed to create dummy tx. Error msg:\n"), emphasize(dummy_tx)))
            return
    print("%s Filler txs were broadcast Status: %s" % (n_tx, accepted_status(True)))
    return

def run_gowrapper(utxo_txid, utxo_index, utxo_sk, blocks):
    cmd = "./run_gowrapper.sh {txid} {index} {sk} {blocks}".format(txid=utxo_txid, index=utxo_index, sk=utxo_sk, blocks=blocks)
    log(">> Generate txs: %s" % cmd)
    return subprocess.getoutput(cmd)

def run_scenario_test0(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 0: cust close from merch-close without dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    merch_close_tx = read_file(MerchCloseTxFile % (utxo_index, utxo_index))
    cust_close_tx = read_file(CustCloseFromMerchTxFile % (utxo_index, utxo_index))
    cust_claim_tx = read_file(CustClaimFromCustCloseMerchTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromMerchTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, merch_close_tx, "Merch Close")
    broadcast_transaction(network, cust_close_tx, "Cust Close from Merch Close")
    generate_blocks(network, blocks-1)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer) - should fail") # should fail
    generate_blocks(network, 1)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer)") # now should succeed
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)") # can be spent immediately
    print("==============================================")

def run_scenario_test1(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 1: cust close from escrow without dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    cust_close_tx = read_file(CustCloseEscrowTxFile % (utxo_index, utxo_index))
    cust_claim_tx = read_file(CustClaimFromCustCloseEscrowTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromEscrowTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, cust_close_tx, "Cust Close from Escrow")
    generate_blocks(network, blocks)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer)")
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)")
    print("==============================================")

def run_scenario_test2(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 2: cust close from escrow with merch dispute")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    first_cust_close_tx = read_file(FirstCustCloseEscrowTxFile % (utxo_index, utxo_index))
    merch_dispute_tx = read_file(MerchDisputeFirstCustCloseTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimViaFirstCustCloseEscrowTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, first_cust_close_tx, "Old Cust Close")
    broadcast_transaction(network, merch_dispute_tx, "Merch dispute the old Cust Close from Escrow (to_customer)")  
    broadcast_transaction(network, merch_claim_tx, "Merch claim from old Cust Close (to_merchant)")
    print("==============================================")

def run_scenario_test3(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 3: cust close from merch with merch dispute")
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

def run_scenario_test4(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 4: merch claim from merch close after timelock")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    merch_close_tx = read_file(MerchCloseTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromMerchCloseTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, merch_close_tx, "Merch Close")
    generate_blocks(network, blocks)
    broadcast_transaction(network, merch_claim_tx, "Merch claim from the Merch Close (after timelock)")
    print("==============================================")

def run_scenario_test5(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 5: mutual close transaction")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    mutual_close_tx = read_file(MutualCloseTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, mutual_close_tx, "Mutual Close Tx")
    print("==============================================")

def run_scenario_test6(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 6: cust close from escrow without dispute (claim cpfp output + escrow change output)")
    start_bitcoind(network, ignore_fees=False, small_blocks=True, auth_user="", auth_pass="", verbose=False)
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    cust_close_tx = read_file(CustCloseEscrowTxFile % (utxo_index, utxo_index))
    cust_bump_fee_tx = read_file(SignBumpFeeChildTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromEscrowTxFile % (utxo_index, utxo_index))

    escrow_txid = broadcast_transaction(network, escrow_tx, "Escrow")
    generate_blocks(network, 1) 
    check_transaction_confirmed(network, "Escrow", escrow_txid)
    
    create_tx_backlog(network, n_tx=30)
    print("Mempool size:", get_mempool_size(network))

    cust_close_txid = broadcast_transaction(network, cust_close_tx, "Cust Close from Escrow")
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)")
    generate_blocks(network, 1) 
    print("Mempool size:", get_mempool_size(network))
    
    log("Attempt to broadcast cust close from escrow, but we simulate it getting stuck in the mempool")
    check_transaction_confirmed(network, "Cust Close from Escrow - should be unconfirmed", cust_close_txid)

    log("Broadcast child tx to bump up the fee associated with Cust Close")
    cust_bump_txid = broadcast_transaction(network, cust_bump_fee_tx, "Claim cpfp output in Cust close using Escrow change output")
    generate_blocks(network, 1) 

    log("If CPFP worked, cust-close should now be confirmed")
    check_transaction_confirmed(network, "Cust Close from Escrow - should be confirmed", cust_close_txid)
    check_transaction_confirmed(network, "Claim cpfp output in Cust close using Escrow change output", cust_bump_txid)
    print("Mempool size:", get_mempool_size(network))

    print("==============================================")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output_btc", help="amount in btc to pay out to each output", default="1")
    parser.add_argument("--network", help="select the type of network", default="regtest")
    parser.add_argument("--ignore_fees", help="if flagged, set minRelayTxFee to 0", default=False,  action="store_true")
    parser.add_argument("--timelock", "-t", help="timelock for closing transactions", default="287")
    parser.add_argument("--rpcuser", help="rpcuser for bitcoind ", default="")
    parser.add_argument("--rpcpass", help="rpcpassword for bitcoind", default="")
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    
    args = parser.parse_args()

    network = str(args.network)
    output_btc = int(args.output_btc)
    ignore_fees = args.ignore_fees
    blocks = int(args.timelock)
    print("blocks", blocks)
    auth_user = args.rpcuser
    auth_pass = args.rpcpass
    verbose = args.verbose
    small_blocks=False

    print("Network: ", network)
    print(subprocess.getoutput("bitcoin-cli -version"))

    start_bitcoind(network, ignore_fees, small_blocks, auth_user, auth_pass, verbose)

    tests_to_run = [run_scenario_test0, run_scenario_test1, run_scenario_test2, run_scenario_test3, run_scenario_test4, run_scenario_test5, run_scenario_test6]
    # tests_to_run = [run_scenario_test0]
    
    output_privkeys = gen_privkeys(len(tests_to_run)+1)

    for i, scenario in enumerate(tests_to_run):
        utxo_txid, tx_index = generate_funded_np2wkh(output_privkeys[i].hex(), output_btc, network, verbose)

        run_gowrapper(utxo_txid, tx_index, output_privkeys[i].hex(), blocks)
        time.sleep(2)
        clear_mempool(network)
        scenario(network, tx_index, blocks)

    out = subprocess.getoutput("bitcoin-cli -{net} stop".format(net=network))
    log("Stop bitcoind ... %s" % out)
    exit(0)

main()
