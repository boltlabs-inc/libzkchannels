# 
# To run the tests, execute the following:
# $: python3 test_scenarios_btcd.py --timelock=287
#

import argparse
import base58
import ecdsa
import hashlib
import json
import subprocess
import time
import sys

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
    elif network == "simnet":
        prefix = b'\x7b'
    elif network == "mainnet":
        prefix = b"\x05"
    else:
        return "Enter the network: tesnet/simnet/mainnet"
    return encode_base58_checksum(prefix + rs_hash)

def make_n_coinbase_utxo_for_sk(input_sk, network, n_tx, skip_restart=False, show_output=True):
    miner_pubkey_bytes = privkey_to_pubkey(bytes.fromhex(input_sk))
    miner_p2sh_p2wpkh_address = pk_to_p2sh_p2wpkh(miner_pubkey_bytes, network)
    if show_output:
        print("Miner address: ", miner_p2sh_p2wpkh_address)
    if not skip_restart:
        # Make sure btcd is not already running
        out = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek stop".format(net=network))
        # if btcd was not running already, it'll return "Post https://localhost:18556: dial tcp [::1]:18556: connect: connection refused"
        print(out)
        # start up btcd in simnet mode with Alice's address as coinbase tx output
        # NOTE: This needs to be run in a separate terminal, otherwise it'll get stuck here
        print("\nExecute this command in a separate terminal\n")
        print("btcd --txindex --{net} --rpcuser=kek --rpcpass=kek --blockprioritysize=0 --blockmaxweight=6000 --miningaddr={addr}".format(net=network, addr=miner_p2sh_p2wpkh_address))
        input("\nPress Enter to begin scenario testing...")
    else:
        # make sure btcd is running
        error_out = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek ping".format(net=network))
        if error_out != "":
            sys.exit("BTCD NOT RUNNING: '%s'" % error_out)
        elif show_output:
            print("BTCD detected running...")

    # Make sure at least 300 blocks have been mined so that segwit is active
    current_block_height = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek getblockcount".format(net=network))

    if int(current_block_height) > 10000:
        print("%s" % red("Mining difficulty of simnet too high and would cause the test to run slowly. Remove blockchain data and start from scratch using:\nrm -r  ~/Library/Application\ Support/Btcd/data/simnet"))
        exit(0)

    if int(current_block_height) < 300:
        block_needed=300-int(current_block_height)
        subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek generate {blocks}".format(net=network, blocks=block_needed))


    # generate 1 block to fund Alice
    # get block hash to find the coinbase transaction
    mined_txid =[]
    amount=[]
    for i in range(n_tx):
        blockhash = json.loads(subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek generate 1".format(net=network)))
        block = json.loads(subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek getblock {block}".format(net=network, block=blockhash[0])))
        # get the coinbase txid
        mined_txid.append(block["tx"][0])

        full_tx = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek getrawtransaction {txid}".format(net=network, txid=mined_txid[i]))
        decoded_tx = json.loads(subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek decoderawtransaction {full_tx}".format(net=network, full_tx=full_tx)))

        amount.append(decoded_tx["vout"][0]["value"])

    # and so that the coinbase tx is spendable (>100 confirmations)
    subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek generate 100".format(net=network))

    return mined_txid, amount


def gen_privkeys(n) -> list :
    privkeys = []
    # privkey_prefix is 30 bytes long. The last byte will be incremented to create other privkeys
    privkey_prefix = bytes.fromhex("111111111111111111111111111111111111111111111111111111111111")
    for i in range(n):
        privkey_n = (privkey_prefix + i.to_bytes(2, byteorder="big", signed=False))
        privkeys.append(privkey_n)

    return privkeys


def np2wkh_to_n_p2wkh(txID_str, tx_index, input_amount_btc, input_privkey_str, n_outputs, output_value_btc):

    # These are hard coded tx variables
    version = bytes.fromhex("0200 0000")
    marker = bytes.fromhex("00")
    flag = bytes.fromhex("01")
    sequence = bytes.fromhex("ffffffff")
    locktime = bytes.fromhex("0000 0000")
    sighash = bytes.fromhex("0100 0000")
    sighash_type_flag = bytes.fromhex("01")
    tx_in_count = bytes.fromhex("01")
    input_amount_sat = int(input_amount_btc * 10**8)
    output_value_sat = int(output_value_btc * 10**8)

    if n_outputs*output_value_sat > input_amount_sat:
        raise Exception("Sum of outputs larger than sum of inputs\nInput amount {} BTC insufficient for {} outputs of {} BTC".format(input_amount_sat/10**8, n_outputs, output_value_sat/10**8))
    tx_out_count = n_outputs.to_bytes(1, byteorder="big", signed=False)

    ##########################################
    # Convert txid, index, amounts, and to_self_delay to little endian
    txid = (bytes.fromhex(txID_str))[::-1]
    index = tx_index.to_bytes(4, byteorder="little", signed=False)
    input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)

    input_privkey = bytes.fromhex(input_privkey_str)
    input_pubkey = privkey_to_pubkey(input_privkey)
    # escrow_value = escrow_value_sat.to_bytes(8, byteorder="little", signed=True)
    output_value = output_value_sat.to_bytes(8, byteorder="little", signed=True)

    ##########################################
    # Put together the tx digest preimage

    hashPrevOuts = dSHA256(txid + index)
    hashSequence = dSHA256(sequence)

    output_privkeys = gen_privkeys(n_outputs)

    outputs = b""
    for i in range(n_outputs):
        output_pubkey = privkey_to_pubkey(output_privkeys[i])

        p2wpkh_scriptPK = (bytes.fromhex("0014") + hash160(output_pubkey))

        # p2wsh scriptPubKey
        payout_scriptPK = bytes.fromhex("a914") + hash160(p2wpkh_scriptPK) + bytes.fromhex("87")
        outputs += (
            output_value
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

    input = (
        txid
        + index
        + scriptSig
        + sequence
    )
    final_tx = (
        version
        + marker
        + flag
        + tx_in_count
        + input
        + tx_out_count
        + outputs
        + witness
        + locktime
    )

    return final_tx.hex()

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
SignSeparateClaimChildOutputTxFile = "txdata_%d/signed_child_tx_output_%d.txt"
SignBumpFeeChildTxFile = "txdata_%d/signed_bump_fee_child_tx_p2wpkh_%d.txt"
PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

def log(msg, verbose=True):
    if verbose: print("%s[+] %s%s" % (PURPLE, msg, NC))

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

def red(msg):
    return "%s%s%s" % (RED, msg, NC)

def read_file(tx_file):
    f = open(tx_file)
    tx_hex = f.read()
    f.close()
    assert len(tx_hex) % 2 == 0
    return tx_hex

def check_transaction_accepted(network, txid, tx_hex):
    full_tx = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek getrawtransaction {txid}".format(net=network, txid=txid))
    return full_tx == tx_hex

def check_transaction_confirmed(network, tx_type_str, txid):
    details = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek gettxout {txid} 0".format(net=network, txid=txid))
    j = json.loads(details)
    is_confirmed = int(j["confirmations"]) > 0    
    print("%s Txid: %s, On-chain Status : %s" % (tx_type_str, emphasize(txid), confirmed_status(is_confirmed)))
    return is_confirmed

def get_mempool_size(network):
    details = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek getmempoolinfo".format(net=network))
    j = json.loads(details)
    return int(j["size"])

def broadcast_transaction(network, tx_hex, tx_type_str):
    txid = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek sendrawtransaction {tx_hex}".format(net=network, tx_hex=tx_hex))
    time.sleep(0.5)
    rc = check_transaction_accepted(network, txid, tx_hex)
    print("%s Txid: %s, Tx Status: %s" % (tx_type_str, emphasize(txid), accepted_status(rc)))
    return txid

def generate_blocks(network, blocks):
    result = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek generate {blocks}".format(net=network, blocks=blocks))
    if result != "":
        print("Generated %s blocks" % emphasize(blocks))
    else:
        print("Failed to advance chain! :-(")
    return
    
def create_tx_backlog(network, miner_privkey, n_tx, sat_per_weight):
    '''
    Creates and broadcasts many transactions which will cause the next block to
    become full. This is used to set up the situation where we can test CPFP as
    a method for bumping up the fee rate of a close tx.
    '''    
    print("Creating %s filler txs..." % n_tx)
    coinbase_txid_list, amount_btc_list = make_n_coinbase_utxo_for_sk(miner_privkey, network, n_tx, skip_restart=True, show_output=False)
    tx_list = []
    for i in range(n_tx):
        # Create a new coinbase UTXO to fund the filler transactions
        n_outputs = 1
        weight_estimate = 533  # nested p2wpkh with one input/output
        tx_fee = (weight_estimate * sat_per_weight) *0.00000001 # convert to btc
        output_btc = amount_btc_list[i] - tx_fee 
        tx = np2wkh_to_n_p2wkh(coinbase_txid_list[i], 0, amount_btc_list[i], miner_privkey, n_outputs, output_btc)
        tx_list.append(tx)

    for tx_hex in tx_list:
        txid = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek sendrawtransaction {tx_hex}".format(net=network, tx_hex=tx_hex))
        time.sleep(1)
        rc = check_transaction_accepted(network, txid, tx_hex)
        if not rc:
            print("%s Filler txs failed to broadcast: %s" % (n_tx, accepted_status(rc)))

    print("%s Filler txs were broadcast Status: %s" % (n_tx, accepted_status(rc)))


def run_gowrapper(utxo_txid, utxo_index, utxo_sk, blocks):
    cmd = "./run_gowrapper.sh {txid} {index} {sk} {blocks}".format(txid=utxo_txid, index=utxo_index, sk=utxo_sk, blocks=blocks)
    log(">> DEBUG: %s" % cmd)
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
    generate_blocks(network, 1)
    broadcast_transaction(network, merch_close_tx, "Merch Close")    
    generate_blocks(network, 1)
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
    cust_claim_cpfp_tx = read_file(SignSeparateClaimChildOutputTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    broadcast_transaction(network, cust_close_tx, "Cust Close from Escrow")
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)")
    generate_blocks(network, blocks)
    broadcast_transaction(network, cust_claim_tx, "Cust claim from Cust Close after timelock (to_customer)")
    broadcast_transaction(network, cust_claim_cpfp_tx, "Cust claim child output in Cust Close from Escrow (to_cpfp)") # cpfp output can be spent immediately (separate tx)
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
    log(">> Scenario 5: mutual close tx")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    mutual_close_tx = read_file(MutualCloseTxFile % (utxo_index, utxo_index))

    broadcast_transaction(network, escrow_tx, "Escrow")
    generate_blocks(network, 1)
    broadcast_transaction(network, mutual_close_tx, "Mutual Close Tx")
    print("==============================================")

def run_scenario_test6(network, utxo_index, blocks):
    print("==============================================")
    log(">> Scenario 6: cust close from escrow without dispute (claim cpfp output + escrow change output)")
    escrow_tx = read_file(EscrowTxFile % (utxo_index, utxo_index))
    cust_close_tx = read_file(CustCloseEscrowTxFile % (utxo_index, utxo_index))
    cust_bump_fee_tx = read_file(SignBumpFeeChildTxFile % (utxo_index, utxo_index))
    merch_claim_tx = read_file(MerchClaimFromEscrowTxFile % (utxo_index, utxo_index))
    miner_privkey = "2222222222222222222222222222222222222222222222222222222222222222"
    broadcast_transaction(network, escrow_tx, "Escrow")
    # make sure escrow is confirmed on chain
    generate_blocks(network, 1) 
    # create full blocks to prevent cust-close being broadcast. Set the fee for 
    # filler txs. Minmum (minRelayTxFee) would be 0.253. For the test we want 
    # to choose a value high enough to block custClose but to allow CPFP.
    create_tx_backlog(network, miner_privkey, n_tx=40, sat_per_weight = 0.8725) 
    #872415 - 872425
    cust_close_txid = broadcast_transaction(network, cust_close_tx, "Cust Close from Escrow")
    broadcast_transaction(network, merch_claim_tx, "Merch claim from Cust Close (to_merchant)")
    # mine one block to prove that cust-close was not able to get confirmed
    
    print("Mempool size:", get_mempool_size(network))
    generate_blocks(network, 1)
    print("Mempool size:", get_mempool_size(network))
    if not check_transaction_confirmed(network, "Cust Close from Escrow - should not get confirmed", cust_close_txid):
        print("%s" % emphasize("Cust close is waiting in the mempool"))
    else:
        print("%s" % red("SCENARIO ERROR: This scenario is supposed to test fee-bumping with CPFP, but cust-close-tx was confirmed on chain instead of getting stuck in the mempool"))
        return
    # now with the help of the child tx, we should see that cust-close is 
    # confirmed in the next block
    broadcast_transaction(network, cust_bump_fee_tx, "Claim cpfp output in Cust close using Escrow change output")
    print("Mempool size:", get_mempool_size(network))
    generate_blocks(network, 1)
    print("Mempool size:", get_mempool_size(network))

    if not check_transaction_confirmed(network, "Cust Close from Escrow - should be confirmed", cust_close_txid):
        print("%s %s" % (emphasize("CPFP was not sufficient to bump cust close tx into the next block: "), confirmed_status(False)))
    else:
        print("%s %s" % (emphasize("CPFP successfully bumped up cust close tx into the next block: "), confirmed_status(True)))

    print("==============================================")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output_btc", "-btc", help="amount in btc to pay out to each output", default="1")
    parser.add_argument("--network", "-nw", help="select the type of network", default="simnet")
    parser.add_argument("--timelock", "-t", help="timelock for closing transactions", default="287")
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    parser.add_argument("--skip_restart", "-sr", help="restart btcd", action="store_true")
    parser.add_argument("--scenario", "-s", help="run a specific scenario", default="-1")

    args = parser.parse_args()

    network = str(args.network)
    output_btc = int(args.output_btc)
    blocks = int(args.timelock)
    scenario_index = int(args.scenario)
    skip_restart = args.skip_restart
    verbose = args.verbose

    print("Network: ", network)

    miner_privkey = "2222222222222222222222222222222222222222222222222222222222222222"
    coinbase_txid, amount_btc = make_n_coinbase_utxo_for_sk(miner_privkey, network, 1, skip_restart)
    print(coinbase_txid)
    # print("miner's utxo txid (little Endian) => " + coinbase_txid)
    # tests_to_run = [run_scenario_test0, run_scenario_test1, run_scenario_test2, run_scenario_test3, run_scenario_test4, run_scenario_test5, run_scenario_test6]
    tests_to_run = [run_scenario_test6]

    n_outputs = len(tests_to_run)

    output_privkeys = gen_privkeys(n_outputs)
    init_tx = np2wkh_to_n_p2wkh(coinbase_txid[0], 0, amount_btc[0], miner_privkey, n_outputs, output_btc)

    utxo_txid = subprocess.getoutput("btcctl --{net} --rpcuser=kek --rpcpass=kek sendrawtransaction {init_tx}".format(net=network, init_tx=init_tx))
    if verbose: print("init_tx utxo txid (little Endian) => %s" % emphasize(utxo_txid))

    output_privkeys_hex = [sk.hex() for sk in output_privkeys]
    if scenario_index in range(0, len(tests_to_run)):
        index = 0
        out = run_gowrapper(utxo_txid, index, output_privkeys_hex[index], blocks)
        if verbose: print("\n%s\n", out)
        time.sleep(2)
        tests_to_run[scenario_index](network, index, blocks)
    else:
        for index, scenario in enumerate(tests_to_run):
            run_gowrapper(utxo_txid, index, output_privkeys_hex[index], blocks)
            time.sleep(2)
            scenario(network, index, blocks)

    exit(0)

main()
