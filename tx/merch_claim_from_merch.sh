#!/bin/bash

PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function assert()
{
    msg=$1; shift
    expected=$1; shift
    actual=$1; shift
    printf "${PURPLE}[+] $msg:${NC} "
    if [ "$expected" != "$actual" ]; then
        printf "${RED}FAILED with ERROR=$actual${NC}\n"
    else
        printf "${GREEN}PASSED${NC}\n"
    fi
}

function log_test() {
    printf "${PURPLE}- Testing $1${NC}\n"
}

ESCROW=`cat signed_escrow.txt`
MERCH_CLOSE_TX=`cat signed_merch_close.txt`
MERCH_CLAIM_FROM_MERCH=`cat signed_merch_claim_merch_close_tx.txt`

log_test "1. broadcast escrow tx"
btcctl --simnet --rpcuser=kek --rpcpass=kek sendrawtransaction $ESCROW
assert "STATUS: " 0 $?

log_test "2. broadcast merch-close-tx"
btcctl --simnet --rpcuser=kek --rpcpass=kek sendrawtransaction $MERCH_CLOSE_TX
assert "STATUS: " 0 $?

log_test "3. wait for 1487 blocks"
btcctl --simnet --rpcuser=kek --rpcpass=kek generate 1487
assert "STATUS: " 0 $?

log_test "4. broadcast merch-claim (spending from merch-close-tx after timeout)"
btcctl --simnet --rpcuser=kek --rpcpass=kek sendrawtransaction $MERCH_CLAIM_FROM_MERCH
assert "STATUS: " 0 $?
