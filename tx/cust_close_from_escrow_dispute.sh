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
CUST_CLOSE_FROM_ESCROW=`cat signed_first_cust_close_escrow_tx.txt`
MERCH_DISPUTE=`cat signed_dispute_tx.txt`

log_test "1. broadcast escrow tx"
btcctl --simnet --rpcuser=kek --rpcpass=kek sendrawtransaction $ESCROW
assert "STATUS: " 0 $?

log_test "2. broadcast cust-first-close-from-escrow tx (old state)"
btcctl --simnet --rpcuser=kek --rpcpass=kek sendrawtransaction $CUST_CLOSE_FROM_ESCROW
assert "STATUS: " 0 $?

log_test "3. merchant dispute cust-close-from-escrow tx"
btcctl --simnet --rpcuser=kek --rpcpass=kek sendrawtransaction $MERCH_DISPUTE
assert "STATUS: " 0 $?