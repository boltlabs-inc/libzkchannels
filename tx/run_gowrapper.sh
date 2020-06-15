#!/bin/bash

export UTXO_TXID=$1
export UTXO_INDEX=$2
export UTXO_SK=$3
export TIMELOCK=$4
export FIX_CUSTOMER_WALLET=yes
export UTXO_SAVE_TX=yes
cd ..

ZKCHAN_PATH="$(pwd)/target/release"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ZKCHAN_PATH
export CGO_LDFLAGS="-L$(pwd)/target/release"
go get -v github.com/stretchr/testify/assert
go test -v libzkchannels.go libzkchannels_test.go

mkdir -p tx/txdata_$UTXO_INDEX
mv signed_* tx/txdata_$UTXO_INDEX

cd tx/
