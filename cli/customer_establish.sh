#!/bin/bash

mode=release

name=$1
if [[ $name == "" ]]; then
    echo "Did not specify a channel name."
    exit -1
fi

echo "opening a channel: '$name'"
../target/$mode/zkchannels-mpc open --party CUST --other-port 12347 --own-port 12346 --cust-bal 9000 --merch-bal 0 --channel-name "$name" 

../target/$mode/zkchannels-mpc init --party CUST --other-port 12347 --own-port 12346 --index 0 --input-sats 10000 --output-sats 9000 --channel-name "$name" --txid f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1 

echo "activating channel: '$name'"
../target/$mode/zkchannels-mpc activate --party CUST --other-port 12347 --own-port 12346 --channel-name "$name"
echo "established!"

echo "now we can unlink: '$name'"
../target/$mode/zkchannels-mpc unlink --party CUST --other-port 12347 --own-port 12346 --channel-name "$name" -v
