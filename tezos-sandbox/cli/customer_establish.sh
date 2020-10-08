#!/bin/bash

mode=release

name=$1
if [[ $name == "" ]]; then
    echo "Did not specify a channel name."
    exit -1
fi

echo "opening a channel: '$name'"
zkchannels-cli open --party CUST --other-port 12347 --own-port 12346 --cust-bal 20000 --merch-bal 2546 --channel-name "$name" 

zkchannels-cli init --party CUST --other-port 12347 --own-port 12346 --index 0 --input-sats 50000 --output-sats 20000 --channel-name "$name" 

echo "activating channel: '$name'"
zkchannels-cli activate --party CUST --other-port 12347 --own-port 12346 --channel-name "$name"
echo "established!"

echo "now we can unlink: '$name'"
zkchannels-cli unlink --party CUST --other-port 12347 --own-port 12346 --channel-name "$name" -v
