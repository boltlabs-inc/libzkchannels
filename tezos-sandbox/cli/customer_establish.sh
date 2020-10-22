#!/bin/bash

mode=release

name=$1
if [[ $name == "" ]]; then
    echo "Did not specify a channel name."
    exit -1
fi

echo "opening a channel: '$name'"
zkchannels-cli open --party CUST --other-port 12347 --own-port 12346 --cust-bal 20000 --merch-bal 1000 --channel-name "$name" 

zkchannels-cli init --party CUST --other-port 12347 --own-port 12346 --input-amount 30000 --output-amount 20000 --channel-name "$name" 

echo "activating channel: '$name'"
zkchannels-cli activate --party CUST --other-port 12347 --own-port 12346 --channel-name "$name"
echo "established!"

echo "now we can unlink: '$name'"
zkchannels-cli unlink --party CUST --other-port 12347 --own-port 12346 --channel-name "$name" -v
