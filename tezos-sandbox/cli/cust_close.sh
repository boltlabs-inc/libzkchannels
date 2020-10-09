#!/bin/bash

CUST_CLOSE=$1 # cust_close.json
CHAN_ALIAS=$2

zkchannels-cli close --party CUST --channel-id "alice" --file $CUST_CLOSE --decompress-cust-close
