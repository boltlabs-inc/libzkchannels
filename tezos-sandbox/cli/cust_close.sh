#!/bin/bash

CUST_CLOSE=$1 # cust_close.json
CHAN_ALIAS=$2

zkchannels-cli close --party CUST --channel-name $CHAN_ALIAS --file $CUST_CLOSE --decompress-cust-close
