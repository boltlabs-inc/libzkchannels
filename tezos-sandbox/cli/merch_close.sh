#!/bin/bash

CHAN_ID=$1
CUST_CLOSE=$2

zkchannels-cli close --party MERCH --file merch_close.json --channel-name "$CHAN_ID" --cust-close $CUST_CLOSE
