#!/bin/bash

mode=debug

../target/$mode/zkchannels-mpc open --party CUST --other-port 12347 --own-port 12346 --cust-bal 9000 --merch-bal 0 

../target/$mode/zkchannels-mpc init --party CUST --other-port 12347 --own-port 12346 --index 0 --input-sats 10000 --output-sats 9000 --txid f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1 

../target/$mode/zkchannels-mpc activate --party CUST --other-port 12347 --own-port 12346

../target/$mode/zkchannels-mpc unlink --party CUST --other-port 12347 --own-port 12346 -v
