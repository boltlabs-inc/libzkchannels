#!/bin/bash

mode=release
#amount=${1:-100}

../target/$mode/zkchannels-mpc pay --party CUST --other-port 12347 --own-port 12346 --amount=$1 -v
