#!/bin/bash

mode=release
name=$1
amount=$2

set -x
../target/$mode/zkchannels-mpc pay --party CUST --other-port 12347 --own-port 12346 --channel-name "$name" --amount=$amount -b -v
set +x
