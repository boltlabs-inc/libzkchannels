#!/bin/bash

mode=release
amount=$1

../target/$mode/zkchannels-mpc open --party MERCH --own-port 12347 --other-port 12346

../target/$mode/zkchannels-mpc init --party MERCH --own-port 12347 --other-port 12346 -b

../target/$mode/zkchannels-mpc activate --party MERCH --own-port 12347 --other-port 12346 -b

../target/$mode/zkchannels-mpc unlink --party MERCH --own-port 12347 --other-port 12346 --amount=$amount -b
