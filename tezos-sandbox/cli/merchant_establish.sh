#!/bin/bash

mode=release

../../target/$mode/zkchannels-cli setfees

../../target/$mode/zkchannels-cli open --party MERCH --own-port 12347 --other-port 12346

../../target/$mode/zkchannels-cli init --party MERCH --own-port 12347 --other-port 12346

../../target/$mode/zkchannels-cli activate --party MERCH --own-port 12347 --other-port 12346

../../target/$mode/zkchannels-cli unlink --party MERCH --own-port 12347 --other-port 12346
