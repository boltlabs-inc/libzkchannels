#!/bin/bash

mode=release

zkchannels-cli setfees

zkchannels-cli open --party MERCH --own-port 12347 --other-port 12346

zkchannels-cli init --party MERCH --own-port 12347 --other-port 12346

zkchannels-cli activate --party MERCH --own-port 12347 --other-port 12346

zkchannels-cli unlink --party MERCH --own-port 12347 --other-port 12346
