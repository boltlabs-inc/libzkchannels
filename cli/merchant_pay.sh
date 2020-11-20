#!/bin/bash

mode=release

../target/$mode/zkchannels-mpc pay --party MERCH --own-port 12347 --other-port 12346 -b
