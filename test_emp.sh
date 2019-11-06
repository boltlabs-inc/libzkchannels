#!/bin/bash

. ./env

# assuming make deps successfully built emp-toolkit

sha256 1 12345 &
sha256 2 12345 &

ecdsa 1 12346 &
ecdsa 2 12346 &

wait $!
echo "Done!"
