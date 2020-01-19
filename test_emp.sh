#!/bin/bash

. ./env

# assuming make deps successfully built emp-toolkit

sha256 1 12345 &
sha256 2 12345 &

wait $!
echo "Done!"
