#!/bin/bash

ZKCHAN_PATH="$(pwd)/target/release"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ZKCHAN_PATH
export CGO_LDFLAGS="-L$(pwd)/target/release"
env | grep LD
go get -v github.com/stretchr/testify/assert
go test -v libzkchannels.go libzkchannels_test.go
