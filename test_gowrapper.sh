#!/bin/bash

export LD_LIBRARY_PATH="-L$(pwd)/target/release"
export CGO_LDFLAGS="-L$(pwd)/target/release"
go test -v libzkchannels.go libzkchannels_test.go
