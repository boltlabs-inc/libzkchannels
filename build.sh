#!/usr/bin/env bash

LND_PATH=$1
FOUND_LND=0

if [[ $LND_PATH = "" ]]; then
   echo "Missing path to zklnd..."
fi

if [ -d "$LND_PATH/make" ]; then
   echo "Will output config to $LND_PATH/make"
   FOUND_LND=1
else
   echo "Did not specify correct path to zklnd..."
fi

unset ZK_DEPS_INSTALL 

ROOT=$(pwd)
ZK_DEPS_INSTALL=${ROOT}/deps/root

export ZK_DEPS_INSTALL
export LD_LIBRARY_PATH=${ZK_DEPS_INSTALL}/lib:${LD_LIBRARY_PATH}
export PATH=$ZK_DEPS_INSTALL/bin:$PATH

mkdir -p ${ZK_DEPS_INSTALL}/lib
mkdir -p ${ZK_DEPS_INSTALL}/bin

make -C deps 

./setup_redis.sh

cargo build --release --manifest-path ./Cargo.toml

echo "export CGO_LDFLAGS=\"-L$(pwd)/target/release\"" > libzkchannels.mk
echo "export LD_LIBRARY_PATH=\"$(pwd)/target/release\"" >> libzkchannels.mk

if [ $FOUND_LND -eq 1 ]; then
   echo "Save libzkchannels build config to $LND_PATH/make"
   cp -v libzkchannels.mk $LND_PATH/make/
fi
