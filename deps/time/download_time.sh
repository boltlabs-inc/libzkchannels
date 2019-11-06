#!/bin/bash

VERSION=$1
if [[ $VERSION = "" ]]; then
    echo "[!] Missing version as argument"
    exit 0
fi

GTEST_VERSION=time-${VERSION}.tar.gz
GTEST_LINK=https://ftp.gnu.org/gnu/time/${GTEST_VERSION}

if [[ ! -f ${GTEST_VERSION} ]]; then
    wget -O ${GTEST_VERSION} ${GTEST_LINK}
fi
