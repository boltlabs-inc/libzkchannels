#!/bin/bash

CENTOS_RELEASE=/etc/centos-release
REDHAT_RELEASE=/etc/redhat-release
FEDORA_RELEASE=/etc/fedora-release
LSB_RELEASE=/etc/lsb-release
ORACLE_RELEASE=/etc/oracle-release
SYSTEM_RELEASE=/etc/system-release
DEBIAN_VERSION=/etc/debian_version

function console() {
  echo "[+] $1"
}

PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function fail() {
  printf "${RED}[!] $1${NC}\n"
  exit 1
}

function platform() {
  local  __out=$1
  if [[ -f "$LSB_RELEASE" ]] && grep -q 'DISTRIB_ID=Ubuntu' $LSB_RELEASE; then
    FAMILY="debian"
    eval $__out="ubuntu"
  elif [[ -f "$DEBIAN_VERSION" ]]; then
    FAMILY="debian"
    eval $__out="debian"
  elif [[ -f "$FEDORA_RELEASE" ]]; then
    FAMILY="fedora"
    eval $__out="fedora"
  elif [[ -f "$CENTOS_RELEASE" ]]; then
    FAMILY="centos"
    eval $__out="centos"
  elif [[ -f "$REDHAT_RELEASE" ]]; then
    FAMILY="redhat"
    eval $__out="redhat"
  else
    eval $__out=`uname -s | tr '[:upper:]' '[:lower:]'`
  fi
}

function distro() {
  local __out=$2
  if [[ $1 = "ubuntu" ]]; then
    eval $__out=`awk -F= '/DISTRIB_CODENAME/ { print $2 }' $LSB_RELEASE`
  elif [[ $1 = "darwin" ]]; then
    eval $__out=`sw_vers -productVersion | awk -F '.' '{print $1 "." $2}'`
  elif [[ $1 = "debian" ]]; then
    eval $__out="`cat /etc/os-release | grep 'VERSION=' | cut -c 9-`"
  else
    eval $__out="unknown_version"
  fi
}

function install_pkgs_ubuntu() {
    CC=`lsb_release -rs | cut -c 1-2`
    VER=`expr $CC + 0`
    if [[ $VER -gt 15 ]]; then
        sudo apt-get install -y software-properties-common
        sudo apt-get update
        sudo apt-get install -y cmake git build-essential libssl-dev libgmp-dev python
        sudo apt-get install -y libboost-dev
        sudo apt-get install -y libboost-{chrono,log,program-options,date-time,thread,system,filesystem,regex,test}-dev
        sudo apt-get install -y libcrypto++ libcrypto++-dev 
	sudo apt-get install -y llvm-dev libclang-dev clang
        sudo apt-get install -y redis-server
    else
        sudo apt-get install -y software-properties-common
        sudo add-apt-repository -y ppa:george-edison55/cmake-3.x
        sudo add-apt-repository -y ppa:kojoley/boost
        sudo apt-get -y update
        sudo apt-get -y upgrade
        sudo apt-get install -y cmake git build-essential libssl-dev libgmp-dev python
        sudo apt-get install -y libboost1.58-dev
        sudo apt-get install -y libboost-{chrono,log,program-options,date-time,thread,system,filesystem,regex,test}1.58-dev
        sudo apt-get install -y llvm-dev libclang-dev clang
        sudo apt-get install -y redis-server
        sudo apt-get install -y libcrypto++-dev libcrypto++9v5 
    fi
}

function install_pkgs_debian() {
    sudo apt -y update
    sudo apt -y upgrade
    sudo apt install -y cmake git build-essential libssl-dev libgmp-dev python
    sudo apt install -y libboost1.67-dev libboost-system1.67-dev
    sudo apt install -y libcrypto++ llvm-dev libclang-dev clang
    sudo apt install -y redis-server
    sudo apt install -y python3 python3-pip
}

INSTALL=.installed
if test -f "$INSTALL"; then
    echo "Already ran the $0 script."
fi

if [[ "$(uname)" = "Darwin" ]]; then
    console "Detected Mac OS X ($(uname))"
	brew update
	brew list openssl || brew install openssl
	brew list xctool || brew install xctool
	brew list pkg-config || brew install pkg-config
	brew list cmake || brew install cmake
	brew list gmp || brew install gmp
	brew list boost || brew install boost
	brew list llvm || brew install llvm
	brew list cryptopp || brew install cryptopp
	brew list redis || brew install redis
else
  platform OS
  distro $OS OS_VERSION

  if [[ $OS = "ubuntu" ]]; then
    console "Detected Ubuntu ($OS_VERSION)"
    install_pkgs_ubuntu
  elif [[ $OS = "debian" ]]; then
    console "Detected Debian ($OS_VERSION)"
    install_pkgs_debian
  else
    fail "Need install steps for your OS: ($OS_VERSION)"
  fi
fi

touch $INSTALL
