#!/bin/bash

SERVER_ONLY="no"
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
    eval $__out="`lsb_release -cs`"
  else
    eval $__out="unknown_version"
  fi
}

if [[ $ZK_DEPS_INSTALL = "" ]]; then
   echo "Did not set env in the root directory"
   exit 1
fi
DEP_LIB=$ZK_DEPS_INSTALL/lib/$1

function main() {
  platform OS
  distro $OS OS_VERSION

  if [[ $OS = "darwin" ]]; then
    console "Detected Mac OS X ($OS_VERSION)"
    set -x
    install_name_tool -id ${DEP_LIB}.dylib ${DEP_LIB}.dylib
    set +x
  fi
}

main $1

