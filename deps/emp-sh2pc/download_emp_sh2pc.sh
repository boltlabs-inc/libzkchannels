#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=git@github.com:boltlabs-inc/emp-sh2pc.git
EMP_SH2PC=${1:-emp-sh2pc-${VERSION}}

LOCAL=${2:false} # literally any argument will prevent this from pulling the repo

if [[ ! ${LOCAL} ]]; then
    echo "Clone github repo @ ${LINK}"
    git clone ${LINK} ${EMP_SH2PC}.git
else
    echo "not cloning bye"
fi

cd ${EMP_SH2PC}.git

if [[ ! -f ${EMP_SH2PC}.${FORMAT} ]]; then
    echo "Create archive of source (without git files)"
    if [[ ${LOCAL} ]]; then
        # archives unstaged changes (but not untracked files)
        git ls-files | tar Tczf - ../${EMP_SH2PC}.test.${FORMAT}
    else 
        # archives committed changes
        git archive --output ../${EMP_SH2PC}.test.${FORMAT} HEAD
   fi

    echo "Create final tarball: ${EMP_SH2PC}.${FORMAT}"
    cd ..
    mkdir ${EMP_SH2PC}
    cd ${EMP_SH2PC}
    tar -xf ../${EMP_SH2PC}.test.${FORMAT}
 
    cd ..
    tar -czf ${EMP_SH2PC}.${FORMAT} ${EMP_SH2PC}
    rm ${EMP_SH2PC}.test.${FORMAT}
    rm -r ${EMP_SH2PC} 
else
    echo "[!] ${EMP_SH2PC}.tar.gz already exists." 
fi
