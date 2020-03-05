#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=https://github.com/boltlabs-inc/emp-ag2pc.git
EMP_AG2PC=${1:-emp-ag2pc-${VERSION}}

LOCAL=${2:false} # literally any argument will prevent this from pulling the repo

if [[ ! ${LOCAL} ]]; then
    echo "Clone github repo @ ${LINK}"
    git clone ${LINK} ${EMP_AG2PC}.git
else
    echo "not cloning bye"
fi

cd ${EMP_AG2PC}.git

if [[ ! -f ${EMP_AG2PC}.${FORMAT} ]]; then
    echo "Create archive of source (without git files)"
    if [[ ${LOCAL} ]]; then
        # archives unstaged changes (but not untracked files)
        git ls-files | tar Tczf - ../${EMP_AG2PC}.test.${FORMAT}
    else 
        # archives committed changes
        git archive --output ../${EMP_AG2PC}.test.${FORMAT} HEAD
    fi

    echo "Create final tarball: ${EMP_AG2PC}.${FORMAT}"
    cd ..
    mkdir ${EMP_AG2PC}
    cd ${EMP_AG2PC}
    tar -xf ../${EMP_AG2PC}.test.${FORMAT}
 
    cd ..
    tar -czf ${EMP_AG2PC}.${FORMAT} ${EMP_AG2PC}
    rm ${EMP_AG2PC}.test.${FORMAT}
    rm -r ${EMP_AG2PC}
else
    echo "[!] ${EMP_AG2PC}.tar.gz already exists."
fi
