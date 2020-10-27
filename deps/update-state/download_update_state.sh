#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=git@github.com:boltlabs-inc/update-state.git
UPDATE_STATE=${1:-update-state-${VERSION}}

LOCAL=${2:false} # literally any argument will prevent this from pulling the repo

if [[ ! ${LOCAL} ]]; then
    echo "Clone github repo @ ${LINK}"
    git clone ${LINK} ${UPDATE_STATE}.git
else
    echo "not cloning bye"
fi

cd ${UPDATE_STATE}.git

if [[ ! -f ${UPDATE_STATE}.${FORMAT} ]]; then
    echo "Create archive of source (without git files)"
    if [[ ${LOCAL} ]]; then
        # archives unstaged changes (but not untracked files)
        git ls-files | tar Tczf - ../${UPDATE_STATE}.test.${FORMAT}
    else 
        # archives committed changes
        git archive --output ../${UPDATE_STATE}.test.${FORMAT} HEAD
    fi

    echo "Create final tarball: ${UPDATE_STATE}.${FORMAT}"
    cd ..
    mkdir ${UPDATE_STATE}
    cd ${UPDATE_STATE}
    tar -xf ../${UPDATE_STATE}.test.${FORMAT}
 
    cd ..
    tar -czf ${UPDATE_STATE}.${FORMAT} ${UPDATE_STATE}
    rm ${UPDATE_STATE}.test.${FORMAT}
    rm -r ${UPDATE_STATE}
else
    echo "[!] ${UPDATE_STATE}.tar.gz already exists."
fi
