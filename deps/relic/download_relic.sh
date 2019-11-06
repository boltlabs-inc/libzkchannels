#!/bin/bash

VERSION=0.5.0
FORMAT=tar.gz
LINK=https://github.com/relic-toolkit/relic
RELIC=${1:-relic-toolkit-${VERSION}}
# commit of as of 10/28/2019
COMMIT=f93e1524fb4e234555a9f7a02b12b7be197d9acf

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${RELIC}.git
cd ${RELIC}.git
git reset --hard ${COMMIT}

if [[ ! -f ${RELIC}.${FORMAT} ]]; then
   echo "Create archive of source (without git files)"
   git archive --output ../${RELIC}.test.${FORMAT} HEAD 

   echo "Create final tarball: ${RELIC}.${FORMAT}"
   cd ..
   mkdir ${RELIC}
   cd ${RELIC}
   tar -xf ../${RELIC}.test.${FORMAT}

   cd ..
   tar -czf ${RELIC}.${FORMAT} ${RELIC}
   rm ${RELIC}.test.${FORMAT}
   rm -r ${RELIC} 
else
   echo "[!] ${RELIC}.tar.gz already exists." 
fi
