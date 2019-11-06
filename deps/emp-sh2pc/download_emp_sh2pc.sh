#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=https://github.com/emp-toolkit/emp-sh2pc.git
EMP_SH2PC=${1:-emp-sh2pc-${VERSION}}

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${EMP_SH2PC}.git
cd ${EMP_SH2PC}.git

if [[ ! -f ${EMP_SH2PC}.${FORMAT} ]]; then

   cp ../*.cpp test
   echo "add_test (ecdsa)" >> CMakeLists.txt
   echo "add_test (sha256)" >> CMakeLists.txt
   git add test/*.cpp
   git commit -a -m "Patching..."

   echo "Create archive of source (without git files)"
   git archive --output ../${EMP_SH2PC}.test.${FORMAT} HEAD

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
