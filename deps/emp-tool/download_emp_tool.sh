#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=https://github.com/emp-toolkit/emp-tool.git
EMP_TOOL=${1:-emp-tool-${VERSION}}

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${EMP_TOOL}.git
cd ${EMP_TOOL}.git

if [[ ! -f ${EMP_TOOL}.${FORMAT} ]]; then
   echo "Patch emp-tool..."
   git apply ../uint.patch
   cp ../uinteger.h* emp-tool/circuits/
   cp ../uint.cpp test/
   git add emp-tool/circuits/uinteger.h*
   git add test/uint.cpp
   git commit -a -m "patching"

   echo "Create archive of source (without git files)"
   git archive --output ../${EMP_TOOL}.test.${FORMAT} HEAD 

   echo "Create final tarball: ${EMP_TOOL}.${FORMAT}"
   cd ..
   mkdir ${EMP_TOOL}
   cd ${EMP_TOOL}
   tar -xf ../${EMP_TOOL}.test.${FORMAT}


   cd ..
   tar -czf ${EMP_TOOL}.${FORMAT} ${EMP_TOOL}
   rm ${EMP_TOOL}.test.${FORMAT}
   rm -r ${EMP_TOOL} 
else
   echo "[!] ${EMP_TOOL}.tar.gz already exists." 
fi
