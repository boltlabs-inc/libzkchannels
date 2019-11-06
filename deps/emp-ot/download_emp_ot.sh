#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=https://github.com/emp-toolkit/emp-ot.git
EMP_OT=${1:-emp-ot-${VERSION}}

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${EMP_OT}.git
cd ${EMP_OT}.git

if [[ ! -f ${EMP_OT}.${FORMAT} ]]; then
   echo "Create archive of source (without git files)"
   git archive --output ../${EMP_OT}.test.${FORMAT} HEAD 

   echo "Create final tarball: ${EMP_OT}.${FORMAT}"
   cd ..
   mkdir ${EMP_OT}
   cd ${EMP_OT}
   tar -xf ../${EMP_OT}.test.${FORMAT}

   cd ..
   tar -czf ${EMP_OT}.${FORMAT} ${EMP_OT}
   rm ${EMP_OT}.test.${FORMAT}
   rm -r ${EMP_OT} 
else
   echo "[!] ${EMP_OT}.tar.gz already exists." 
fi
