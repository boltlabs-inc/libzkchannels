#!/bin/bash

VERSION=0.1
FORMAT=tar.gz
LINK=https://github.com/boltlabs-inc/emp-tool.git
EMP_TOOL=${1:-emp-tool-${VERSION}}

LOCAL=${2:false} # literally any argument will prevent this from pulling the repo

if [[ ! ${LOCAL} ]]; then
	echo "Clone github repo @ ${LINK}"
	git clone ${LINK} ${EMP_TOOL}.git
else
	echo "not cloning bye"
fi

cd ${EMP_TOOL}.git

if [[ ! -f ${EMP_TOOL}.${FORMAT} ]]; then
   echo "Create archive of source (without git files)"
   if [[ ${LOCAL} ]]; then
	   # archives unstaged changes (but not untracked files)
	   git ls-files | tar Tczf - ../${EMP_TOOL}.test.${FORMAT}
   else 
	   # archives committed changes
	   git archive --output ../${EMP_TOOL}.test.${FORMAT} HEAD
   fi

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
