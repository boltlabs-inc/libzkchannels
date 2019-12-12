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
   cp ../tokens/* emp-sh2pc
   sed -i '' -e '11i\
   find_library(CRYPTOPP_LIBRARIES NAMES cryptopp libcryptopp )\
   MESSAGE(STATUS "CryptoPP libs: " ${CRYPTOPP_LIBRARIES} )\
   ' CMakeLists.txt
   sed -i '' -e '18i\
   \
   add_library(token-utils SHARED emp-sh2pc/sha256.cpp emp-sh2pc/hmac.cpp emp-sh2pc/ecdsa.cpp emp-sh2pc/tokens.cpp emp-sh2pc/tokens-misc.cpp)\
   target_link_libraries(token-utils ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${GMP_LIBRARIES} ${EMP-OT_LIBRARIES})\
   \
   install(TARGETS token-utils DESTINATION lib)\
   ' CMakeLists.txt
   sed -i '' -e '28i\
   \
   macro (add_test _name)\
\ \ add_executable(${_name} "test/${_name}.cpp")\
\ \ target_link_libraries(${_name}\
\ \ \ \ ${OPENSSL_LIBRARIES}\
\ \ \ \ ${Boost_LIBRARIES}\
\ \ \ \ ${GMP_LIBRARIES}\
\ \ \ \ ${EMP-OT_LIBRARIES}\
\ \ \ \ ${CRYPTOPP_LIBRARIES}\
\ \ \ \ token-utils)\
endmacro()\
   ' CMakeLists.txt
   sed -i '' -e '25,28d' CMakeLists.txt
   echo "add_test (ecdsa)" >> CMakeLists.txt
   echo "add_test (sha256)" >> CMakeLists.txt
   echo "add_test (hmac)" >> CMakeLists.txt
   git add test/*.cpp
   git add emp-sh2pc/*
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
