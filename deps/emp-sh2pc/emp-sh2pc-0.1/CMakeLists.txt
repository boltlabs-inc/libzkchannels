cmake_minimum_required (VERSION 2.8.11)
project (emp-sh2pc)
set(NAME "emp-sh2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-ot REQUIRED)
   find_library(CRYPTOPP_LIBRARIES NAMES cryptopp libcryptopp )
   MESSAGE(STATUS "CryptoPP libs: " ${CRYPTOPP_LIBRARIES} )
   
include_directories(${EMP-OT_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-sh2pc-config.cmake DESTINATION cmake/)
   
add_library(token-utils SHARED tokens/sha256.cpp tokens/hmac.cpp tokens/ecdsa.cpp tokens/tokens.cpp tokens/tokens-misc.cpp tokens/constants.cpp tokens/tx-builder.cpp tokens/test-e2e.cpp)
target_link_libraries(token-utils ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${GMP_LIBRARIES} ${EMP-OT_LIBRARIES})
   
install(TARGETS token-utils DESTINATION lib)
  
add_executable(generate-circuit tokens/generate-circuit.cpp)
target_link_libraries(generate-circuit
    ${EMP-OT_LIBRARIES}
    token-utils)
  
install(TARGETS generate-circuit DESTINATION bin)

install(DIRECTORY emp-sh2pc DESTINATION include/)
install(FILES tokens/tokens.h DESTINATION include/emp-sh2pc)
install(FILES tokens/test-e2e.h DESTINATION include/emp-sh2pc)

macro (add_test _name)
  add_executable(${_name} "test/${_name}.cpp")
  target_link_libraries(${_name}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${GMP_LIBRARIES}
    ${EMP-OT_LIBRARIES}
    ${CRYPTOPP_LIBRARIES}
    token-utils)
endmacro()
   
add_test (ecdsa)
add_test (sha256)
add_test (hmac)
add_test (bitcoin)
add_test (token-main)
