cmake_minimum_required (VERSION 2.8.11)
project (emp-ag2pc)
set(NAME "emp-ag2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)

include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

FIND_PACKAGE(emp-ot REQUIRED)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})

install(DIRECTORY emp-ag2pc DESTINATION include)
install(DIRECTORY cmake/ DESTINATION cmake)
install(FILES tokens/tokens.h DESTINATION include/emp-ag2pc)
install(FILES tokens/translation.h DESTINATION include/emp-ag2pc)
install(FILES tokens/test-e2e.h DESTINATION include/emp-ag2pc)
install(FILES tokens/sha256.h DESTINATION include/emp-ag2pc)

add_library(tokenm-utils SHARED tokens/tokens.cpp tokens/translation.cpp)
add_library(test-e2e SHARED tokens/test-e2e.cpp tokens/translation.cpp)
target_link_libraries(tokenm-utils ${EMP-OT_LIBRARIES})
target_link_libraries(test-e2e ${EMP-OT_LIBRARIES})

install(TARGETS tokenm-utils DESTINATION lib)
install(TARGETS test-e2e DESTINATION lib)

# Test cases
macro (add_test _name)
  add_executable(${_name} "test/${_name}.cpp")
  target_link_libraries(${_name}
    ${EMP-OT_LIBRARIES}
    tokenm-utils)
endmacro()

add_test(aes)
add_test(sha1)
#add_test(sha256)
add_test (simple_circuit)
add_test(addition)
add_test(translation)
#add_test (abit)
#add_test (amortized_2pc)

add_test(tokens-main)

