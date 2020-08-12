find_package(emp-ot)

find_path(EMP-AG2PC_INCLUDE_DIR emp-ag2pc/emp-ag2pc.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(EMP-AG2PC DEFAULT_MSG EMP-AG2PC_INCLUDE_DIR)

if(EMP-AG2PC_FOUND)
	set(EMP-AG2PC_INCLUDE_DIRS ${EMP-AG2PC_INCLUDE_DIR} ${EMP-OT_INCLUDE_DIRS})
	set(EMP-AG2PC_LIBRARIES ${EMP-OT_LIBRARIES})
endif()
