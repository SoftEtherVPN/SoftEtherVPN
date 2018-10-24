if(NOT WIN32)
  message(FATAL_ERROR "VPN Client Manager is available only for Windows.")
endif()

set(VPNCMGR_SOURCES vpncmgr.c vpncmgr.rc)

if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
  set(VPNCMGR_SOURCES ${VPNCMGR_SOURCES} ${CMAKE_SOURCE_DIR}/src/BuildFiles/Manifests/x64_user.manifest)
else()
  set(VPNCMGR_SOURCES ${VPNCMGR_SOURCES} ${CMAKE_SOURCE_DIR}/src/BuildFiles/Manifests/x86_user.manifest)
endif()

add_executable(vpncmgr WIN32 ${VPNCMGR_SOURCES})

set_target_properties(vpncmgr
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpncmgr cedar mayaqua)
