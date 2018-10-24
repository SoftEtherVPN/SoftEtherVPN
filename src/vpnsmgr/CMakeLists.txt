if(NOT WIN32)
  message(FATAL_ERROR "VPN Server Manager is available only for Windows.")
endif()

set(VPNSMGR_SOURCES vpnsmgr.c vpnsmgr.rc)

if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
  set(VPNSMGR_SOURCES ${VPNSMGR_SOURCES} ${CMAKE_SOURCE_DIR}/src/BuildFiles/Manifests/x64_user.manifest)
else()
  set(VPNSMGR_SOURCES ${VPNSMGR_SOURCES} ${CMAKE_SOURCE_DIR}/src/BuildFiles/Manifests/x86_user.manifest)
endif()

add_executable(vpnsmgr WIN32 ${VPNSMGR_SOURCES})

set_target_properties(vpnsmgr
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnsmgr cedar mayaqua)
