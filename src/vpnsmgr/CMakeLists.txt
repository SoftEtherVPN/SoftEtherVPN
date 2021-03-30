if(NOT WIN32)
  message(FATAL_ERROR "VPN Server Manager is available only for Windows.")
endif()

set(COMPONENT_NAME "Server Manager")
set(COMPONENT_INTERNAL_NAME "vpnsmgr")

add_executable(vpnsmgr WIN32
  "vpnsmgr.c"
  "vpnsmgr.rc"

  "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
)

get_filename_component(COMPONENT_FILE_NAME vpnsmgr NAME)
set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
target_sources(vpnsmgr PRIVATE "vpnsmgr.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

set_target_properties(vpnsmgr
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnsmgr cedar mayaqua)
