if(NOT WIN32)
  message(FATAL_ERROR "VPN Setup is available only for Windows.")
endif()

set(COMPONENT_NAME "Setup")
set(COMPONENT_INTERNAL_NAME "vpnsetup")

add_executable(vpnsetup WIN32
  "vpnsetup.c"
  "vpnsetup.rc"

  "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
)

get_filename_component(COMPONENT_FILE_NAME vpnsetup NAME)
set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
target_sources(vpnsetup PRIVATE "vpnsetup.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

set_target_properties(vpnsetup
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnsetup cedar)
