if(NOT WIN32)
  message(FATAL_ERROR "VPN Driver Installer is available only for Windows.")
endif()

set(COMPONENT_NAME "Driver Installer")
set(COMPONENT_INTERNAL_NAME "vpndrvinst")

add_executable(vpndrvinst WIN32 vpndrvinst.c vpndrvinst.h)

get_filename_component(COMPONENT_FILE_NAME vpndrvinst NAME)
set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
target_sources(vpndrvinst PRIVATE "vpndrvinst.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

# Fixes manifest authoring error c1010001
set_target_properties(vpndrvinst PROPERTIES LINK_FLAGS "/MANIFESTUAC:level='requireAdministrator'")

if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
  target_sources(vpndrvinst PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x64_admin.manifest")
else()
  target_sources(vpndrvinst PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x86_admin.manifest")
endif()

set_target_properties(vpndrvinst
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  LIBRARY_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  RUNTIME_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpndrvinst cedar mayaqua)
