if(NOT WIN32)
  message(FATAL_ERROR "VPN Driver Installer is available only for Windows.")
endif()

set(COMPONENT_NAME "Driver Installer")
set(COMPONENT_INTERNAL_NAME "vpndrvinst")

add_executable(vpndrvinst
  main.c
  Device.c
  Device.h
  Dialog.c
  Dialog.h
  Driver.c
  Driver.h
  Str.c
  Str.h

  "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
)

get_filename_component(COMPONENT_FILE_NAME vpndrvinst NAME)
set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
target_sources(vpndrvinst PRIVATE "vpndrvinst.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

if(MSVC)
  # Fixes manifest authoring error c1010001
  set_target_properties(vpndrvinst PROPERTIES LINK_FLAGS "/manifestuac:level='requireAdministrator'")
endif()

target_link_options(vpndrvinst PRIVATE "/MANIFESTUAC:level='requireAdministrator'")
# Hide console while keeping main() as entry point
target_link_options(vpndrvinst PRIVATE "/SUBSYSTEM:WINDOWS" "/ENTRY:mainCRTStartup")

set_target_properties(vpndrvinst
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  LIBRARY_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  RUNTIME_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpndrvinst
  PRIVATE
    libhamcore
    newdev.lib
    SetupAPI.Lib
)
