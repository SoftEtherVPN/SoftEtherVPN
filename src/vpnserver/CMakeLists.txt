add_executable(vpnserver vpnserver.c)

set_target_properties(vpnserver
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnserver"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnserver"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnserver"
)

target_link_libraries(vpnserver cedar mayaqua)
