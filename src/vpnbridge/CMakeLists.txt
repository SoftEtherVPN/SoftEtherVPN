add_executable(vpnbridge vpnbridge.c)

set_target_properties(vpnbridge
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnbridge"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnbridge"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnbridge"
)

target_link_libraries(vpnbridge cedar mayaqua)
