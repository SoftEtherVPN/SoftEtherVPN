add_executable(vpnbridge vpnbridge.c)

set_target_properties(vpnbridge
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/vpnbridge"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnbridge"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnbridge"
)

target_link_libraries(vpnbridge cedar mayaqua)
