add_executable(vpnclient vpncsvc.c)

set_target_properties(vpnclient
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnclient"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnclient"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpnclient"
)

target_link_libraries(vpnclient cedar mayaqua)
