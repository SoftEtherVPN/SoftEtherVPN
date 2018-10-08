add_executable(vpntest vpntest.c vpntest.h)

set_target_properties(vpntest
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpntest"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpntest"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpntest"
)

target_link_libraries(vpntest cedar mayaqua)
