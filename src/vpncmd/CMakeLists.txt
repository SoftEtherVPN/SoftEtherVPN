add_executable(vpncmd vpncmd.c)

set_target_properties(vpncmd
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpncmd"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpncmd"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}/vpncmd"
)

target_link_libraries(vpncmd cedar mayaqua)
