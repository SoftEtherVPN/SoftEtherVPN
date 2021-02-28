set(COMPONENT_NAME "Testing Utility")
set(COMPONENT_INTERNAL_NAME "vpntest")

add_executable(vpntest vpntest.c vpntest.h)

set_target_properties(vpntest
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpntest
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpntest NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
  target_sources(vpntest PRIVATE "vpntest.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

  if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
    target_sources(vpntest PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x64_user.manifest")
  else()
    target_sources(vpntest PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x86_user.manifest")
  endif()
endif()

target_link_libraries(vpntest cedar mayaqua)
