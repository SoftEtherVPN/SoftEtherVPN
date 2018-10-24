set(VPNTEST_SOURCES vpntest.c vpntest.h)

if(WIN32)
  if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
    set(VPNTEST_SOURCES ${VPNTEST_SOURCES} ${CMAKE_SOURCE_DIR}/src/BuildFiles/Manifests/x64_user.manifest)
  else()
    set(VPNTEST_SOURCES ${VPNTEST_SOURCES} ${CMAKE_SOURCE_DIR}/src/BuildFiles/Manifests/x86_user.manifest)
  endif()
endif()

add_executable(vpntest ${VPNTEST_SOURCES})

set_target_properties(vpntest
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpntest cedar mayaqua)
