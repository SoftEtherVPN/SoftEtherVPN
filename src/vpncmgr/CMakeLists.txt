if(NOT WIN32)
  message(FATAL_ERROR "VPN Client Manager is available only for Windows.")
endif()

set(COMPONENT_NAME "Client Manager")
set(COMPONENT_INTERNAL_NAME "vpncmgr")

add_executable(vpncmgr WIN32 vpncmgr.c vpncmgr.rc)

get_filename_component(COMPONENT_FILE_NAME vpncmgr NAME)
set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
target_sources(vpncmgr PRIVATE "vpncmgr.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
  target_sources(vpncmgr PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x64_user.manifest")
else()
  target_sources(vpncmgr PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x86_user.manifest")
endif()

set_target_properties(vpncmgr
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpncmgr cedar mayaqua)
