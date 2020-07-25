set(COMPONENT_NAME "Bridge")
set(COMPONENT_INTERNAL_NAME "vpnbridge")

if(WIN32)
  add_executable(vpnbridge WIN32 vpnbridge.c)

  set_target_properties(vpnbridge
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpnbridge NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
  target_sources(vpnbridge PRIVATE "vpnbridge.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

  if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
    target_sources(vpnbridge PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x64_user.manifest")
  else()
    target_sources(vpnbridge PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x86_user.manifest")
  endif()
else()
  add_executable(vpnbridge vpnbridge.c)
endif()

set_target_properties(vpnbridge
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnbridge cedar mayaqua)

if(UNIX)
  # Copy binary and "hamcore.se2" to /usr/lib(exec)/softether/, install launch script and systemd service
  install(TARGETS vpnbridge
    COMPONENT "vpnbridge"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpnbridge"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )

  install(FILES "${BUILD_DIRECTORY}/hamcore.se2"
    COMPONENT "vpnbridge"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpnbridge"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
  )

  install_wrapper_script("vpnbridge")
  if(NOT "${CMAKE_INSTALL_SYSTEMD_UNITDIR}" STREQUAL "")
    install_unit_file("vpnbridge")
  endif()
endif()
