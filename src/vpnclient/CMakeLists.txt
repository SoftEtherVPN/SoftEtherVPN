set(COMPONENT_NAME "Client")
set(COMPONENT_INTERNAL_NAME "vpnclient")

if(WIN32)
  add_executable(vpnclient WIN32 vpncsvc.c vpncsvc.h)

  set_target_properties(vpnclient
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpnclient NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
  target_sources(vpnclient PRIVATE "vpnclient.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

  if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
    target_sources(vpnclient PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x64_user.manifest")
  else()
    target_sources(vpnclient PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x86_user.manifest")
  endif()
else()
  add_executable(vpnclient vpncsvc.c vpncsvc.h)
endif()

set_target_properties(vpnclient
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnclient cedar mayaqua)

if(UNIX)
  # Copy binary and "hamcore.se2" to /usr/lib(exec)/softether/, install launch script and systemd service
  install(TARGETS vpnclient
    COMPONENT "vpnclient"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpnclient"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )

  install(FILES "${BUILD_DIRECTORY}/hamcore.se2"
    COMPONENT "vpnclient"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpnclient"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
  )

  install_wrapper_script("vpnclient")
  if(NOT "${CMAKE_INSTALL_SYSTEMD_UNITDIR}" STREQUAL "")
    install_unit_file("vpnclient")
  endif()
endif()
