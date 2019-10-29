set(COMPONENT_NAME "Server")
set(COMPONENT_INTERNAL_NAME "vpnserver")

add_executable(vpnserver vpnserver.c)

set_target_properties(vpnserver
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpnserver
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpnserver NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_BINARY_DIR}/VerScript/vpnserver.rc")
  target_sources(vpnserver PRIVATE vpnserver.rc "${CMAKE_BINARY_DIR}/VerScript/vpnserver.rc")
endif()

target_link_libraries(vpnserver cedar mayaqua)

if(UNIX)
  # Copy binary and "hamcore.se2" to /usr/lib(exec)/softether/, install launch script and systemd service
  install(TARGETS vpnserver
    COMPONENT "vpnserver"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpnserver"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )

  install(FILES "${BUILD_DIRECTORY}/hamcore.se2"
    COMPONENT "vpnserver"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpnserver"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
  )

  install_wrapper_script("vpnserver" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnserver/vpnserver")
  if(NOT "${CMAKE_INSTALL_SYSTEMD_UNITDIR}" STREQUAL "")
    configure_file(${TOP_DIRECTORY}/systemd/softether-vpnserver.service ${CMAKE_BINARY_DIR}/systemd/softether-vpnserver.service)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/softether-vpnserver.service
      COMPONENT "vpnserver"
      DESTINATION ${CMAKE_INSTALL_SYSTEMD_UNITDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
  endif()
endif()
