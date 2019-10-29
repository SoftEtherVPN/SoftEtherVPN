set(COMPONENT_NAME "Bridge")
set(COMPONENT_INTERNAL_NAME "vpnbridge")

add_executable(vpnbridge vpnbridge.c)

set_target_properties(vpnbridge
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpnbridge
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpnbridge NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_BINARY_DIR}/VerScript/vpnbridge.rc")
  target_sources(vpnbridge PRIVATE vpnbridge.rc "${CMAKE_BINARY_DIR}/VerScript/vpnbridge.rc")
endif()

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

  install_wrapper_script("vpnbridge" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnbridge/vpnbridge")
  if(NOT "${CMAKE_INSTALL_SYSTEMD_UNITDIR}" STREQUAL "")
    configure_file(${TOP_DIRECTORY}/systemd/softether-vpnbridge.service ${CMAKE_BINARY_DIR}/systemd/softether-vpnbridge.service)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/softether-vpnbridge.service
      COMPONENT "vpnbridge"
      DESTINATION ${CMAKE_INSTALL_SYSTEMD_UNITDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
  endif()
endif()
