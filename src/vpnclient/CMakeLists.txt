set(COMPONENT_NAME "Client")
set(COMPONENT_INTERNAL_NAME "vpnclient")

add_executable(vpnclient vpncsvc.c vpncsvc.h)

set_target_properties(vpnclient
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpnclient
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpnclient NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_BINARY_DIR}/VerScript/vpnclient.rc")
  target_sources(vpnclient PRIVATE vpnclient.rc "${CMAKE_BINARY_DIR}/VerScript/vpnclient.rc")
endif()

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

  install_wrapper_script("vpnclient" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnclient/vpnclient")
  if(NOT "${CMAKE_INSTALL_SYSTEMD_UNITDIR}" STREQUAL "")
    configure_file(${TOP_DIRECTORY}/systemd/softether-vpnclient.service ${CMAKE_BINARY_DIR}/systemd/softether-vpnclient.service)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/softether-vpnclient.service
      COMPONENT "vpnclient"
      DESTINATION ${CMAKE_INSTALL_SYSTEMD_UNITDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
  endif()
endif()
