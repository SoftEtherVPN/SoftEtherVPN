set(VPNSERVER_SOURCES vpnserver.c)

if(WIN32)
  set(VPNSERVER_SOURCES ${VPNSERVER_SOURCES} vpnserver.rc)
endif()

add_executable(vpnserver ${VPNSERVER_SOURCES})

set_target_properties(vpnserver
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

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
  if(EXISTS "/lib/systemd/system")
    configure_file(${CMAKE_SOURCE_DIR}/systemd/softether-vpnserver.service ${CMAKE_BINARY_DIR}/systemd/softether-vpnserver.service)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/softether-vpnserver.service
      COMPONENT "vpnserver"
      DESTINATION "/lib/systemd/system"
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
  endif()
endif()
