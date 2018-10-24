set(VPNBRIDGE_SOURCES vpnbridge.c)

if(WIN32)
  set(VPNBRIDGE_SOURCES ${VPNBRIDGE_SOURCES} vpnbridge.rc)
endif()

add_executable(vpnbridge ${VPNBRIDGE_SOURCES})

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

  install_wrapper_script("vpnbridge" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnbridge/vpnbridge")
  if(EXISTS "/lib/systemd/system")
    configure_file(${CMAKE_SOURCE_DIR}/systemd/softether-vpnbridge.service ${CMAKE_BINARY_DIR}/systemd/softether-vpnbridge.service)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/softether-vpnbridge.service
      COMPONENT "vpnbridge"
      DESTINATION "/lib/systemd/system"
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
  endif()
endif()
