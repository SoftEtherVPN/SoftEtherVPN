add_executable(vpnclient vpncsvc.c)

set_target_properties(vpnclient
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnclient cedar mayaqua)

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
if(EXISTS "/lib/systemd/system")
  configure_file(${CMAKE_SOURCE_DIR}/systemd/softether-vpnclient.service ${CMAKE_SOURCE_DIR}/tmp/systemd/softether-vpnclient.service)
  install(FILES ${CMAKE_SOURCE_DIR}/tmp/systemd/softether-vpnclient.service
    COMPONENT "vpnclient"
    DESTINATION "/lib/systemd/system"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
  )
endif()
