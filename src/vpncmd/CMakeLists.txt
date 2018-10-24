set(VPNCMD_SOURCES vpncmd.c)

if(WIN32)
  set(VPNCMD_SOURCES ${VPNCMD_SOURCES} vpncmd.rc)
endif()

add_executable(vpncmd ${VPNCMD_SOURCES})

set_target_properties(vpncmd
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpncmd cedar mayaqua)

if(UNIX)
  # Copy binary and "hamcore.se2" to /usr/lib(exec)/softether/, install launch script
  install(TARGETS vpncmd
    COMPONENT "vpncmd"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpncmd"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )

  install(FILES "${BUILD_DIRECTORY}/hamcore.se2"
    COMPONENT "vpncmd"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether/vpncmd"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
  )

  install_wrapper_script("vpncmd" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpncmd/vpncmd")
endif()
