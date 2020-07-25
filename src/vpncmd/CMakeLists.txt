set(COMPONENT_NAME "Command Line Management Utility")
set(COMPONENT_INTERNAL_NAME "vpncmd")

add_executable(vpncmd vpncmd.c)

set_target_properties(vpncmd
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpncmd
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpncmd NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
  target_sources(vpncmd PRIVATE "vpncmd.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

  if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
    target_sources(vpncmd PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x64_user.manifest")
  else()
    target_sources(vpncmd PRIVATE "${TOP_DIRECTORY}/src/BuildFiles/Manifests/x86_user.manifest")
  endif()
endif()

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

  install_wrapper_script("vpncmd")
endif()
