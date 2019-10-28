add_executable(hamcorebuilder hamcorebuilder.c)

set_target_properties(hamcorebuilder
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/tmp"
  LIBRARY_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/tmp"
  RUNTIME_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/tmp"
)

if(WIN32)
  set_target_properties(hamcorebuilder
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/tmp"
  )
endif()

target_link_libraries(hamcorebuilder cedar mayaqua)
