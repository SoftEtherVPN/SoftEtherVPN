if(NOT WIN32)
  message(FATAL_ERROR "PenCore is needed only on Windows.")
endif()

add_library(PenCore SHARED pencore.c pencore.rc)

set_target_properties(PenCore
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  LIBRARY_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  RUNTIME_OUTPUT_DIRECTORY "${TOP_DIRECTORY}/src/bin/hamcore"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(PenCore)
