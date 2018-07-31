file(GLOB SOURCES_CEDAR "*.c")
file(GLOB HEADERS_CEDAR "*.h")

add_library(cedar STATIC ${SOURCES_CEDAR} ${HEADERS_CEDAR})

set_target_properties(cedar
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Cedar"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Cedar"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Cedar"
)

find_library(LIB_READLINE readline)
find_package(Curses REQUIRED)

target_link_libraries(cedar ${LIB_READLINE} ${CURSES_LIBRARIES})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
  target_link_libraries(cedar pcap)
endif()
