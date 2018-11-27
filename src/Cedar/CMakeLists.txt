file(GLOB SOURCES_CEDAR "*.c")
file(GLOB HEADERS_CEDAR "*.h")

if(WIN32)
  enable_language(CXX)
  file(GLOB SOURCES_CEDAR_CPP "*.cpp")
endif()

if(WIN32)
  add_library(cedar STATIC ${SOURCES_CEDAR} ${SOURCES_CEDAR_CPP} ${HEADERS_CEDAR})
else()
  add_library(cedar SHARED ${SOURCES_CEDAR} ${SOURCES_CEDAR_CPP} ${HEADERS_CEDAR})
endif()

set_target_properties(cedar
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(cedar
    PROPERTIES
    COMPILE_PDB_NAME "cedar"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  target_include_directories(cedar PRIVATE winpcap)
endif()

if(UNIX)
  find_library(LIB_READLINE readline)
  find_package(Curses REQUIRED)

  target_link_libraries(cedar PRIVATE ${LIB_READLINE} ${CURSES_LIBRARIES})

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    target_link_libraries(cedar PRIVATE mayaqua pcap)
  endif()
endif()

# Version
add_definitions(-DCEDAR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR} -DCEDAR_VERSION_MINOR=${PROJECT_VERSION_MINOR} -DCEDAR_VERSION_BUILD=${PROJECT_VERSION_PATCH})

# Builder
if(UNIX)
  add_definitions(-DBUILDER_NAME="$ENV{USER}")
elseif(WIN32)
  add_definitions(-DBUILDER_NAME="$ENV{USERNAME}")
endif()

cmake_host_system_information(RESULT BUILDER_HOSTNAME QUERY HOSTNAME)

add_definitions(-DBUILD_PLACE="${BUILDER_HOSTNAME}")

# Remove leading 0 from date and time
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_DAY "${DATE_DAY}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_MONTH "${DATE_MONTH}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_YEAR "${DATE_YEAR}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_HOUR "${TIME_HOUR}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_MINUTE "${TIME_MINUTE}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_SECOND "${TIME_SECOND}")

add_definitions(-DBUILD_DATE_D=${BUILD_DAY} -DBUILD_DATE_M=${BUILD_MONTH} -DBUILD_DATE_Y=${BUILD_YEAR})
add_definitions(-DBUILD_DATE_HO=${BUILD_HOUR} -DBUILD_DATE_MI=${BUILD_MINUTE} -DBUILD_DATE_SE=${BUILD_SECOND})

if(UNIX)
  install(TARGETS cedar
    COMPONENT "common"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
  )
endif()
