include(TestBigEndian)

add_executable(hamcorebuilder
  main.c
  FileSystem.c
  FileSystem.h
)

if(WIN32)
  target_compile_definitions(hamcorebuilder PRIVATE "OS_WINDOWS")
endif()

test_big_endian(BIG_ENDIAN)
if(BIG_ENDIAN)
  target_compile_definitions(hamcorebuilder PRIVATE "BYTE_ORDER_BIG_ENDIAN")
endif()

target_include_directories(hamcorebuilder PRIVATE "${TOP_DIRECTORY}/3rdparty/tinydir")

find_package(ZLIB REQUIRED)
target_link_libraries(hamcorebuilder PRIVATE ZLIB::ZLIB)
