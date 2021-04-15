add_executable(hamcorebuilder
  main.c
  FileSystem.c
  FileSystem.h
)

if(WIN32)
  target_compile_definitions(hamcorebuilder PRIVATE "OS_WINDOWS")
endif()

target_include_directories(hamcorebuilder PRIVATE "${TOP_DIRECTORY}/3rdparty/tinydir")

target_link_libraries(hamcorebuilder PRIVATE libhamcore)
