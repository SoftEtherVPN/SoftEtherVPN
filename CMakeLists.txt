cmake_minimum_required(VERSION 3.4.3)

project(SoftEtherVPN LANGUAGES C)

set(default_build_type "Release")

# Check that submodules are present only if source was downloaded with git
if(EXISTS "${SoftEtherVPN_SOURCE_DIR}/.git" AND NOT EXISTS "${SoftEtherVPN_SOURCE_DIR}/src/Mayaqua/cpu_features/CMakeLists.txt")
    message (FATAL_ERROR "Submodules are not initialized. Run\n\tgit submodule update --init --recursive")
endif()

add_subdirectory(src)
