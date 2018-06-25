project(insecure)
cmake_minimum_required(VERSION 3.6)

find_package(PkgConfig)
pkg_check_modules(FUSE REQUIRED IMPORTED_TARGET fuse)

add_executable(longnamefs
    src/longnamefs.c
    src/sha256.c
)

target_link_libraries(longnamefs
    PkgConfig::FUSE
)

target_compile_options(longnamefs PRIVATE
    -std=gnu99
    -Wall -Wextra -Wno-unused-parameter
)

install(TARGETS longnamefs DESTINATION bin)
