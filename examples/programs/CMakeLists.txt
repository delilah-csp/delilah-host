cmake_minimum_required(VERSION 3.16)

project(delilah-tud-programs)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS "-target bpf -c -Wno-implicit-function-declaration -fno-builtin -O3")

file(GLOB PROGRAMS "*.c")
add_library(programs STATIC ${PROGRAMS})

add_custom_command(TARGET programs POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:programs> ${CMAKE_CURRENT_BINARY_DIR}/
    COMMAND_EXPAND_LISTS
)
