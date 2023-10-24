cmake_minimum_required(VERSION 3.16)

project(aes)

add_compile_options(-Wall -Werror -march=native)

# AES library
add_library(aes STATIC
    src/aes.c
    tables/tables.c
    src/aes_hw.c
)
target_include_directories(aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Tests for the AES library
add_executable(aes-test
    src/test.cpp
)
target_compile_features(aes-test PRIVATE cxx_std_20)
target_link_libraries(aes-test PRIVATE aes)

# Very basic AES benchmark
add_executable(aes-benchmark
    src/benchmark.cpp
)
target_compile_features(aes-benchmark PRIVATE cxx_std_20)
target_link_libraries(aes-benchmark PRIVATE aes)
