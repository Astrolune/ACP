cmake_minimum_required(VERSION 3.15)
project(acp_c_examples C)

set(CMAKE_C_STANDARD 11)

# Find ACP library
find_library(ACP_LIBRARY NAMES acp acp_ffi PATHS ${CMAKE_SOURCE_DIR}/../../target/release)
find_path(ACP_INCLUDE_DIR acp.h PATHS ${CMAKE_SOURCE_DIR}/../../crates/acp-ffi/include)

if(NOT ACP_LIBRARY)
    message(FATAL_ERROR "ACP library not found. Build acp-ffi first with: cargo build --release -p acp-ffi")
endif()

include_directories(${ACP_INCLUDE_DIR})

# Basic encryption example
add_executable(basic_encryption basic_encryption.c)
target_link_libraries(basic_encryption ${ACP_LIBRARY})

if(WIN32)
    target_link_libraries(basic_encryption ws2_32 userenv bcrypt ntdll)
elseif(APPLE)
    target_link_libraries(basic_encryption "-framework Security")
endif()
