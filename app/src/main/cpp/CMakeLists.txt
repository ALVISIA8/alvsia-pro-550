cmake_minimum_required(VERSION 3.22.1)
project(AlvsiaSec CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Hardened compile flags
add_compile_options(
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fstack-protector-all
    -D_FORTIFY_SOURCE=2
    -Wformat -Wformat-security
    # Strip debug symbols at link
)

add_link_options(
    -Wl,--strip-all
    -Wl,--gc-sections
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

find_library(log-lib log)
find_library(dl-lib dl)

# The release pipeline supplies a fresh random seed per build. The seed is only
# an obfuscation input and must never be treated as a server-side secret.
if(NOT DEFINED ALVSIA_SEAL_SEED_HEX OR ALVSIA_SEAL_SEED_HEX STREQUAL "")
    if(CMAKE_BUILD_TYPE MATCHES "[Rr]elease")
        message(FATAL_ERROR "ALVSIA_SEAL_SEED_HEX is required for release builds")
    endif()
    set(ALVSIA_SEAL_SEED_HEX "0000000000000000000000000000000000000000000000000000000000000000")
endif()
string(LENGTH "${ALVSIA_SEAL_SEED_HEX}" ALVSIA_SEAL_SEED_LENGTH)
if(NOT ALVSIA_SEAL_SEED_LENGTH EQUAL 64 OR NOT ALVSIA_SEAL_SEED_HEX MATCHES "^[0-9a-fA-F]+$")
    message(FATAL_ERROR "ALVSIA_SEAL_SEED_HEX must be 64 hexadecimal characters")
endif()

add_library(
    rasp_guard
    SHARED
    rasp_guard.cpp
)
target_compile_definitions(rasp_guard PRIVATE ALVSIA_SEAL_SEED_HEX=\"${ALVSIA_SEAL_SEED_HEX}\")

target_link_libraries(
    rasp_guard
    ${log-lib}
    ${dl-lib}
)
