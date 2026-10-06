cmake_minimum_required(VERSION 3.22.1)

# Android NDK cross-compile:
# prevent CMake compiler detection from linking a test executable.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

project(AlvsiaSec LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Android NDK + CMake 3.22:
# Mbed TLS does not need the optional host Threads package for this build.
set(CMAKE_DISABLE_FIND_PACKAGE_Threads TRUE)

# Build only the Mbed TLS crypto library required by rasp_guard.
set(MBEDTLS_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/mbedtls EXCLUDE_FROM_ALL)

# Hardened compile flags.
add_compile_options(
    -O2
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fstack-protector-all
    -D_FORTIFY_SOURCE=2
    -Wformat
    -Wformat-security
)

# Hardened linker flags.
add_link_options(
    -Wl,--strip-all
    -Wl,--gc-sections
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

find_library(log-lib log)
find_library(dl-lib dl)

add_library(
    rasp_guard
    SHARED
    rasp_guard.cpp
)

target_link_libraries(
    rasp_guard
    PRIVATE
    ${log-lib}
    ${dl-lib}
    mbedcrypto
)
