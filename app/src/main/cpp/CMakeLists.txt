set(MBEDTLS_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/mbedtls EXCLUDE_FROM_ALL)

cmake_minimum_required(VERSION 3.22.1)


# Android NDK: CMake 3.22 pthread probe is incompatible with pthread_cancel().
set(CMAKE_HAVE_LIBC_PTHREAD 1 CACHE INTERNAL "Android pthread support" FORCE)
set(CMAKE_USE_PTHREADS_INIT 1 CACHE INTERNAL "Android pthread support" FORCE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE CACHE BOOL "Prefer pthread flag" FORCE)
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

add_library(
    rasp_guard
    SHARED
    rasp_guard.cpp
)

target_link_libraries(
    rasp_guard
    ${log-lib}
    ${dl-lib}
    mbedcrypto
)
