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

add_library(
    rasp_guard
    SHARED
    rasp_guard.cpp
)

target_link_libraries(
    rasp_guard
    ${log-lib}
    ${dl-lib}
)
