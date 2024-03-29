cmake_minimum_required(VERSION 3.21)

project(proxy-wifi LANGUAGES CXX)

# Provide path for scripts
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# Options
option(MICROSOFT_TELEMETRY "Enable Microsoft telemetry collection" OFF)

include(FetchContent)

# Configure WIL dependency
set(WIL_BUILD_TESTS OFF CACHE INTERNAL "Turn off wil tests")
set(WIL_BUILD_PACKAGING OFF CACHE INTERNAL "Turn off wil packaging")
FetchContent_Declare(WIL
    GIT_REPOSITORY "https://github.com/microsoft/wil"
    GIT_TAG "f9284c19c9873664978b873b8858d7dfacc6af1e"
    GIT_SHALLOW OFF
)
FetchContent_MakeAvailable(WIL)

# Build parameters

# Default to debug build if unspecified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# Rationalize TARGET_PLATFORM
if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "arm64" OR "${TARGET_PLATFORM}" STREQUAL "arm64")
    set(TARGET_PLATFORM "arm64")
elseif("${CMAKE_GENERATOR_PLATFORM}" MATCHES "x64|amd64|" OR "${TARGET_PLATFORM}" MATCHES "x64|amd64|")
    set(TARGET_PLATFORM "x64")
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_GENERATOR_PLATFORM}")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -DDBG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")

add_compile_options(/sdl /W4 /WX)

add_compile_definitions(
    UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MICROSOFT_TELEMETRY)
    add_compile_definitions(MICROSOFT_TELEMETRY)
endif()

add_subdirectory(lib)
add_subdirectory(util)

if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(cmdline)

    include(CTest)

    if(BUILD_TESTING)
        add_subdirectory(test)
    endif()
endif()