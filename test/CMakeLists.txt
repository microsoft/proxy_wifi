# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.1
  )

FetchContent_MakeAvailable(Catch2)

add_executable(proxy-wifi-test)
target_link_libraries(proxy-wifi-test
    PRIVATE
        Catch2::Catch2
        proxy-wifi-util
        proxy-wifi
        Synchronization.lib
    )

target_include_directories(proxy-wifi-test
    PRIVATE
        ../lib
)

target_sources(proxy-wifi-test
    PRIVATE
        main.cpp
        TestUtils.cpp
        TestOpHandler.cpp
        WlansvcMock.hpp
        $<$<BOOL:${BYPASS_WLANAPI_DEPENDENCY}>:WlanApiStubs.cpp>
)

# Allows CTest to discover Catch2 tests automatically
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")
include(Catch)
catch_discover_tests(proxy-wifi-test)