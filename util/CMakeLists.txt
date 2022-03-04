# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_library(proxy-wifi-util INTERFACE "")

target_sources(proxy-wifi-util
    PRIVATE
        GuidUtils.hpp
        StringUtils.hpp
        WorkQueue.hpp
        DynamicFunction.hpp
)

target_include_directories(proxy-wifi-util
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(proxy-wifi-util
    INTERFACE
        rpcrt4.lib
        GSL
        WIL
)

install(TARGETS proxy-wifi-util
    EXPORT proxy-wifi-targets
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/proxy-wifi
)
