# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(proxy-wifi-cmdline "")

target_sources(proxy-wifi-cmdline
    PRIVATE
        ProxyWifiCmd.cpp
)

target_link_libraries(proxy-wifi-cmdline
    PRIVATE
        rpcrt4.lib
        proxy-wifi
        proxy-wifi-util
        WIL
)
