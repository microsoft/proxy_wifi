# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_library(proxy-wifi STATIC "")

target_include_directories(proxy-wifi
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
)

target_link_libraries(proxy-wifi
    PUBLIC
        Mswsock.lib
        Ws2_32.lib
    PRIVATE
        GSL
        WIL
        proxy-wifi-util
)

set(PROXY_WIFI_PUBLIC_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/ProxyWifi/ProxyWifiService.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/ProxyWifi/Logs.hpp
)

target_sources(proxy-wifi
    PRIVATE
        ${PROXY_WIFI_PUBLIC_HEADERS}
        Iee80211Utils.hpp
        ClientWlanInterface.hpp
        ClientWlanInterface.cpp
        Connection.hpp
        Connection.cpp
        Networks.hpp
        Networks.cpp
        Logs.cpp
        LogsHelpers.hpp
        Messages.hpp
        Messages.cpp
        OperationHandler.hpp
        OperationHandler.cpp
        WlanSvcOperationHandler.hpp
        OperationHandlerBuilder.hpp
        Protocol.hpp
        RealWlanInterface.hpp
        RealWlanInterface.cpp
        SocketHelpers.hpp
        SocketHelpers.cpp
        TestWlanInterface.hpp
        TestWlanInterface.cpp
        Tracelog.hpp
        Transport.hpp
        Transport.cpp
        ProxyWifiServiceImpl.hpp
        ProxyWifiServiceImpl.cpp
        WlanInterface.hpp
        WlanSvcHelpers.hpp
        WlanSvcHelpers.cpp
        WlanSvcWrapper.hpp
        WlanSvcWrapper.cpp
)

set_target_properties(proxy-wifi PROPERTIES
    PUBLIC_HEADER "${PROXY_WIFI_PUBLIC_HEADERS}"
)

install(TARGETS proxy-wifi
    EXPORT proxy-wifi-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${TARGET_PLATFORM}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ProxyWifi
)

install(FILES
    $<TARGET_FILE_DIR:proxy-wifi>/$<TARGET_FILE_BASE_NAME:proxy-wifi>.pdb
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/${TARGET_PLATFORM}
)

install(EXPORT proxy-wifi-targets
    NAMESPACE proxy-wifi::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/${TARGET_PLATFORM}/cmake/proxy-wifi
)
