// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <windows.h>
#include <windot11.h>
#include <wlantypes.h>

namespace ProxyWifi {

/// @brief The mode controlling how the proxy operates.
enum class OperationMode
{
    /// @brief Normal (proxied) mode.
    ///
    /// The proxy provides real results using available hardware on the host. If
    /// no suitable hardware is available, most operations are likely to fail.
    Normal,

    /// @brief Simulated mode.
    ///
    /// The proxy simulates results, not using hardware on the host, even if it
    /// is present and available.
    Simulated,
};

/// @brief Represents a host Wi-Fi proxy service.
class ProxyWifiService
{
public:
    virtual ~ProxyWifiService() = default;

    /// @brief Start the proxy.
    ///
    /// This creates the transport and begins accepting connections on it. Until
    /// Start() is called, the proxy is inactive and does not accept connections.
    virtual void Start() = 0;

    /// @brief Stop the proxy.
    ///
    /// Stop the proxy if it is started. This will sever all existing connections
    /// to the proxy and destroy the transport. Following execution of this call,
    /// the proxy will no longer accept new connections. It may be restarted
    /// using Start().
    virtual void Stop() = 0;
};

/// @brief Indicate who is concerned by a connection/disconnection event
enum class EventSource
{
    Host,  ///< The host was (dis)connected
    Guest, ///< The guest was (dis)connected
};

/// @brief Indicate the status of a guest initiated connection
enum class GuestConnectStatus
{
    Starting, ///< A connection request was received and will result in trying to connect host interfaces
    Succeeded, ///< An host interface has been connected to the requested network and the guest will be notified of the success
    Failed ///< No host interface could be connected to the requested network and the guest will be notified of the failure
};

/// @brief List basic information about a Wi-Fi network
struct WifiNetworkInfo
{
    WifiNetworkInfo() = default;
    WifiNetworkInfo(const DOT11_SSID& ssid, const DOT11_MAC_ADDRESS& bssid);

    DOT11_SSID ssid = {};
    DOT11_MAC_ADDRESS bssid = {};
};

/// @brief Package the argugments for the `OnConnection` callback
struct OnConnectionArgs {
    /// The host interface that connected
    GUID interfaceGuid{};
    /// The ssid of the connected network
    DOT11_SSID connectedNetwork{};
    /// The authentication algorithm of the connected network, for host connections
    /// Remarks: This is the auth algo that is reported to the guest in scan results,
    /// it might differ from the actual auth algo used by the host
    DOT11_AUTH_ALGORITHM authAlgo{DOT11_AUTH_ALGO_80211_OPEN};
};

/// @brief Package the argugments for the `OnDisconnection` callback
struct OnDisconnectionArgs {
    /// The host interface that disconnected
    GUID interfaceGuid{};
    /// The ssid of the disconnected network
    DOT11_SSID disconnectedNetwork{};
};

struct ProxyWifiCallbacks
{
    /// @brief Callback executed on a connection event
    /// If the `EventSource` is the `Host`, it means indicated host interface connected
    /// If the `EventSource` is the `Guest`, it means the guest is connecting (the connection request will be
    /// completed only after this callback returns)
    std::function<void(EventSource, const OnConnectionArgs&)> OnConnection;

    /// @brief Callback executed on a disconnection event
    /// If the `EventSource` is the `Host`, it means indicated host interface disconnected
    /// If the `EventSource` is the `Guest`, it means the guest is disconnecting (the disconnection request will be
    /// completed only after this callback returns)
    std::function<void(EventSource, const OnDisconnectionArgs&)> OnDisconnection;

    /// @brief Callback executed on the guest connection request that will cause a host interface to connect
    /// The callback is invoked when before interfaces are connected/disconnected on the host, and after the connection
    /// attempt is completed, whether it succeeds or fails.
    std::function<void(GuestConnectStatus)> OnGuestConnectRequestProgress;

    /// @brief Callback providing a list of networks that will be simulated by the Wi-Fi proxy
    /// They will be shown as open networks, and are considered as permanently connected for the purpose of notifications
    std::function<std::vector<WifiNetworkInfo>()> ProvideFakeNetworks;
};

/// @brief Guid used in notifications concerning the provided fake networks
/// 1b57e649-a1df-482f-85c2-a16063836418
constexpr GUID FakeInterfaceGuid{0x1b57e649, 0xa1df, 0x482f, {0x85, 0xc2, 0xa, 0x6, 0x6, 0x8, 0x6, 0x18}};

/// @brief Default request/response port used for both HyperV and TCP based Wi-Fi
/// proxies if none is explicitly specified.
constexpr unsigned short RequestResponsePortDefault = 12345;

/// @brief Default notification port used for both HyperV and TCP based Wi-Fi
/// proxies if none is explicitly specified.
constexpr unsigned short NotificationPortDefault = 12346;

/// @brief Settings controlling a HyperV based Wi-Fi proxy.
struct ProxyWifiHyperVSettings
{
    /// @brief Construct a setting object to configure a new Wifi Proxy using an Hyper V transport
    /// @param guestVmId The vm id of the HyperV container guest from which to allow connections.
    /// @param requestResponsePort The HyperV socket port number for the request/response communication channel.
    /// @param notificationPort The HyperV socket port number for the notification communication channel.
    ProxyWifiHyperVSettings(const GUID& guestVmId, unsigned short requestResponsePort, unsigned short notificationPort, OperationMode mode);

    /// @brief Construct a setting object to configure a new Wifi Proxy using an Hyper V transport
    /// @param guestVmId The vm id of the HyperV container guest from which to allow connections
    explicit ProxyWifiHyperVSettings(const GUID& guestVmId);

    /// @brief The HyperV socket port number for the request/response communication channel.
    unsigned short RequestResponsePort = RequestResponsePortDefault;

    /// @brief The HyperV socket port number for the notification communication channel.
    unsigned short NotificationPort = NotificationPortDefault;

    /// @brief The vm id of the HyperV container guest from which to allow connections.
    const GUID GuestVmId{};

    /// @brief The initial mode for the proxy
    const OperationMode ProxyMode = OperationMode::Normal;
};

/// @brief Settings controlling a TCP based Wi-Fi proxy.
struct ProxyWifiTcpSettings
{
    /// @brief Construct a setting object to configure a new Wifi Proxy using a Tcp transport
    /// @param listenIp The TCP/IP address for the proxy to listen for connection.
    /// @param requestResponsePort The TCP/IP port number for the request/response communication channel.
    /// @param notificationPort The TCP/IP port number for the notification communication channel.
    /// @param mode The initial mode the proxy should start with
    ProxyWifiTcpSettings(const std::string& listenIp, unsigned short requestResponsePort, unsigned short notificationPort, OperationMode mode);

    /// @brief Construct a setting object to configure a new Wifi Proxy using a Tcp transport
    /// @param listenIp The TCP/IP address for the proxy to listen for connection.
    explicit ProxyWifiTcpSettings(const std::string& listenIp);

    /// @brief The TCP/IP port number for the request/response communication channel.
    unsigned short RequestResponsePort = RequestResponsePortDefault;

    /// @brief The TCP/IP port number for the notification communication channel.
    unsigned short NotificationPort = NotificationPortDefault;

    /// @brief The TCP/IP address for the proxy to listen for connection.
    const std::string ListenIp;

    /// @brief The initial mode for the proxy
    const OperationMode ProxyMode = OperationMode::Normal;
};

std::unique_ptr<ProxyWifiService> BuildProxyWifiService(const ProxyWifiHyperVSettings& settings, ProxyWifiCallbacks callbacks);
std::unique_ptr<ProxyWifiService> BuildProxyWifiService(const ProxyWifiTcpSettings& settings, ProxyWifiCallbacks callbacks);

} // namespace ProxyWifi