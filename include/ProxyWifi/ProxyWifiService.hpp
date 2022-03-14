// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <functional>
#include <memory>
#include <vector>

#include <Windows.h>
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

/// @brief Indicate the status of a guest initiated operation
enum class OperationStatus
{
    Succeeded,
    Failed
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

/// @brief Indicate the impact a guest requested operation will have on the host
enum class OperationType
{
    GuestDirected, ///< The guest is directing this operation, and the host state will change to accomodate it
    HostMirroring ///< The guest was only replicating the state of the host, the host state won't change as a result of this request
};

/// @brief Observer class that get notified on host or guest events
/// Client should inherit from it and override method to handle notifications
class ProxyWifiObserver
{
public:
    virtual ~ProxyWifiObserver() = default;

    struct ConnectRequestArgs {
        DOT11_SSID ssid;
    };

    struct ConnectCompleteArgs {
        GUID interfaceGuid;
        DOT11_SSID ssid;
        DOT11_AUTH_ALGORITHM authAlgo;
    };

    struct DisconnectRequestArgs {
        DOT11_SSID ssid;
    };

    struct DisconnectCompleteArgs {
        GUID interfaceGuid;
        DOT11_SSID ssid;
    };

    /// @brief An host WiFi interface connected to a network
    virtual void OnHostConnection(const ConnectCompleteArgs& /* connectionInfo */) noexcept
    {
    }

    /// @brief An host WiFi interface disconnected from a network
    virtual void OnHostDisconnection(const DisconnectCompleteArgs& /* disconnectionInfo */) noexcept
    {
    }

    /// @brief The guest requested a connection to a network
    /// If `type == OperationType::HostMirroring`, an host inteface is already connected to the network, otherwise, one will be
    /// connected The connection won't proceed until the callback returns
    virtual void OnGuestConnectionRequest(OperationType /* type */, const ConnectRequestArgs& /* connectionInfo */) noexcept
    {
    }

    /// @brief A guest connection request was processed
    /// If `type == OperationType::HostMirroring`, an host inteface was already connected to the network, otherwise, one has been be connected
    /// The response won't be sent to the guest until this callback returns
    virtual void OnGuestConnectionCompletion(
        OperationType /* type */, OperationStatus /* status */, const ConnectCompleteArgs& /* connectionInfo */) noexcept
    {
    }

    /// @brief The guest requested a disconnection from the connected network
    /// If `type == OperationType::HostMirroring`, the host won't be impacted, otherwise, a matching host interface will be disconnected
    /// The disconnection won't proceed until the callback returns
    virtual void OnGuestDisconnectionRequest(OperationType /* type */, const DisconnectRequestArgs& /* connectionInfo */) noexcept
    {
    }

    /// @brief A guest disconnection request was processed
    /// If `type == OperationType::HostMirroring`, this was a no-op for the host, otherwise, a matching host interface has been disconnected
    /// The response won't be sent to the guest until this callback returns
    virtual void OnGuestDisconnectionCompletion(OperationType /* type */, OperationStatus /* status */, const DisconnectCompleteArgs& /* disconnectionInfo */) noexcept
    {
    }

    /// @brief The guest requested a scan
    /// The scan won't start on the host until this callback returns
    virtual void OnGuestScanRequest() noexcept
    {
    }

    /// @brief A guest scan request was processed
    /// The scan results won't be sent to the guest until this callback returns
    virtual void OnGuestScanCompletion(OperationStatus /* status */) noexcept
    {
    }
};

/// @brief Type of the callback providing a list of networks that will be simulated by the Wi-Fi proxy
/// They will be shown as open networks, and are considered as permanently connected for the purpose of notifications
using FakeNetworkProvider = std::function<std::vector<WifiNetworkInfo>()>;

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
    /// @param mode The mode of operation used to emulate or virtualize Wifi
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
    /// @param mode The mode of operation used to emulate or virtualize Wifi
    ProxyWifiTcpSettings(std::string listenIp, unsigned short requestResponsePort, unsigned short notificationPort, OperationMode mode);

    /// @brief Construct a setting object to configure a new Wifi Proxy using a Tcp transport
    /// @param listenIp The TCP/IP address for the proxy to listen for connection.
    explicit ProxyWifiTcpSettings(std::string listenIp);

    /// @brief The TCP/IP port number for the request/response communication channel.
    unsigned short RequestResponsePort = RequestResponsePortDefault;

    /// @brief The TCP/IP port number for the notification communication channel.
    unsigned short NotificationPort = NotificationPortDefault;

    /// @brief The TCP/IP address for the proxy to listen for connection.
    const std::string ListenIp;

    /// @brief The initial mode for the proxy
    const OperationMode ProxyMode = OperationMode::Normal;
};

std::unique_ptr<ProxyWifiService> BuildProxyWifiService(
    const ProxyWifiHyperVSettings& settings, FakeNetworkProvider fakeNetworkCallback = {}, ProxyWifiObserver* pObserver = nullptr);
std::unique_ptr<ProxyWifiService> BuildProxyWifiService(
    const ProxyWifiTcpSettings& settings, FakeNetworkProvider fakeNetworkCallback = {}, ProxyWifiObserver* pObserver = nullptr);

} // namespace ProxyWifi