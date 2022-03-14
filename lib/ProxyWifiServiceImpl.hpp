// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <memory>
#include <thread>

#include "OperationHandler.hpp"
#include "Transport.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"

namespace ProxyWifi {

/// @brief Represents a host Wi-Fi proxy.
class ProxyWifiCommon: public ProxyWifiService
{
public:
    ProxyWifiCommon(OperationMode mode, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver);
    ~ProxyWifiCommon() override;

    ProxyWifiCommon(const ProxyWifiCommon&) = delete;
    ProxyWifiCommon& operator=(const ProxyWifiCommon&) = delete;
    ProxyWifiCommon(ProxyWifiCommon&&) = delete;
    ProxyWifiCommon& operator=(ProxyWifiCommon&&) = delete;

    /// @brief Start the proxy.
    ///
    /// This creates the transport and begins accepting connections on it. Until
    /// Start() is called, the proxy is inactive and does not accept connections.
    void Start() override;

    /// @brief Stop the proxy.
    ///
    /// Stop the proxy if it is started. This will sever all existing connections
    /// to the proxy and destroy the transport. Following execution of this call,
    /// the proxy will no longer accept new connections. It may be restarted
    /// using Start().
    void Stop() override;

protected:
    /// @brief Create a transport for the proxy.
    virtual std::unique_ptr<Transport> CreateTransport() = 0;

protected:
    std::thread m_proxy;
    OperationMode m_mode = OperationMode::Normal;
    std::shared_ptr<OperationHandler> m_operationHandler;
    std::unique_ptr<Transport> m_transport;
};

/// @brief Represents a Wi-Fi proxy for HyperV container endpoints.
///
/// This proxy allows connections from HyperV containers. Each proxy instance is
/// bound to exactly one HyperV container and will not allow connections from any
/// other container.
///
/// The proxy transport uses two (2) HyperV (AF_HYPERV) sockets to facilitate the
/// proxy protocol:
///	    1) Request/Response communication channel.
///	    2) Notification communication channel.
///
/// The request/response communication channel is driven by the client endpoint
/// which originates requests to which the host responds.
///
/// The notification communication channel is driven by the host which originates
/// notification messages destined for the client endpoint. This is a one-way
/// communication channel; the host does not listen on it for client responses.
///
/// Unless the client VM has been expressly configured to allow communication on
/// the ports defined by these sockets, a registry entry must be added denoting
/// registration of the proxy application with the HyperV socket. A registry key
/// must be added under:
///
/// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices
///
/// with key name equal to a GUID describing the service. This class does not
/// handle such registration; it is the responsibility of the caller.
class ProxyWifiHyperV : public ProxyWifiCommon
{
public:
    /// @brief Construct a new Proxy Wifi HyperV object.
    /// @param settings The settings controlling operations of the proxy.
    /// @param fakeNetworkCallback Function that the proxy will call when it needs a list of fake network to emulate
    /// @param pObserver The handler for guest and host notifications
    explicit ProxyWifiHyperV(const ProxyWifiHyperVSettings& settings, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver);

    /// @brief Get HyperV specific proxy settings.
    const ProxyWifiHyperVSettings& Settings() const;

    /// @brief Create a Transport object
    std::unique_ptr<Transport> CreateTransport() override;

private:
    const ProxyWifiHyperVSettings m_settings;
};

/// @brief Represents a Wi-Fi proxy for TCP endpoints.
///
/// This proxy allows connections from TCP/IP endpoints. Each proxy instance is
/// bound to exactly one listening IP address and will not allow connections from
/// any other endpoint.
class ProxyWifiTcp : public ProxyWifiCommon
{
public:
    /// @brief Construct a new Proxy Wifi Tcp object.
    ///
    /// @param settings The settings controlling operations of the proxy.
    /// @param fakeNetworkCallback Function that the proxy will call when it needs a list of fake network to emulate
    /// @param pObserver The handler for guest and host notifications
    explicit ProxyWifiTcp(const ProxyWifiTcpSettings& settings, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver);

    /// @brief TCP specific proxy settings.
    const ProxyWifiTcpSettings& Settings() const;

    /// @brief Create a Transport object
    std::unique_ptr<Transport> CreateTransport() override;

private:
    const ProxyWifiTcpSettings m_settings;
};

} // namespace ProxyWifi