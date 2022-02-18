// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <any>
#include <chrono>
#include <functional>
#include <iterator>
#include <memory>
#include <shared_mutex>
#include <variant>
#include <vector>

#include "Networks.hpp"
#include "Messages.hpp"
#include "WlanInterface.hpp"
#include "WorkQueue.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"

namespace ProxyWifi {

// Interface for operation handlers
// Classes implementing this interface can handle and build a response to request from the guest
class OperationHandler: private INotificationHandler
{
public:
    OperationHandler(ProxyWifiCallbacks callbacks, std::vector<std::unique_ptr<IWlanInterface>> wlanInterfaces)
        : m_clientCallbacks{std::move(callbacks)}, m_wlanInterfaces{std::move(wlanInterfaces)}
    {
        for (auto& wlanIntf: m_wlanInterfaces)
        {
            wlanIntf->SetNotificationHandler(this);
        }
    }

    virtual ~OperationHandler()
    {
        // First, destroy all interfaces so no notification will be queued on a destroyed workqueue
        m_wlanInterfaces.clear();

        // Then cancel async works before the object destruction to ensure nothing reference `this`
        m_serializedRunner.Cancel();
    }

    /// @brief Add an interface to the operation handler
    /// Takes a builder function instead of the interface directly to create the interface in the work queue
    /// (needed to avoid deadlocks when an interface is created - and subscribe to notifications - from a notification thread)
    void AddInterface(const std::function<std::unique_ptr<IWlanInterface>()>& wlanInterfaceBuilder);
    void RemoveInterface(const GUID& interfaceGuid);

    ConnectResponse HandleConnectRequest(const ConnectRequest& connectRequest);
    DisconnectResponse HandleDisconnectRequest(const DisconnectRequest& disconnectRequest);
    ScanResponse HandleScanRequest(const ScanRequest& scanRequest);

    using GuestNotificationCallback = std::function<void(std::variant<DisconnectNotif, SignalQualityNotif>)>;
    void RegisterGuestNotificationCallback(GuestNotificationCallback notificationCallback);
    void ClearGuestNotificationCallback();

protected:

    /// @brief Must be called by the interfaces when they connect to a network
    void OnHostConnection(const GUID& interfaceGuid, const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) override;
    /// @brief Must be called by the interfaces when they disconnect to a network
    void OnHostDisconnection(const GUID& interfaceGuid, const Ssid& ssid) override;
    /// @brief Must be called by the interfaces when the signal quality changes
    void OnHostSignalQualityChange(const GUID& interfaceGuid, unsigned long signalQuality) override;

    std::vector<WifiNetworkInfo> GetUserBss();

private:

    // These functions do the actual handling of the request from a seriliazed work queue
    ConnectResponse HandleConnectRequestSerialized(const ConnectRequest& connectRequest);
    DisconnectResponse HandleDisconnectRequestSerialized(const DisconnectRequest& disconnectRequest);
    ScanResponse HandleScanRequestSerialized(const ScanRequest& scanRequest);

    /// @brief Send a notification to the guest
    void SendGuestNotification(std::variant<DisconnectNotif, SignalQualityNotif> notif);

    void NotifyConnectionToClientSerialized(EventSource source, const GUID& interfaceGuid, const DOT11_SSID& network, DOT11_AUTH_ALGORITHM authAlgo);
    void NotifyDisconnectionToClientSerialized(EventSource source, const GUID& interfaceGuid, const DOT11_SSID& network);

    /// @brief Notify the lib user that the host/guest connected
    void NotifyConnectionToClient(EventSource source, const GUID& interfaceGuid, const DOT11_SSID& network, DOT11_AUTH_ALGORITHM authAlgo);

    /// @brief Notifiy the lib user that the host/guest disconnected
    void NotifyDisconnectionToClient(EventSource source, const GUID& interfaceGuid, const DOT11_SSID& network);

    /// @brief Notifiy the lib user that of the current status of a guest driven connection
    /// This must be called when the connect request will cause a host interface to actually connect.
    /// It must indicate the start of the process and the final result (success or failure)
    void NotifyGuestConnectRequestProgress(GuestConnectStatus status);

    std::shared_mutex m_notificationLock;
    GuestNotificationCallback m_notificationCallback;

    // TODO guhetier: Try to get only the two necessary callback there? The last one is only needed for the fake interface
    ProxyWifiCallbacks m_clientCallbacks;

    enum class ConnectionType
    {
        Mirrored,
        GuestDirected
    };

    struct ConnectionInfo
    {
        /// @brief Identify how the guest connection was initiated
        ConnectionType type;
        /// @brief Identify the host interface corresponding to the guest connection
        GUID interfaceGuid;
        /// @brief Identify the ssid the guest is connected
        Ssid ssid;
    };

    std::optional<ConnectionInfo> m_guestConnection;

    /// @brief Number identifying the current connection session in the host
    /// It allows to keep the host and guest in sync in some race scenarios, e.g:
    /// 1) HostInitiated send disconnect notif
    /// 2) Guest send connect request before receiving disconnect notif
    /// 3) HostInitiated process connect request, connect, answer
    /// 4) Guest process disconnect notif (blocked in queue while connect request pending)
    /// 5) Session ID is expired, prevent the disconnection in the guest
    std::atomic<uint64_t> m_sessionId{};

    std::vector<std::unique_ptr<IWlanInterface>> m_wlanInterfaces;

    SerializedWorkRunner m_serializedRunner;
    SerializedWorkRunner m_clientNotificationQueue;
};

} // namespace ProxyWifi