// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <functional>
#include <memory>
#include <set>
#include <shared_mutex>
#include <variant>
#include <vector>

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
    OperationHandler(ProxyWifiObserver* pObserver, std::vector<std::unique_ptr<IWlanInterface>> wlanInterfaces)
        : m_pClientObserver{pObserver}, m_wlanInterfaces{std::move(wlanInterfaces)}
    {
        for (const auto& wlanIntf: m_wlanInterfaces)
        {
            wlanIntf->SetNotificationHandler(this);
        }
    }

    ~OperationHandler() override
    {
        // First, destroy all interfaces so no notification will be queued on a destroyed workqueue
        m_wlanInterfaces.clear();

        // Then cancel async works before the object destruction to ensure nothing reference `this`
        m_serializedRunner.Cancel();
    }

    OperationHandler(const OperationHandler&) = delete;
    OperationHandler(OperationHandler&&) = delete;
    OperationHandler& operator=(const OperationHandler&) = delete;
    OperationHandler& operator=(OperationHandler&&) = delete;

    /// @brief Add an interface to the operation handler
    /// Takes a builder function instead of the interface directly to create the interface in the work queue
    /// (needed to avoid deadlocks when an interface is created - and subscribe to notifications - from a notification thread)
    void AddInterface(const std::function<std::unique_ptr<IWlanInterface>()>& wlanInterfaceBuilder);
    void RemoveInterface(const GUID& interfaceGuid);

    ConnectResponse HandleConnectRequest(const ConnectRequest& connectRequest);
    DisconnectResponse HandleDisconnectRequest(const DisconnectRequest& disconnectRequest);
    ScanResponse HandleScanRequest(const ScanRequest& scanRequest);

    using GuestNotificationTypes = std::variant<DisconnectNotif, SignalQualityNotif, ScanResponse>;
    void RegisterGuestNotificationCallback(std::function<void(GuestNotificationTypes)> notificationCallback);
    void ClearGuestNotificationCallback();

    /// @brief Wait all client notifications have been processed and return
    /// Unit test helper
    void DrainWorkqueues();

protected:

    /// @brief Must be called by the interfaces when they connect to a network
    void OnHostConnection(const GUID& interfaceGuid, const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) override;
    /// @brief Must be called by the interfaces when they disconnect to a network
    void OnHostDisconnection(const GUID& interfaceGuid, const Ssid& ssid) override;
    /// @brief Must be called by the interfaces when the signal quality changes
    void OnHostSignalQualityChange(const GUID& interfaceGuid, unsigned long signalQuality) override;
    /// @brief Must be called by the interfaces when scan results are availables
    void OnHostScanResults(const GUID& interfaceGuid, const std::vector<ScannedBss>& scannedBss, ScanStatus status) override;

private:

    // These functions do the actual handling of the request from a seriliazed work queue
    ConnectResponse HandleConnectRequestSerialized(const ConnectRequest& connectRequest);
    DisconnectResponse HandleDisconnectRequestSerialized(const DisconnectRequest& disconnectRequest);
    ScanResponse HandleScanRequestSerialized(const ScanRequest& scanRequest);

    /// @brief Send a notification to the guest
    void SendGuestNotification(GuestNotificationTypes notif);

    /// @brief Notify the guest of guest operation request and completion
    ProxyWifiObserver::Authorization AuthorizeGuestConnectionRequest(OperationType type, const Ssid& ssid) noexcept;
    void OnGuestConnectionCompletion(OperationType type, OperationStatus status, const GUID& interfaceGuid, const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) noexcept;
    void OnGuestDisconnectionRequest(OperationType type, const Ssid& ssid) noexcept;
    void OnGuestDisconnectionCompletion(OperationType type, OperationStatus status, const GUID& interfaceGuid, const Ssid& ssid) noexcept;
    void OnGuestScanRequest() noexcept;
    void OnGuestScanCompletion(OperationStatus status) noexcept;

    std::shared_mutex m_notificationLock;
    std::function<void(GuestNotificationTypes)> m_notificationCallback;

    /// @brief Client provided object to notify client of various events
    ProxyWifiObserver* m_pClientObserver = nullptr;

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

    /// @brief Set of interfaces currently executing a scan
    std::set<GUID> m_scanningInterfaces;

    std::vector<std::unique_ptr<IWlanInterface>> m_wlanInterfaces;

    /// @brief Serialized workqueue processing guest requests and guest notifications
    SerializedWorkRunner m_serializedRunner;
    /// @brief Serialized workqueue sending client notifications
    SerializedWorkRunner m_clientNotificationQueue;
};

} // namespace ProxyWifi