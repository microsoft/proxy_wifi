// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "OperationHandler.hpp"

#include <gsl/span>

#include "GuidUtils.hpp"
#include "ProxyWifi/Logs.hpp"
#include "WlanSvcHelpers.hpp"

namespace ProxyWifi {

namespace {

    const wchar_t* ToString(OperationStatus s)
    {
        switch (s)
        {
        case OperationStatus::Succeeded:
            return L"Succeeded";
        case OperationStatus::Failed:
            return L"Failed";
        default:
            return L"Unknown status";
        }
    }

    const wchar_t* ToString(OperationType t)
    {
        switch (t)
        {
        case OperationType::GuestDirected:
            return L"GuestDirected";
        case OperationType::HostMirroring:
            return L"HostMirroring";
        default:
            return L"Unknown type";
        }
    }

} // namespace

void OperationHandler::RegisterGuestNotificationCallback(GuestNotificationCallback notificationCallback)
{
    auto gate = std::unique_lock{m_notificationLock};
    m_notificationCallback = notificationCallback;
}

void OperationHandler::ClearGuestNotificationCallback()
{
    auto gate = std::unique_lock{m_notificationLock};
    m_notificationCallback = {};
}

void OperationHandler::SendGuestNotification(std::variant<DisconnectNotif, SignalQualityNotif> notif)
{
    auto gate = std::shared_lock{m_notificationLock};
    if (m_notificationCallback)
    {
        m_notificationCallback(std::move(notif));
    }
}

void OperationHandler::OnGuestConnectionRequest(OperationType type, const Ssid& ssid) noexcept
{
    m_clientNotificationQueue.RunAndWait([&] {
        Log::Info(
            L"Notifying the client of a guest connection request. Type: %ws, Ssid: %ws",
            ToString(type),
            SsidToLogString(ssid.value()).c_str());

        if (m_clientObserver)
        {
            m_clientObserver->OnGuestConnectionRequest(type, ssid);
        }
    });
}

void OperationHandler::OnGuestConnectionCompletion(OperationType type, OperationStatus status, const GUID& interfaceGuid, const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) noexcept
{
    m_clientNotificationQueue.RunAndWait([&] {
        Log::Info(
            L"Notifying the client of a guest connection completion. Type: %ws, Status: %ws, Interface: %ws, Ssid: %ws, AuthAlgo: %ws",
            ToString(type),
            ToString(status),
            GuidToString(interfaceGuid).c_str(),
            SsidToLogString(ssid.value()).c_str(),
            Wlansvc::AuthAlgoToString(authAlgo).c_str());

        if (m_clientObserver)
        {
            m_clientObserver->OnGuestConnectionCompletion(type, status, interfaceGuid, ssid, authAlgo);
        }
    });
}

void OperationHandler::OnGuestDisconnectionRequest(OperationType type, const Ssid& ssid) noexcept
{
    m_clientNotificationQueue.RunAndWait([&] {
        Log::Info(
            L"Notifying the client of a guest disconnection request. Type: %ws, Ssid: %ws",
            ToString(type),
            SsidToLogString(ssid.value()).c_str());

        if (m_clientObserver)
        {
            m_clientObserver->OnGuestDisconnectionRequest(type, ssid);
        }
    });
}

void OperationHandler::OnGuestDisconnectionCompletion(OperationType type, OperationStatus status, const GUID& interfaceGuid, const Ssid& ssid) noexcept
{
    m_clientNotificationQueue.RunAndWait([&] {
        Log::Info(
            L"Notifying the client of a guest disconnection completion. Type: %ws, Status: %ws, Interface: %ws, Ssid: %ws",
            ToString(type),
            ToString(status),
            GuidToString(interfaceGuid).c_str(),
            SsidToLogString(ssid.value()).c_str());

        if (m_clientObserver)
        {
            m_clientObserver->OnGuestDisconnectionCompletion(type, status, interfaceGuid, ssid);
        }
    });
}

void OperationHandler::OnGuestScanRequest() noexcept
{
    m_clientNotificationQueue.RunAndWait([&] {
        Log::Info(L"Notifying the client of a guest scan request");

        if (m_clientObserver)
        {
            m_clientObserver->OnGuestScanRequest();
        }
    });
}

void OperationHandler::OnGuestScanCompletion(OperationStatus status) noexcept
{
    m_clientNotificationQueue.RunAndWait([&] {
        Log::Info(L"Notifying the client of a guest scan completion. Status: %ws", ToString(status));

        if (m_clientObserver)
        {
            m_clientObserver->OnGuestScanCompletion(status);
        }
    });
}

void OperationHandler::OnHostConnection(const GUID& interfaceGuid, const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo)
{
    // Always notify the client on a new host connection
    m_clientNotificationQueue.Run([this, interfaceGuid, ssid, authAlgo] {
        Log::Info(
            L"Notifying the client of a host connection. Interface: %ws, Ssid: %ws, Auth Algo: %ws",
            GuidToString(interfaceGuid).c_str(),
            SsidToLogString(ssid.value()).c_str(),
            Wlansvc::AuthAlgoToString(authAlgo).c_str());
        if (m_clientObserver)
        {
            m_clientObserver->OnHostConnection(interfaceGuid, ssid, authAlgo);
        }
    });
}

void OperationHandler::OnHostDisconnection(const GUID& interfaceGuid, const Ssid& ssid)
{
    // Notify the client first
    m_clientNotificationQueue.Run([this, interfaceGuid, ssid] {
        Log::Info(
            L"Notifying the client of a host disconnection. Interface: %ws, Ssid: %ws",
            GuidToString(interfaceGuid).c_str(),
            SsidToLogString(ssid.value()).c_str());

        if (m_clientObserver)
        {
            m_clientObserver->OnHostDisconnection(interfaceGuid, ssid);
        }
    });

    // If this is a spontaneous disconnection from the host on the interface currently used by the guest,
    // send a disconnect notification to the guest and mark it as disconnected

    // TODO guhetier: Remove this completely or keep it behind a flag for having it in the public lib?

    // m_serializedRunner.Run([this, interfaceGuid] {
    // if (m_guestConnection && interfaceGuid == m_guestConnection->interfaceGuid)
    // {
    //     m_guestConnection.reset();

    //     Log::Trace(L"Sending Disconnection notification to the guest");
    //     SendGuestNotification(DisconnectNotif{m_sessionId});
    // }
    // });
}

void OperationHandler::OnHostSignalQualityChange(const GUID& interfaceGuid, unsigned long signalQuality)
{
    // Only forward notification for the currently connected interface to the guest
    m_serializedRunner.Run([this, interfaceGuid, signalQuality] {
        if (m_guestConnection && interfaceGuid == m_guestConnection->interfaceGuid)
        {
            Log::Trace(L"Send Signal quality change notification to the guest, Signal quality: %d", signalQuality);
            SendGuestNotification(SignalQualityNotif{Wlansvc::LinkQualityToRssi(signalQuality)});
        }
    });
}

void OperationHandler::AddInterface(const std::function<std::unique_ptr<IWlanInterface>()>& wlanInterfaceBuilder)
{
    m_serializedRunner.Run([this, wlanInterfaceBuilder] {
        auto wlanInterface = wlanInterfaceBuilder();
        const auto& newGuid = wlanInterface->GetGuid();
        auto foundIt =
            std::find_if(m_wlanInterfaces.begin(), m_wlanInterfaces.end(), [&](const auto& i) { return i->GetGuid() == newGuid; });

        if (foundIt != m_wlanInterfaces.end())
        {
            // The interface is already present, nothing to do
            Log::Debug(L"Interfaces %ws already present", GuidToString(wlanInterface->GetGuid()).c_str());
            return;
        }

        Log::Info(L"Adding the interface %ws.", GuidToString(wlanInterface->GetGuid()).c_str());
        wlanInterface->SetNotificationHandler(this);
        m_wlanInterfaces.emplace_back(std::move(wlanInterface));
    });
}

void OperationHandler::RemoveInterface(const GUID& interfaceGuid)
{
    m_serializedRunner.Run([this, interfaceGuid] {
        Log::Info(L"Removing the interface %ws.", GuidToString(interfaceGuid).c_str());
        std::erase_if(m_wlanInterfaces, [&](const auto& i) { return i->GetGuid() == interfaceGuid; });
    });
}

ConnectResponse OperationHandler::HandleConnectRequestSerialized(const ConnectRequest& connectRequest)
{
    const Ssid ssid({connectRequest->ssid, connectRequest->ssid_len});

    // TODO guhetier: Should we consider disconnecting a potentially connected interface, if connected by the guest?
    // The next connection could be on a different interface, letting the first one connected...

    if (m_wlanInterfaces.empty())
    {
        // No interface to connect with: fails directly
        Log::Trace(L"No interfaces are present");
        return ConnectResponse{WlanStatus::UnspecifiedFailure, connectRequest->bssid, m_sessionId};
    }

    for (auto& wlanIntf : m_wlanInterfaces)
    {
        Log::Info(L"Checking whether interface %ws is already connected to the correct network", GuidToString(wlanIntf->GetGuid()).c_str());
        if (auto networkInfo = wlanIntf->IsConnectedTo(ssid); networkInfo.has_value())
        {
            // The host is already connected to the network (or this is a fake network, always connected)
            // Succeed imediately
            const auto connectedIntfGuid = wlanIntf->GetGuid();
            m_guestConnection = {ConnectionType::Mirrored, connectedIntfGuid, ssid};

            Log::Info(L"Successfully mirrored the connection on interface %ws. Notifying clients.", GuidToString(connectedIntfGuid).c_str());
            OnGuestConnectionRequest(OperationType::HostMirroring, ssid);
            OnGuestConnectionCompletion(OperationType::HostMirroring, OperationStatus::Succeeded, connectedIntfGuid, ssid, networkInfo->auth);

            return ConnectResponse{WlanStatus::Success, networkInfo->bssid, ++m_sessionId};
        }
    }

    // At this point, an host interface will be connected. Notify the client of a guest direct connection
    OnGuestConnectionRequest(OperationType::GuestDirected, ssid);

    try
    {
        // Gather informations needed to connect
        auto secInfo = WlanSecurity{
            static_cast<AuthAlgo>(connectRequest->auth_type),
            connectRequest->wpa_versions,
            {}, // Akm suites initialized below (need conversion)
            {}, // Cipher suites initialized below (need conversion)
            static_cast<CipherSuite>(connectRequest->group_cipher_suite),
            {connectRequest->key, connectRequest->key + connectRequest->key_len}};

        std::transform(
            connectRequest->akm_suites,
            connectRequest->akm_suites + connectRequest->num_akm_suites,
            std::back_inserter(secInfo.akmSuites),
            [](auto akm) { return static_cast<AkmSuite>(akm); });
        std::transform(
            connectRequest->pairwise_cipher_suites,
            connectRequest->pairwise_cipher_suites + connectRequest->num_pairwise_cipher_suites,
            std::back_inserter(secInfo.cipherSuites),
            [](auto cipher) { return static_cast<CipherSuite>(cipher); });

        // TODO guhetier: Move the inside of this loop in a subfunction?
        for (auto& wlanIntf : m_wlanInterfaces)
        {
            auto connectionResult = WlanStatus::UnspecifiedFailure;
            ConnectedNetwork networkInfo{};
            try
            {
                auto connectFuture = wlanIntf->Connect(ssid, toBssid(connectRequest->bssid), secInfo);
                if (connectFuture.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
                {
                    connectionResult = WlanStatus::UnspecifiedFailure;
                    LOG_WIN32_MSG(ERROR_TIMEOUT, "Connect timed out on interface %ws.", GuidToString(wlanIntf->GetGuid()).c_str());
                }
                else
                {
                    auto r = connectFuture.get();
                    std::tie(connectionResult, networkInfo) = r;
                }
            }
            catch (...)
            {
                LOG_CAUGHT_EXCEPTION_MSG("WlanConnect failed for interface %ws", GuidToString(wlanIntf->GetGuid()).c_str());
                connectionResult = WlanStatus::UnspecifiedFailure;
            }

            if (connectionResult == WlanStatus::Success)
            {
                const auto connectedIntfGuid = wlanIntf->GetGuid();
                m_guestConnection = {ConnectionType::GuestDirected, connectedIntfGuid, ssid};

                Log::Info(L"Successfully connected on interface %ws. Notifying clients.", GuidToString(connectedIntfGuid).c_str());
                OnGuestConnectionCompletion(OperationType::GuestDirected, OperationStatus::Succeeded, connectedIntfGuid, ssid, networkInfo.auth);

                return ConnectResponse{connectionResult, networkInfo.bssid, ++m_sessionId};
            }
        }

        Log::Info(L"All interfaces failed to connect. Answering with a failure.");
        OnGuestConnectionCompletion(OperationType::GuestDirected, OperationStatus::Failed, {}, ssid, {});
        return ConnectResponse{WlanStatus::UnspecifiedFailure, Bssid{}, ++m_sessionId};
    }
    catch (...)
    {
        LOG_CAUGHT_EXCEPTION();
        // Need send the connect request completion notification
        OnGuestConnectionCompletion(OperationType::GuestDirected, OperationStatus::Failed, {}, ssid, {});
        return ConnectResponse{WlanStatus::UnspecifiedFailure, Bssid{}, ++m_sessionId};
    }
}

ConnectResponse OperationHandler::HandleConnectRequest(const ConnectRequest& connectRequest)
{
    return m_serializedRunner.RunAndWait([&] { return HandleConnectRequestSerialized(connectRequest); });
}

DisconnectResponse OperationHandler::HandleDisconnectRequestSerialized(const DisconnectRequest& disconnectRequest)
{
    // No-op if the session id is outdated: the guest already entered a new session
    if (m_sessionId > disconnectRequest->session_id)
    {
        Log::Trace(L"Ignoring disconnect request for previous session: %lld > %lld", m_sessionId.load(), disconnectRequest->session_id);
        return DisconnectResponse{};
    }

    // Disconnect request is a no-op if we already think the guest isn't connected
    if (!m_guestConnection)
    {
        Log::Trace(L"Ignoring disconnect request, already disconnected.");
        return DisconnectResponse{};
    }

    if (m_guestConnection->type != ConnectionType::GuestDirected)
    {
        // Don't disconnect the host interface, simply answer to the guest
        Log::Info(L"Keeping the host connected since the connection wasn't guest directed.");
        OnGuestDisconnectionRequest(OperationType::HostMirroring, m_guestConnection->ssid);

        const auto guestConnectInfo = m_guestConnection;
        m_guestConnection.reset();

        OnGuestDisconnectionCompletion(OperationType::HostMirroring, OperationStatus::Succeeded, guestConnectInfo->interfaceGuid, guestConnectInfo->ssid);
        return DisconnectResponse();
    }


    // At this point, an host interface will be disconnected. Notify the client (make sure it is notified of the completion on each path)
    OnGuestDisconnectionRequest(OperationType::GuestDirected, m_guestConnection->ssid);

    auto completeDisconnection = [&] {
        const auto guestConnectInfo = m_guestConnection;
        m_guestConnection.reset();

        OnGuestDisconnectionCompletion(OperationType::GuestDirected, OperationStatus::Succeeded, guestConnectInfo->interfaceGuid, guestConnectInfo->ssid);
        return DisconnectResponse{};
    };

    auto interfaceToDisconnect = std::find_if(m_wlanInterfaces.begin(), m_wlanInterfaces.end(), [&](const auto& i) {
        return m_guestConnection->interfaceGuid == i->GetGuid();
    });

    if (interfaceToDisconnect == m_wlanInterfaces.end())
    {
        // Should never happen: the GUID must be in the list
        LOG_WIN32_MSG(ERROR_INVALID_STATE, "An interface is connected, but we cannot find it...");
        return completeDisconnection();
    }

    // Disconnect the connected interface
    Log::Info(L"Disconnecting interface %ws.", GuidToString((*interfaceToDisconnect)->GetGuid()).c_str());
    try
    {
        auto disconnectFuture = (*interfaceToDisconnect)->Disconnect();
        if (disconnectFuture.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
        {
            LOG_WIN32_MSG(
                ERROR_TIMEOUT,
                "Disconnect timed out on interface %ws. Stop waiting.",
                GuidToString((*interfaceToDisconnect)->GetGuid()).c_str());
        }
    }
    CATCH_LOG_MSG("WlanDisconnect failed on interface %ws", GuidToString((*interfaceToDisconnect)->GetGuid()).c_str());

    return completeDisconnection();
}

DisconnectResponse OperationHandler::HandleDisconnectRequest(const DisconnectRequest& disconnectRequest)
{
    return m_serializedRunner.RunAndWait([&] { return HandleDisconnectRequestSerialized(disconnectRequest); });
}

ScanResponse OperationHandler::HandleScanRequestSerialized(const ScanRequest& scanRequest)
{
    // Notify the client that the guest is scanning
    OnGuestScanRequest();

    auto requestedSsid =
        scanRequest->ssid_len > 0 ? std::make_optional<const Ssid>(gsl::span{scanRequest->ssid, scanRequest->ssid_len}) : std::nullopt;

    // Start all scan requests
    std::vector<std::future<std::vector<ScannedBss>>> futureScanResults;
    for (auto& wlanIntf : m_wlanInterfaces)
    {
        try
        {
            futureScanResults.push_back(wlanIntf->Scan(requestedSsid));
        }
        CATCH_LOG_MSG("WlanScan failed")
    }

    // Collect all scan results and merge them
    ScanResponseBuilder scanResponse;
    const auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    for (auto& scanFuture : futureScanResults)
    {
        try {
            std::vector<ScannedBss> scanResults;
            if (scanFuture.wait_until(timeout) != std::future_status::ready)
            {
                LOG_WIN32_MSG(ERROR_TIMEOUT, "Scan timed out.");
            }
            else
            {
                scanResults = scanFuture.get();
            }

            for (const auto& bss : scanResults)
            {
                scanResponse.AddBss(bss);
            }
        }
        CATCH_LOG_MSG("Failed to retreive an interface scan results")
    }

    OnGuestScanCompletion(OperationStatus::Succeeded);
    return scanResponse.Build();
}

ScanResponse OperationHandler::HandleScanRequest(const ScanRequest& scanRequest)
{
    return m_serializedRunner.RunAndWait([&] { return HandleScanRequestSerialized(scanRequest); });
}

void OperationHandler::DrainClientNotifications()
{
    // Wait for a task doing nothing: this ensure all previous notification have been processed
    m_clientNotificationQueue.RunAndWait([] { return; });
}

} // namespace ProxyWifi