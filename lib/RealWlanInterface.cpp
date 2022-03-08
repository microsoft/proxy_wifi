// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "RealWlanInterface.hpp"

#include "StringUtils.hpp"
#include "ProxyWifi/Logs.hpp"
#include "WlanSvcHelpers.hpp"

#include <wil/result_macros.h>
#include <wil/safecast.h>

namespace ProxyWifi {

namespace {

bool IsBssSupported(const ScannedBss& bss, const std::vector<WLAN_AVAILABLE_NETWORK>& networks)
{
    const auto matchingNetwork =
        std::ranges::find_if(networks, [&](const auto& n) { return bss.ssid == n.dot11Ssid; });

    if (matchingNetwork == networks.cend())
    {
        Log::Debug(
            L"BSS without matching network, Bssid: %ws, Ssid: %ws, ChannelCenterFreq: %d, Rssi: %d, Ie dump:\n%ws",
            BssidToString(bss.bssid).c_str(),
            SsidToLogString(bss.ssid.value()).c_str(),
            bss.channelCenterFreq,
            bss.rssi,
            ByteBufferToHexString(bss.ies).c_str());

        return true;
    }

    if (Wlansvc::IsAuthCipherPairSupported({matchingNetwork->dot11DefaultAuthAlgorithm, matchingNetwork->dot11DefaultCipherAlgorithm}))
    {
        Log::Debug(
            L"Supported BSS, Bssid: %ws, Ssid: %ws, AuthAlgo: %ws, CihperAlgo: %ws, ChannelCenterFreq: %d, Rssi: %d, "
            L"Ie dump:\n%ws",
            BssidToString(bss.bssid).c_str(),
            SsidToLogString(bss.ssid.value()).c_str(),
            Wlansvc::AuthAlgoToString(matchingNetwork->dot11DefaultAuthAlgorithm).c_str(),
            Wlansvc::CipherAlgoToString(matchingNetwork->dot11DefaultCipherAlgorithm).c_str(),
            bss.channelCenterFreq,
            bss.rssi,
            ByteBufferToHexString(bss.ies).c_str());
        return true;
    }

    Log::Debug(
        L"Mirroring only BSS, Bssid: %ws, Ssid: %ws, ChannelCenterFreq: %d, Rssi: %d, Original AuthAlgo: %ws, "
        L"Original CipherAlgo: %ws",
        BssidToString(bss.bssid).c_str(),
        SsidToLogString(bss.ssid.value()).c_str(),
        bss.channelCenterFreq,
        bss.rssi,
        Wlansvc::AuthAlgoToString(matchingNetwork->dot11DefaultAuthAlgorithm).c_str(),
        Wlansvc::CipherAlgoToString(matchingNetwork->dot11DefaultCipherAlgorithm).c_str());

    return false;
}

/// @brief Return the auth algo that will be shown in scan results to the guest, given the real scanned algo
DOT11_AUTH_ALGORITHM AdaptAuthAlgo(std::pair<DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM> authCipher)
{
    return Wlansvc::IsAuthCipherPairSupported(authCipher) ? authCipher.first : DOT11_AUTH_ALGO_RSNA_PSK;
}

ScannedBss BuildFakeScanResult(const ScannedBss& bss)
{
    // Use a fake Bss to generated the scan result IEs
    const FakeBss fakeBss{
        BssCapability::Ess | BssCapability::Privacy,
        bss.rssi,
        bss.channelCenterFreq,
        bss.beaconInterval,
        bss.bssid,
        bss.ssid,
        {AkmSuite::Psk},
        {CipherSuite::Ccmp},
        CipherSuite::Ccmp,
        {} // Key won't be used
    };

    return ScannedBss{fakeBss};
}

std::vector<ScannedBss> AdaptScanResult(const std::vector<ScannedBss>& bssList, const std::vector<WLAN_AVAILABLE_NETWORK>& networkList)
{
    std::vector<ScannedBss> results;
    for (const auto& bss : bssList)
    {
        if (!IsBssSupported(bss, networkList))
        {
            // Replace all Bss with an unsupported network type a WPA2-PSK entry
            // A guest initiated connection won't work, but a host connection can be mirrored
            results.push_back(BuildFakeScanResult(bss));
        }
        else
        {
            results.push_back(bss);
        }
    }
    return results;
}

} // namespace

RealWlanInterface::RealWlanInterface(std::shared_ptr<Wlansvc::WlanApiWrapper> wlansvc, const GUID& interfaceGuid)
    : m_wlansvc{std::move(wlansvc)}, m_interfaceGuid{interfaceGuid}
{
    m_wlansvc->Subscribe(m_interfaceGuid, [this](const auto& n) { WlanNotificationHandler(n); });
}

RealWlanInterface::~RealWlanInterface()
{
    try
    {
        m_wlansvc->Unsubscribe(m_interfaceGuid);
    }
    CATCH_LOG()
}

void RealWlanInterface::WlanNotificationHandler(const WLAN_NOTIFICATION_DATA& notification) noexcept
try
{
    if (notification.NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM)
    {
        switch (notification.NotificationCode)
        {
        case wlan_notification_acm_disconnected:
            OnDisconnected(*static_cast<WLAN_CONNECTION_NOTIFICATION_DATA*>(notification.pData));
            break;
        case wlan_notification_acm_scan_complete:
        case wlan_notification_acm_scan_fail:
            OnScanComplete();
            break;
        case wlan_notification_acm_connection_complete:
            OnConnectComplete(*static_cast<WLAN_CONNECTION_NOTIFICATION_DATA*>(notification.pData));
            break;
        default:
            return;
        }
    }
    else if (notification.NotificationSource == WLAN_NOTIFICATION_SOURCE_MSM)
    {
        switch (notification.NotificationCode)
        {
        case wlan_notification_msm_signal_quality_change:
            OnSignalQualityChange(*static_cast<unsigned long*>(notification.pData));
            break;
        default:
            return;
        }
    }
}
CATCH_LOG()

void RealWlanInterface::SetNotificationHandler(INotificationHandler* handler)
{
    {
        auto lock = std::scoped_lock(m_notifMutex);
        m_notifCallback = handler;
    }

    // Send an initial notification if this interface is connected
    try
    {
        const auto currentConnection = m_wlansvc->GetCurrentConnection(m_interfaceGuid);
        if (currentConnection && currentConnection->isState == wlan_interface_state_connected)
        {
            NotifyHostConnection(
                currentConnection->wlanAssociationAttributes.dot11Ssid,
                AdaptAuthAlgo(
                    {currentConnection->wlanSecurityAttributes.dot11AuthAlgorithm, currentConnection->wlanSecurityAttributes.dot11CipherAlgorithm}));
        }
    }
    CATCH_LOG()
}

const GUID& RealWlanInterface::GetGuid() const noexcept
{
    return m_interfaceGuid;
}

std::optional<ConnectedNetwork> RealWlanInterface::IsConnectedTo(const Ssid& requestedSsid) noexcept
{
    try
    {
        const auto currentConnection = m_wlansvc->GetCurrentConnection(m_interfaceGuid);
        // Note: This does not handle transient interface states when connection is being setup
        if (!currentConnection || currentConnection->isState != wlan_interface_state_connected)
        {
            return std::nullopt;
        }

        ConnectedNetwork network{
            currentConnection->wlanAssociationAttributes.dot11Ssid,
            toBssid(currentConnection->wlanAssociationAttributes.dot11Bssid),
            currentConnection->wlanSecurityAttributes.dot11AuthAlgorithm
        };

        if (requestedSsid != network.ssid)
        {
            return std::nullopt;
        }

        Log::Info(
            L"Host interface %ws already connected to ssid: %ws, bssid: %ws, auth: %ws",
            GuidToString(m_interfaceGuid).c_str(),
            SsidToLogString(network.ssid.value()).c_str(),
            BssidToString(network.bssid).c_str(),
            Wlansvc::AuthAlgoToString(network.auth).c_str());
        return network;
    }
    CATCH_LOG()

    return std::nullopt;
}

std::future<std::pair<WlanStatus, ConnectedNetwork>> RealWlanInterface::Connect(const Ssid& ssid, const Bssid& bssid, const WlanSecurity& securityInfo)
{
    const auto authCipher = Wlansvc::DetermineAuthCipherPair(securityInfo);
    const auto connectionProfile = Wlansvc::MakeConnectionProfile(ssid, authCipher, securityInfo.key);

    // Parse the requested BSSID from the request
    const DOT11_MAC_ADDRESS& requestedBssid = *reinterpret_cast<const DOT11_MAC_ADDRESS*>(bssid.data());

    // Ask Wlansvc to connect
    std::scoped_lock connectLock(m_promiseMutex);
    Log::Trace(L"Connecting to %ws on host interface %ws", SsidToLogString(ssid.value()).c_str(), GuidToString(m_interfaceGuid).c_str());
    m_wlansvc->Connect(m_interfaceGuid, connectionProfile, requestedBssid);

    m_connectPromise.emplace();
    return m_connectPromise->get_future();
}

void RealWlanInterface::OnConnectComplete(const WLAN_CONNECTION_NOTIFICATION_DATA& data)
{
    if (data.wlanReasonCode == ERROR_SUCCESS)
    {
        const auto connInfo = m_wlansvc->GetCurrentConnection(m_interfaceGuid);
        if (!connInfo)
        {
            Log::Trace(
                L"Could not get the connection information after connecting the interface %ws", GuidToString(m_interfaceGuid).c_str());
            std::scoped_lock connectLock(m_promiseMutex);
            if (m_connectPromise)
            {
                m_connectPromise->set_value({WlanStatus::UnspecifiedFailure, ConnectedNetwork{}});
                m_connectPromise = std::nullopt;
            }
            return;
        }

        // Notify the client for the host connection outside of the lock
        NotifyHostConnection(
            data.dot11Ssid,
            AdaptAuthAlgo({connInfo->wlanSecurityAttributes.dot11AuthAlgorithm, connInfo->wlanSecurityAttributes.dot11CipherAlgorithm}));

        // If there is a promise, this is a successful guest initiated connection
        std::scoped_lock connectLock(m_promiseMutex);
        if (m_connectPromise)
        {
            auto connectedNetwork = ConnectedNetwork{
                connInfo->wlanAssociationAttributes.dot11Ssid,
                toBssid(connInfo->wlanAssociationAttributes.dot11Bssid),
                connInfo->wlanSecurityAttributes.dot11AuthAlgorithm};

            m_connectPromise->set_value({WlanStatus::Success, connectedNetwork});
            m_connectPromise = std::nullopt;
        }
    }
    else
    {
        // If there is a promise, the guest initiated connection failed
        std::scoped_lock connectLock(m_promiseMutex);
        if (m_connectPromise)
        {
            Log::Trace(L"Could not connect host interface %ws", GuidToString(m_interfaceGuid).c_str());
            m_connectPromise->set_value({WlanStatus::UnspecifiedFailure, ConnectedNetwork{}});
            m_connectPromise = std::nullopt;
        }
    }
}

std::future<void> RealWlanInterface::Disconnect()
{
    std::unique_lock disconnectLock(m_promiseMutex);

    Log::Trace(L"Requesting disconnection on host interface %ws", GuidToString(m_interfaceGuid).c_str());
    m_wlansvc->Disconnect(m_interfaceGuid);

    m_disconnectPromise.emplace();
    return m_disconnectPromise->get_future();
}

void RealWlanInterface::OnDisconnected(const WLAN_CONNECTION_NOTIFICATION_DATA& data)
{
    // Let the client and guest know about the host disconnection out of the lock
    Log::Trace(L"Host interface %ws disconnected", GuidToString(m_interfaceGuid).c_str());
    NotifyHostDisconnection(data.dot11Ssid);

    {
        // If there is a promise, this is a guest initiated disconnection
        std::scoped_lock disconnectLock(m_promiseMutex);
        if (m_disconnectPromise)
        {
            Log::Trace(L"Disconnection complete on host interface %ws", GuidToString(m_interfaceGuid).c_str());
            m_disconnectPromise->set_value();
            m_disconnectPromise = std::nullopt;
            return;
        }
    }
}

std::future<std::pair<std::vector<ScannedBss>, ScanStatus>> RealWlanInterface::Scan(std::optional<const Ssid>& ssid)
{
    std::unique_lock scanLock(m_promiseMutex);
    if (m_scanRunning)
    {
        // A scan was already scheduled. Wait for its completion to provide results
        Log::Trace(L"A scan was already scheduled on interface %ws. Waiting for its completion.", GuidToString(m_interfaceGuid).c_str());
        m_scanPromise.emplace();
        return m_scanPromise->get_future();
    }

    // A scan request to wlansvc always flushes the BSS cache. Cache the existing results, and use them if the scan fails
    // and return no results: drivers can fail a scan right after the host connects (media in use), but relevant results
    // have already been scanned.
    auto cachedScannedBss = m_wlansvc->GetScannedBssList(m_interfaceGuid);
    auto cachedScannedNetworks = m_wlansvc->GetScannedNetworkList(m_interfaceGuid);

    auto scannedBss = AdaptScanResult(cachedScannedBss, cachedScannedNetworks);

    try
    {
        m_scanRunning = true;

        if (ssid)
        {
            auto requestedSsid = static_cast<DOT11_SSID>(*ssid);

            Log::Trace(
                L"Requesting targeted scan on host interface %ws, Ssid: %ws",
                GuidToString(m_interfaceGuid).c_str(),
                SsidToLogString({requestedSsid.ucSSID, requestedSsid.uSSIDLength}).c_str());
            m_wlansvc->Scan(m_interfaceGuid, &requestedSsid);
        }
        else
        {
            Log::Trace(L"Requesting scan on host interface %ws", GuidToString(m_interfaceGuid).c_str());
            m_wlansvc->Scan(m_interfaceGuid);
        }
    }
    catch (...)
    {
        m_scanRunning = false;
    }

    // Always mark the scan as completed: if the cached results are not good enough, the next scan request
    // will wait for the real scan completion, or the new results will be sent through a notification
    Log::Trace(L"Reporting cached scan results on interface %ws", GuidToString(m_interfaceGuid).c_str());

    std::promise<std::pair<std::vector<ScannedBss>, ScanStatus>> promise;
    promise.set_value({std::move(scannedBss), ScanStatus::Completed});
    return promise.get_future();
}

void RealWlanInterface::OnScanComplete()
{
    auto scanResults = m_wlansvc->GetScannedBssList(m_interfaceGuid);
    auto availableNetworks = m_wlansvc->GetScannedNetworkList(m_interfaceGuid);

    auto results = AdaptScanResult(scanResults, availableNetworks);

    {
        std::unique_lock scanLock(m_promiseMutex);

        // The scan is not running anymore
        m_scanRunning = false;

        // If a scan request is waiting, complete the promise
        if (m_scanPromise)
        {
            m_scanPromise->set_value({std::move(results), ScanStatus::Completed});
            return;
        }
    }

    // Nobody is waiting, simply notify the guest of the new results
    NotifyScanResults(std::move(results), ScanStatus::Completed);
}

void RealWlanInterface::OnSignalQualityChange(unsigned long signal) const
{
    NotifySignalQualityChange(signal);
}

} // namespace ProxyWifi