// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

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
        std::find_if(networks.cbegin(), networks.cend(), [&](const auto& n) { return bss.ssid == n.dot11Ssid; });

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
    FakeBss fakeBss{
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

RealWlanInterface::RealWlanInterface(const std::shared_ptr<Wlansvc::WlanApiWrapper>& wlansvc, const GUID& interfaceGuid)
    : m_wlansvc{wlansvc}, m_interfaceGuid{interfaceGuid}
{
    m_wlansvc->Subscribe(m_interfaceGuid, [this](const auto& n) { WlanNotificationHandler(n); });
}

RealWlanInterface::~RealWlanInterface()
{
    try
    {
        m_wlansvc->Unsubscribe(m_interfaceGuid);
    }
    CATCH_LOG();
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
        }
    }
}
CATCH_LOG()

void RealWlanInterface::SetNotificationHandler(INotificationHandler* handler)
{
    m_notifCallback = handler;

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

std::future<std::vector<ScannedBss>> RealWlanInterface::Scan(std::optional<const Ssid>& ssid)
{
    // A scan request to wlansvc always flushes the BSS cache. Cache the existing results, and use them if the scan fails
    // and return no results: drivers can fail a scan right after the host connects (media in use), but relevant results
    // have already been scanned.
    {
        std::scoped_lock cachedResult{m_cachedResultsMutex};
        m_cachedScannedBss = m_wlansvc->GetScannedBssList(m_interfaceGuid);
        m_cachedScannedNetworks = m_wlansvc->GetScannedNetworkList(m_interfaceGuid);
    }

    std::unique_lock scanLock(m_promiseMutex);
    try
    {
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
        std::scoped_lock cachedResult{m_cachedResultsMutex};
        std::promise<std::vector<ScannedBss>> promise;
        promise.set_value(AdaptScanResult(m_cachedScannedBss, m_cachedScannedNetworks));
        return promise.get_future();
    }

    m_scanPromise.emplace();
    return m_scanPromise->get_future();
}

void RealWlanInterface::OnScanComplete()
{
    auto scanResults = m_wlansvc->GetScannedBssList(m_interfaceGuid);
    auto availableNetworks = m_wlansvc->GetScannedNetworkList(m_interfaceGuid);

    if (scanResults.empty())
    {
        std::scoped_lock cachedResult{m_cachedResultsMutex};
        Log::Debug(L"No results after scan completion on host interface %ws, using cached results", GuidToString(m_interfaceGuid).c_str());
        scanResults.swap(m_cachedScannedBss);
        availableNetworks.swap(m_cachedScannedNetworks);
    }

    std::scoped_lock scanLock(m_promiseMutex);
    if (m_scanPromise)
    {
        auto results = AdaptScanResult(scanResults, availableNetworks);
        Log::Debug(L"%d BSS entries reported on host interface %ws", results.size(), GuidToString(m_interfaceGuid).c_str());
        m_scanPromise->set_value(std::move(results));
        m_scanPromise = std::nullopt;
    }
}

void RealWlanInterface::OnSignalQualityChange(unsigned long signal)
{
    NotifySignalQualityChange(signal);
}

} // namespace ProxyWifi