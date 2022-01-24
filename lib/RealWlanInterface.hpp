// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include <windows.h>
#include <wlanapi.h>

#include <wil/resource.h>

#include <future>
#include <optional>

#include "Networks.hpp"
#include "Iee80211Utils.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"
#include "WlanInterface.hpp"
#include "WlanSvcWrapper.hpp"

namespace ProxyWifi {

/// @brief This class represent an actual wlan station interface managed by wlansvc
class RealWlanInterface: public IWlanInterface
{
public:
    // Add notification handler parameter
    RealWlanInterface(const std::shared_ptr<Wlansvc::WlanApiWrapper>& wlansvc, const GUID& interfaceGuid);
    ~RealWlanInterface();

    void SetNotificationHandler(INotificationHandler* handler) override;

    const GUID& GetGuid() const noexcept override;
    std::optional<ConnectedNetwork> IsConnectedTo(const Ssid& requestedSsid) noexcept override;

    std::future<std::pair<WlanStatus, ConnectedNetwork>> Connect(const Ssid& requestedSsid, const Bssid& bssid, const WlanSecurity& securityInfo) override;
    std::future<void> Disconnect() override;
    std::future<std::vector<ScannedBss>> Scan(std::optional<const Ssid>& ssid) override;


private:
    void WlanNotificationHandler(const WLAN_NOTIFICATION_DATA& notification) noexcept;
    void OnConnectComplete(const WLAN_CONNECTION_NOTIFICATION_DATA& data);
    void OnDisconnected(const WLAN_CONNECTION_NOTIFICATION_DATA& data);
    void OnScanComplete();
    void OnSignalQualityChange(unsigned long signal);

    const std::shared_ptr<Wlansvc::WlanApiWrapper> m_wlansvc;
    const GUID m_interfaceGuid;

    std::mutex m_promiseMutex;
    std::optional<std::promise<std::pair<WlanStatus, ConnectedNetwork>>> m_connectPromise;
    std::optional<std::promise<void>> m_disconnectPromise;
    std::optional<std::promise<std::vector<ScannedBss>>> m_scanPromise;

    std::mutex m_cachedResultsMutex;
    std::vector<ScannedBss> m_cachedScannedBss;
    std::vector<WLAN_AVAILABLE_NETWORK> m_cachedScannedNetworks;

    INotificationHandler* m_notifCallback;

    inline void NotifyHostConnection(const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) const
    {
        if (m_notifCallback)
        {
            m_notifCallback->OnHostConnection(m_interfaceGuid, ssid, authAlgo);
        }
    }

    inline void NotifyHostDisconnection(const Ssid& ssid) const
    {
        if (m_notifCallback)
        {
            m_notifCallback->OnHostDisconnection(m_interfaceGuid, ssid);
        }
    }

    inline void NotifySignalQualityChange(unsigned long signal) const
    {
        if (m_notifCallback)
        {
            m_notifCallback->OnHostSignalQualityChange(m_interfaceGuid, signal);
        }
    }
};

} // namespace ProxyWifi