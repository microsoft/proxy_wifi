// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "WlanInterface.hpp"

#include <Windows.h>

#include <future>
#include <optional>
#include <vector>

#include "Networks.hpp"
#include "Iee80211Utils.hpp"

namespace ProxyWifi {

/// @brief This class represent a fake wlan interface simulating networks provided by the lib client
class TestWlanInterface : public IWlanInterface
{
public:
    TestWlanInterface(const GUID& interfaceGuid);

    void SetNotificationHandler(INotificationHandler* handler) override;
    const GUID& GetGuid() const noexcept override;
    std::optional<ConnectedNetwork> IsConnectedTo(const Ssid& requestedSsid) noexcept override;
    std::future<std::pair<WlanStatus, ConnectedNetwork>> Connect(const Ssid& requestedSsid, const Bssid& bssid, const WlanSecurity& securityInfo) override;
    std::future<void> Disconnect() override;
    std::future<std::pair<std::vector<ScannedBss>, ScanStatus>> Scan(std::optional<const Ssid>& ssid) override;

private:
    static std::vector<FakeBss> BuildFakeNetworkList();
    void NotificationSender();

    const GUID m_interfaceGuid{};
    const std::vector<FakeBss> m_networks{BuildFakeNetworkList()};
    std::mutex m_connectedNetworkMutex;
    std::optional<size_t> m_connectedNetwork;

    INotificationHandler* m_notifCallback{};

    inline void NotifyConnection(const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) const
    {
        if (m_notifCallback)
        {
            m_notifCallback->OnHostConnection(m_interfaceGuid, ssid, authAlgo);
        }
    }

    inline void NotifyDisconnection(const Ssid& ssid) const
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

    inline void NotifyScanResults(std::vector<ScannedBss> result, ScanStatus status) const
    {
        if (m_notifCallback)
        {
            m_notifCallback->OnHostScanResults(m_interfaceGuid, result, status);
        }
    }
};

} // namespace ProxyWifi