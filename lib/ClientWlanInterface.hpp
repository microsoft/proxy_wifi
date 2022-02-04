// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "WlanInterface.hpp"

#include <Windows.h>

#include <future>
#include <optional>

#include "Networks.hpp"
#include "Iee80211Utils.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"

namespace ProxyWifi {

/// @brief This class represent a fake wlan interface simulating networks provided by the lib client
class ClientWlanInterface : public IWlanInterface
{
public:
    ClientWlanInterface(const GUID& interfaceGuid, std::function<std::vector<WifiNetworkInfo>()> callback);

    void SetNotificationHandler(INotificationHandler* handler) override;
    const GUID& GetGuid() const noexcept override;
    std::optional<ConnectedNetwork> IsConnectedTo(const Ssid& requestedSsid) noexcept override;
    std::future<std::pair<WlanStatus, ConnectedNetwork>> Connect(const Ssid& requestedSsid, const Bssid& bssid, const WlanSecurity& securityInfo) override;
    std::future<void> Disconnect() override;
    std::future<std::pair<std::vector<ScannedBss>, ScanStatus>> Scan(std::optional<const Ssid>& ssid) override;

private:
    inline std::vector<WifiNetworkInfo> GetBssFromClient() const
    {
        if (m_getClientBssCallback)
        {
            return m_getClientBssCallback();
        }
        return {};
    }

    std::function<std::vector<WifiNetworkInfo>()> m_getClientBssCallback;
    const GUID m_interfaceGuid = FakeInterfaceGuid;
};

} // namespace ProxyWifi