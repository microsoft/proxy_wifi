// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "Messages.hpp"

#include <wil/safecast.h>

namespace ProxyWifi {

bool ScanResponseBuilder::IsBssAlreadyPresent(const Bssid& bssid)
{
    return std::ranges::find_if(m_bssList, [&](const auto& bss) { return bss.bssid == bssid; }) != m_bssList.cend();
}

void ScanResponseBuilder::AddBss(ScannedBss bss)
{
    if (IsBssAlreadyPresent(bss.bssid))
    {
        return;
    }
    m_bssList.push_back(std::move(bss));
}

void ScanResponseBuilder::SetScanComplete(bool isComplete) noexcept
{
    m_scanComplete = isComplete;
}

ScanResponse ScanResponseBuilder::Build() const
{
    auto allocSize = sizeof(proxy_wifi_scan_response) + m_bssList.size() * sizeof(proxy_wifi_bss);
    for (const auto& bss : m_bssList)
    {
        allocSize += bss.ies.size();
    }

    ScanResponse scanResponse{allocSize, m_bssList.size(), m_scanComplete};

    auto nextIe = scanResponse.getIes();
    for (auto i = 0u; i < m_bssList.size(); ++i)
    {
        const auto& bss = m_bssList[i];
        scanResponse->bss[i] = proxy_wifi_bss{
            {}, bss.capabilities, bss.rssi, bss.beaconInterval, bss.channelCenterFreq, wil::safe_cast<uint32_t>(bss.ies.size()), {}};
        std::ranges::copy(bss.bssid, scanResponse->bss[i].bssid);
        std::ranges::copy(bss.ies, nextIe.data());
        scanResponse->bss[i].ie_offset =
            wil::safe_cast<uint32_t>(std::distance(reinterpret_cast<uint8_t*>(&scanResponse->bss[i]), nextIe.data()));

        nextIe = nextIe.subspan(bss.ies.size());
    }

    return scanResponse;
}

} // namespace ProxyWifi