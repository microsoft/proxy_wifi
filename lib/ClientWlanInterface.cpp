// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "ClientWlanInterface.hpp"

#include "StringUtils.hpp"
#include "ProxyWifi/Logs.hpp"

namespace ProxyWifi {

ClientWlanInterface::ClientWlanInterface(const GUID& interfaceGuid, std::function<std::vector<WifiNetworkInfo>()> callback)
    : m_getClientBssCallback{std::move(callback)}, m_interfaceGuid{interfaceGuid}
{
}

void ClientWlanInterface::SetNotificationHandler(INotificationHandler*)
{
    // ClientWlanInterface never send notification: all its networks are always connected with 100% signal quality
}

const GUID& ClientWlanInterface::GetGuid() const noexcept
{
    return m_interfaceGuid;
}

std::optional<ConnectedNetwork> ClientWlanInterface::IsConnectedTo(const Ssid& requestedSsid) noexcept
{
    const auto clientNetworks = GetBssFromClient();
    const auto network =
        std::ranges::find_if(clientNetworks, [&](const auto& n) { return n.ssid == requestedSsid; });

    if (network == clientNetworks.cend())
    {
        return std::nullopt;
    }
    // A fake interface is always considered connected to all the networks it handles
    Log::Info(
        L"Client interface %ws already connected to ssid: %ws",
        GuidToString(m_interfaceGuid).c_str(),
        SsidToLogString(requestedSsid.value()).c_str());
    // Fake interfaces pretend to see WPA2PSK networks
    return ConnectedNetwork{requestedSsid, toBssid(network->bssid), DOT11_AUTH_ALGORITHM_RSNA_PSK};
}

std::future<std::pair<WlanStatus, ConnectedNetwork>> ClientWlanInterface::Connect(const Ssid& requestedSsid, const Bssid&, const WlanSecurity&)
{
    const auto clientNetworks = GetBssFromClient();
    const auto network =
        std::ranges::find_if(clientNetworks, [&](const auto& n) { return n.ssid == requestedSsid; });

    std::promise<std::pair<WlanStatus, ConnectedNetwork>> promise;
    if (network == clientNetworks.cend())
    {
        Log::Trace(
            L"Could not connect client interface %ws to ssid: %ws",
            GuidToString(m_interfaceGuid).c_str(),
            SsidToLogString(requestedSsid.value()).c_str());
        promise.set_value({WlanStatus::UnspecifiedFailure, {}});
    }
    else
    {
        Log::Trace(
            L"Connected client interface %ws to to ssid: %ws",
            GuidToString(m_interfaceGuid).c_str(),
            SsidToLogString(requestedSsid.value()).c_str());
        promise.set_value({WlanStatus::Success, {requestedSsid, toBssid(network->bssid), DOT11_AUTH_ALGO_RSNA_PSK}});
    }
    return promise.get_future();
}

std::future<void> ClientWlanInterface::Disconnect()
{
    // Disconnect is a no-op for a fake interface
    std::promise<void> promise;
    promise.set_value();
    return promise.get_future();
}

std::future<std::pair<std::vector<ScannedBss>, ScanStatus>> ClientWlanInterface::Scan(std::optional<const Ssid>&)
{
    std::vector<ScannedBss> result;
    for (auto bss : GetBssFromClient())
    {
        if (bss.ssid.uSSIDLength > c_wlan_max_ssid_len)
        {
            Log::Info(L"Ignoring an invalid client provided SSID (length: %d)", bss.ssid.uSSIDLength);
            continue;
        }

        // Create a wpa2psk network with the requested SSID and BSSID
        FakeBss fakeBss;
        fakeBss.capabilities = BssCapability::Ess | BssCapability::Privacy;
        fakeBss.ssid = bss.ssid;
        fakeBss.bssid = toBssid(bss.bssid);
        fakeBss.akmSuites = {AkmSuite::Psk};
        fakeBss.cipherSuites = {CipherSuite::Ccmp};
        fakeBss.groupCipher = CipherSuite::Ccmp;

        Log::Debug(
            L"Reporting client BSS, Bssid: %ws, Ssid: %ws, AkmSuites: {%ws}, CipherSuites: {%ws}, GroupCipher: %.8x, "
            L"ChannelCenterFreq: %d",
            BssidToString(fakeBss.bssid).c_str(),
            SsidToLogString(fakeBss.ssid.value()).c_str(),
            ListEnumToHexString(gsl::span{fakeBss.akmSuites}).c_str(),
            ListEnumToHexString(gsl::span{fakeBss.cipherSuites}).c_str(),
            fakeBss.groupCipher ? WI_EnumValue(*fakeBss.groupCipher) : 0,
            fakeBss.channelCenterFreq);

        result.emplace_back(fakeBss);
    }

    Log::Debug(L"%d BSS entries reported on client interface %ws", result.size(), GuidToString(m_interfaceGuid).c_str());
    std::promise<std::pair<std::vector<ScannedBss>, ScanStatus>> promise;
    promise.set_value({std::move(result), ScanStatus::Completed});
    return promise.get_future();
}

} // namespace ProxyWifi