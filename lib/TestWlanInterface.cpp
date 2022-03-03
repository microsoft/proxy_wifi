// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "TestWlanInterface.hpp"

#include "LogsHelpers.hpp"
#include "StringUtils.hpp"
#include "ProxyWifi/Logs.hpp"

#include <iostream>

namespace ProxyWifi {

namespace {

DOT11_AUTH_ALGORITHM GetAuthAlgo(const FakeBss& bss)
{
    // The test interface support only open and wpa2psk networks
    return bss.akmSuites.empty() ? DOT11_AUTH_ALGO_80211_OPEN : DOT11_AUTH_ALGO_RSNA_PSK;
}

} // namespace

/* static */ std::vector<FakeBss> TestWlanInterface::BuildFakeNetworkList()
{
    return {
        {
            BssCapability::Ess | BssCapability::Privacy, // capabilities
            -50,                                         // rssi
            2432000,                                     // channelCenterFreq
            0,                                           // beaconInterval
            {0x0, 0x0, 0x0, 0x0, 0x0, 0x1},              // bssid
            Ssid{"FakeWpa2Psk"},                         // ssid
            {AkmSuite::Psk},                             // akmSuites
            {CipherSuite::Ccmp},                         // cipherSuites
            CipherSuite::Ccmp,                           // groupCipher
            {0x45, 0xf6, 0x30, 0x20, 0x80, 0xc4, 0x77, 0x93, 0x58, 0x28, 0x11, 0x59, 0xfa, 0x68, 0xbf, 0x4b, 0xf7,
             0x35, 0xd1, 0x01, 0xde, 0x08, 0x85, 0x4e, 0x88, 0x58, 0xaa, 0xb3, 0xeb, 0x03, 0x6a, 0xad} // key: "secretsecret"
        },
        {
            BssCapability::Ess,             // capabilities
            -50,                            // rssi
            5240000,                        // channelCenterFreq
            0,                              // beaconInterval
            {0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, // bssid
            Ssid{"FakeOpen"},               // ssid
            {},                             // akmSuites
            {},                             // cipherSuites
            std::nullopt,                   // groupCipher
            {},                             // key
        },
        {
            BssCapability::Ess,             // capabilities
            -50,                            // rssi
            6115000,                        // channelCenterFreq
            0,                              // beaconInterval
            {0x0, 0x0, 0x0, 0x0, 0x0, 0x3}, // bssid
            Ssid{"Fake6GHz"},               // ssid
            {},                             // akmSuites
            {},                             // cipherSuites
            std::nullopt,                   // groupCipher
            {},                             // key
        }};
}

TestWlanInterface::TestWlanInterface(const GUID& interfaceGuid)
    : m_interfaceGuid{interfaceGuid}
{
    // Start accepting user triggered notification
    auto notificationThread = std::thread([this]() {
        const auto logger = SetThreadWilFailureLogger();
        NotificationSender();
    });
    notificationThread.detach();
}

void TestWlanInterface::SetNotificationHandler(INotificationHandler* handler)
{
    m_notifCallback = handler;
}

const GUID& TestWlanInterface::GetGuid() const noexcept
{
    return m_interfaceGuid;
}

std::optional<ConnectedNetwork> TestWlanInterface::IsConnectedTo(const Ssid& requestedSsid) noexcept
{
    auto lock = std::scoped_lock{m_connectedNetworkMutex};
    if (!m_connectedNetwork || requestedSsid != m_networks[*m_connectedNetwork].ssid)
    {
        return std::nullopt;
    }

    Log::Info(
        L"Test interface %ws already connected to ssid: %ws",
        GuidToString(m_interfaceGuid).c_str(),
        SsidToLogString(requestedSsid.value()).c_str());
    return ConnectedNetwork{requestedSsid, m_networks[*m_connectedNetwork].bssid, GetAuthAlgo(m_networks[*m_connectedNetwork])};
}

std::future<std::pair<WlanStatus, ConnectedNetwork>> TestWlanInterface::Connect(const Ssid& requestedSsid, const Bssid&, const WlanSecurity&)
{
    const auto network = std::ranges::find_if(m_networks, [&](const auto& n) { return n.ssid == requestedSsid; });

    std::promise<std::pair<WlanStatus, ConnectedNetwork>> promise;
    if (network == m_networks.cend())
    {
        Log::Trace(
            L"Could not connect test interface %ws to ssid: %ws",
            GuidToString(m_interfaceGuid).c_str(),
            SsidToLogString(requestedSsid.value()).c_str());
        promise.set_value({WlanStatus::UnspecifiedFailure, {}});
    }
    else
    {
        Log::Trace(
            L"Connected test interface %ws to to ssid: %ws",
            GuidToString(m_interfaceGuid).c_str(),
            SsidToLogString(requestedSsid.value()).c_str());
        auto lock = std::scoped_lock{m_connectedNetworkMutex};
        m_connectedNetwork = std::distance(m_networks.begin(), network);
        promise.set_value({WlanStatus::Success, {requestedSsid, network->bssid, GetAuthAlgo(*network)}});
    }
    return promise.get_future();
}

std::future<void> TestWlanInterface::Disconnect()
{
    auto lock = std::scoped_lock{m_connectedNetworkMutex};
    m_connectedNetwork.reset();

    std::promise<void> promise;
    promise.set_value();
    return promise.get_future();
}

std::future<std::pair<std::vector<ScannedBss>, ScanStatus>> TestWlanInterface::Scan(std::optional<const Ssid>&)
{
    std::vector<ScannedBss> result;
    for (const auto& fakeBss : m_networks)
    {
        Log::Debug(
            L"Reporting fake BSS, Bssid: %ws, Ssid: %ws, AkmSuites: {%ws}, CipherSuites: {%ws}, GroupCipher: %.8x, "
            L"ChannelCenterFreq: %d",
            BssidToString(fakeBss.bssid).c_str(),
            SsidToLogString(fakeBss.ssid.value()).c_str(),
            ListEnumToHexString(gsl::span{fakeBss.akmSuites}).c_str(),
            ListEnumToHexString(gsl::span{fakeBss.cipherSuites}).c_str(),
            fakeBss.groupCipher ? WI_EnumValue(*fakeBss.groupCipher) : 0,
            fakeBss.channelCenterFreq);

        result.emplace_back(fakeBss);

        if (m_scanBehavior == ScanBehavior::Async)
        {
            // Only report the first network in the imediate answer of an async scan
            break;
        }
    }

    Log::Debug(L"%d BSS entries reported on test interface %ws", result.size(), GuidToString(m_interfaceGuid).c_str());
    std::promise<std::pair<std::vector<ScannedBss>, ScanStatus>> promise;
    promise.set_value({std::move(result), m_scanBehavior == ScanBehavior::Async ? ScanStatus::Running : ScanStatus::Completed});
    return promise.get_future();
}

void TestWlanInterface::NotificationSender()
{
    enum class Notification
    {
        ConnectedOpen,
        ConnectedPsk,
        Disconnected,
        SignalQuality,
        ScanResults,
        ScanSync,
        ScanAsync
    };

    static const std::array<std::pair<Notification, std::string>, 7> notifications{
        {{Notification::Disconnected, "Disconnected"},
         {Notification::ConnectedOpen, "Connected Open"},
         {Notification::ConnectedPsk, "Connected Psk"},
         {Notification::SignalQuality, "Signal quality"},
         {Notification::ScanResults, "Scan results"},
         {Notification::ScanSync, "Scan Mode: Sync"},
         {Notification::ScanAsync, "Scan Mode: Async"}}};

    for (;;)
    {
        std::cout << ">>> Enter a value to send a notification: ";
        for (auto i = 0u; i < notifications.size(); ++i)
        {
            std::cout << "<" << i << " -> " << notifications[i].second << "> ";
        }
        std::cout << std::endl;

        unsigned int userInput = std::numeric_limits<unsigned int>::max();
        std::cin >> userInput;
        if (userInput >= notifications.size())
        {
            std::cout << "Invalid notification code: " << userInput << std::endl;
            continue;
        }

        std::cout << "Sending notification " << notifications[userInput].second << std::endl;

        switch (notifications[userInput].first)
        {
        case Notification::Disconnected:
        {
            DOT11_SSID ssid{};
            {
                const auto lock = std::scoped_lock{m_connectedNetworkMutex};
                if (m_connectedNetwork)
                {
                    ssid = m_networks[*m_connectedNetwork].ssid;
                    m_connectedNetwork.reset();
                }
            }

            NotifyDisconnection(ssid);
            break;
        }
        case Notification::ConnectedOpen:
        {
            NotifyConnection(m_networks.front().ssid, DOT11_AUTH_ALGO_80211_OPEN);
            break;
        }
        case Notification::ConnectedPsk:
        {
            NotifyConnection(m_networks.front().ssid, DOT11_AUTH_ALGO_RSNA_PSK);
            break;
        }
        case Notification::SignalQuality:
        {
            NotifySignalQualityChange(60);
            break;
        }
        case Notification::ScanResults:
        {
            std::vector<ScannedBss> result;
            for (const auto& fakeBss : m_networks)
            {
                Log::Debug(
                    L"Reporting fake BSS, Bssid: %ws, Ssid: %ws, AkmSuites: {%ws}, CipherSuites: {%ws}, GroupCipher: %.8x, "
                    L"ChannelCenterFreq: %d",
                    BssidToString(fakeBss.bssid).c_str(),
                    SsidToLogString(fakeBss.ssid.value()).c_str(),
                    ListEnumToHexString(gsl::span{fakeBss.akmSuites}).c_str(),
                    ListEnumToHexString(gsl::span{fakeBss.cipherSuites}).c_str(),
                    fakeBss.groupCipher ? WI_EnumValue(*fakeBss.groupCipher) : 0,
                    fakeBss.channelCenterFreq);

                result.emplace_back(fakeBss);
            }
            NotifyScanResults(result, ScanStatus::Completed);
            break;
        }
        case Notification::ScanSync:
            m_scanBehavior = ScanBehavior::Sync;
            break;
        case Notification::ScanAsync:
            m_scanBehavior = ScanBehavior::Async;
            break;
        default:
            throw std::runtime_error("Unsupported notification");
        }
    }
}

} // namespace ProxyWifi