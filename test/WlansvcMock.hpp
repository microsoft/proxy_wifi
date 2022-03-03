// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include <catch2/catch.hpp>
#include "WlanSvcWrapper.hpp"

#include "Iee80211Utils.hpp"
#include "StringUtils.hpp"

#include <algorithm>
#include <iterator>
#include <optional>
#include <regex>
#include <thread>

namespace Mock {

/// @brief Represent a network visible from the station
struct Network
{
    WLAN_AVAILABLE_NETWORK network;
    ProxyWifi::ScannedBss bss;
};

//------------------------------------------------------------------------------
// ------------------------- Test data -----------------------------------------
//------------------------------------------------------------------------------
//
// As a rule of thumb, the value of not-commented fields isn't used by the lib
// and their value doesn't matter

constexpr GUID c_intf1{0xcfd367f6, 0x870b, 0x49d7, {0xbb, 0x75, 0x67, 0xd4, 0x10, 0xee, 0xb9, 0x8b}};
constexpr GUID c_intf2{0xa004e4fe, 0x232e, 0x4bf4, {0xa2, 0xdb, 0x86, 0x02, 0xe2, 0xc6, 0xd7, 0x45}};

/// @brief A WPA2PSK network
static const Network c_wpa2PskNetwork{
    WLAN_AVAILABLE_NETWORK{
        L"ProfileWpa2Psk",
        {10, {'w', 'p', 'a', '2', 'p', 's', 'k', 'n', 'e', 't'}}, // Ssid
        dot11_BSS_type_infrastructure,
        1,
        true,
        WLAN_REASON_CODE_SUCCESS,
        0,
        {},
        false,
        88,
        true,
        DOT11_AUTH_ALGO_RSNA_PSK, // Auth algo
        DOT11_CIPHER_ALGO_CCMP,   // Cipher algo
        0,
        0},
    ProxyWifi::ScannedBss{
        {0, 1, 2, 3, 4, 5},                                                              // Bssid
        ProxyWifi::Ssid{"wpa2psknet"},                                                   // Ssid
        WI_EnumValue(ProxyWifi::BssCapability::Ess | ProxyWifi::BssCapability::Privacy), // Capabilities
        -56,                                                                             // Rssi
        2412000,                                                                         // Channel center freq
        0,                                                                               // Beacon period
        // Not a real IE. The lib only forward IE, so the value doesn't matter.
        {0x00, 0x0b, 0x47, 0x69, 0x67, 0x61, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x7}}};

/// @brief An Open network
static const Network c_openNetwork{
    WLAN_AVAILABLE_NETWORK{
        L"ProfileOpen",
        {7, {'o', 'p', 'e', 'n', 'n', 'e', 't'}}, // Ssid
        dot11_BSS_type_infrastructure,
        1,
        true,
        WLAN_REASON_CODE_SUCCESS,
        0,
        {},
        false,
        88,
        true,
        DOT11_AUTH_ALGO_80211_OPEN, // Auth algo
        DOT11_CIPHER_ALGO_NONE,   // Cipher algo
        0,
        0},
    ProxyWifi::ScannedBss{
        {6, 7, 8, 9, 10, 11},                        // Bssid
        ProxyWifi::Ssid{"opennet"},                  // Ssid
        WI_EnumValue(ProxyWifi::BssCapability::Ess), // Capabilities
        -80,                                         // Rssi
        5745000,                                     // Channel center freq
        0,                                           // Beacon period
        // Not a real IE. The lib only forward IE, so the value doesn't matter.
        {0x00, 0x0b, 0x47, 0x69, 0x67, 0x61, 0x46, 0x61}}};

/// @brief An non-supported network (here, an enterprise one)
static const Network c_enterpriseNetwork{
    WLAN_AVAILABLE_NETWORK{
        L"ProfileEnterprise",
        {7, {'e', 'n', 't', '_', 'n', 'e', 't'}}, // Ssid
        dot11_BSS_type_infrastructure,
        1,
        true,
        WLAN_REASON_CODE_SUCCESS,
        0,
        {},
        false,
        88,
        true,
        DOT11_AUTH_ALGO_RSNA,   // Auth algo
        DOT11_CIPHER_ALGO_CCMP, // Cipher algo
        0,
        0},
    ProxyWifi::ScannedBss{
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},                                            // Bssid
        ProxyWifi::Ssid{"ent_net"},                                                      // Ssid
        WI_EnumValue(ProxyWifi::BssCapability::Ess | ProxyWifi::BssCapability::Privacy), // Capabilities
        -50,                                                                             // Rssi
        5745000,                                                                         // Channel center freq
        0,                                                                               // Beacon period
        // Not a real IE. The lib only forward IE, so the value doesn't matter.
        {0x00, 0x0b, 0x47, 0x69, 0x67, 0x61, 0x46, 0x61, 0xaa, 0xcc, 0xab}}};

/// @brief Another WPA2PSK network, for when we need more connectable networks
static const Network c_pizzaNetwork{
    WLAN_AVAILABLE_NETWORK{
        L"",
        {8, {'p', 'i', 'z', 'z', 'a', 'n', 'e', 't'}}, // Ssid
        dot11_BSS_type_infrastructure,
        1,
        true,
        WLAN_REASON_CODE_SUCCESS,
        0,
        {},
        false,
        88,
        true,
        DOT11_AUTH_ALGO_RSNA_PSK, // Auth algo
        DOT11_CIPHER_ALGO_CCMP,   // Cipher algo
        0,
        0},
    ProxyWifi::ScannedBss{
        {5, 4, 3, 2, 1, 0},                                                              // Bssid
        ProxyWifi::Ssid{"pizzanet"},                                                     // Ssid
        WI_EnumValue(ProxyWifi::BssCapability::Ess | ProxyWifi::BssCapability::Privacy), // Capabilities
        -56,                                                                             // Rssi
        2412000,                                                                         // Channel center freq
        0,                                                                               // Beacon period
        // Not a real IE. The lib only forward IE, so the value doesn't matter.
        {0x00, 0x0b, 0x47, 0x69, 0x42, 0x61, 0x42, 0x61, 0x63, 0x74, 0x6f, 0x7}}};

/// @brief The RSNE IE for a WPA2PSK network
static const std::vector<uint8_t> c_wpa2pskRsnIe{0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00,
                                                 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};

//------------------------------------------------------------------------------
// ------------------------- Wlansvc Mock --------------------------------------
//------------------------------------------------------------------------------

/// @brief Emulate the behavior of Wlansvc for method in WlanApiWrapper.
/// Method behavior may be configured by setting member variables prior to calling a method
struct WlanSvcFake : public ProxyWifi::Wlansvc::WlanApiWrapper
{
    WlanSvcFake() = default;

    WlanSvcFake(const std::vector<GUID>& interfaces, const std::vector<Network>& visibleNetworks = {}, bool cacheScanResults = true)
    {
        for (const auto& guid : interfaces)
        {
            m_interfaces.emplace(std::make_pair(guid, WlanInterface{cacheScanResults ? visibleNetworks : std::vector<Network>{}, std::nullopt}));
        }
        m_visibleNetworks = std::move(visibleNetworks);
    }

    WlanSvcFake(const WlanSvcFake&) = delete;
    WlanSvcFake(WlanSvcFake&&) = delete;
    WlanSvcFake& operator=(const WlanSvcFake&) = delete;
    WlanSvcFake& operator=(WlanSvcFake&&) = delete;

    ~WlanSvcFake() override
    {
        WaitForNotifComplete();
    }

    void AddNetwork(const Network& network)
    {
        m_visibleNetworks.push_back(network);
    }

    void AddNetwork(const GUID& interfaceGuid, const Network& network)
    {
        m_interfaces.at(interfaceGuid).m_visibleNetworks.push_back(network);
    }

    // ----------------------- Mocked methods ----------------------------------

    std::vector<GUID> EnumerateInterfaces() override
    {
        std::vector<GUID> res;
        for (const auto& i: m_interfaces)
        {
            res.push_back(i.first);
        }
        return res;
    }

    void Subscribe(const GUID& interfaceGuid, std::function<void(const WLAN_NOTIFICATION_DATA&)> callback) override
    {
        auto lock = m_notifLock.lock_exclusive();
        m_notifCallbacks[interfaceGuid] = callback;
    }

    void Unsubscribe(const GUID& interfaceGuid) override
    {
        auto lock = m_notifLock.lock_exclusive();
        m_notifCallbacks[interfaceGuid] = nullptr;
    }

    std::optional<WLAN_CONNECTION_ATTRIBUTES> GetCurrentConnection(const GUID& interfaceGuid) override
    {
        auto connectedBss = m_interfaces.at(interfaceGuid).m_connectedBss;
        if (connectedBss)
        {
            WLAN_CONNECTION_ATTRIBUTES r{};
            r.isState = connectedBss ? wlan_interface_state_connected : wlan_interface_state_disconnected;
            r.wlanAssociationAttributes.dot11Ssid = connectedBss->bss.ssid;
            std::ranges::copy(connectedBss->bss.bssid, r.wlanAssociationAttributes.dot11Bssid);
            r.wlanSecurityAttributes.dot11AuthAlgorithm = connectedBss->network.dot11DefaultAuthAlgorithm;
            r.wlanSecurityAttributes.dot11CipherAlgorithm = connectedBss->network.dot11DefaultCipherAlgorithm;
            return r;
        }
        return std::nullopt;
    }

    void Connect(const GUID& interfaceGuid, const std::wstring& profile, const DOT11_MAC_ADDRESS&) override
    {
        callCount.connect++;

        // Update the Fake wlansvc connected network
        std::wsmatch sm1;
        REQUIRE(std::regex_search(profile, sm1, std::wregex(L"<hex>(.*)</hex>")));
        const auto byteBuffer = HexStringToByteBuffer(sm1.str(1));

        ConnectHost(interfaceGuid, ProxyWifi::Ssid{byteBuffer});
    }

    void Disconnect(const GUID& interfaceGuid) override
    {
        callCount.disconnect++;
        DisconnectHost(interfaceGuid);
    }

    void Scan(const GUID& interfaceGuid, DOT11_SSID* = nullptr) override
    {

        // Produce the union of two unsorted containers (quadratic) in parameter `b`
        auto buildUnion =
            [](const auto& a, auto& b, auto eq) {
                std::ranges::copy_if(a, std::back_inserter(b), [&](const auto& ea) {
                    return !std::ranges::any_of(b, [&](const auto& eb) {
                        return eq(ea, eb);
                    });
                });
            };

        // Add visible networks to the interface
        auto& intf = m_interfaces.at(interfaceGuid);
        buildUnion(m_visibleNetworks, intf.m_visibleNetworks, [](const auto& n1, const auto& n2) {
            return n1.bss.bssid == n2.bss.bssid;
        });

        // Send a notification to annonce the scan completion
        SendWlansvcNotif(interfaceGuid, [interfaceGuid](const auto& send) {
            WLAN_REASON_CODE rc = WLAN_REASON_CODE_SUCCESS;
            send({WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_scan_complete, interfaceGuid, sizeof rc, &rc});
        });
    }

    std::vector<ProxyWifi::ScannedBss> GetScannedBssList(const GUID& interfaceGuid) override
    {
        const auto& networks = m_interfaces.at(interfaceGuid).m_visibleNetworks;

        std::vector<ProxyWifi::ScannedBss> r;
        std::ranges::transform(networks, std::back_inserter(r), [](const auto& n) { return n.bss; });
        return r;
    }

    std::vector<WLAN_AVAILABLE_NETWORK> GetScannedNetworkList(const GUID& interfaceGuid) override
    {
        const auto& networks = m_interfaces.at(interfaceGuid).m_visibleNetworks;

        std::vector<WLAN_AVAILABLE_NETWORK> r;
        std::ranges::transform(networks, std::back_inserter(r), [](const auto& n) { return n.network; });
        return r;
    }

    // ----------- Methods to drive the fake wlansvc from test code ------------

    void AddInterface(const GUID& interfaceGuid)
    {
        m_interfaces.emplace(std::make_pair(interfaceGuid, WlanInterface{}));
        SendWlansvcNotif(interfaceGuid, [interfaceGuid](const auto& send) {
            send({WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_interface_arrival, interfaceGuid, 0, nullptr});
        });
    }

    void RemoveInterface(const GUID& interfaceGuid)
    {
        const auto it = m_interfaces.find(interfaceGuid);
        if (it != m_interfaces.end())
        {
            m_interfaces.erase(it);
        }
        SendWlansvcNotif(interfaceGuid, [interfaceGuid](const auto& send) {
            send({WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_interface_removal, interfaceGuid, 0, nullptr});
        });
    }

    /// @brief Internal connect function, for call from test code
    void ConnectHost(const GUID& interfaceGuid, const ProxyWifi::Ssid& ssid)
    {
        const auto& networks = m_interfaces.at(interfaceGuid).m_visibleNetworks;
        const auto network = std::ranges::find_if(networks, [&](const auto& e) { return ssid == e.bss.ssid; });

        if (network != networks.end())
        {
            m_interfaces.at(interfaceGuid).m_connectedBss = *network;
        }
        else
        {
            m_interfaces.at(interfaceGuid).m_connectedBss = std::nullopt;
        }

        // Send a notification to annonce the connection completion
        const auto notifCallback = m_notifCallbacks.find(interfaceGuid);
        if (notifCallback != m_notifCallbacks.end())
        {
            auto r = m_interfaces.at(interfaceGuid).m_connectedBss ? WLAN_REASON_CODE_SUCCESS : WLAN_REASON_CODE_UNKNOWN;
            SendWlansvcNotif(interfaceGuid, [interfaceGuid, ssid, r](const auto& send) {
                // All we care about are the result code and ssid
                WLAN_CONNECTION_NOTIFICATION_DATA data{};
                data.dot11Ssid = ssid;
                data.wlanReasonCode = r;
                send({WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_connection_complete, interfaceGuid, sizeof data, &data});
            });
        }
    }

    /// @brief Internal Disconnect function for call from test code
    void DisconnectHost(const GUID& interfaceGuid)
    {
        auto& connectedBss = m_interfaces.at(interfaceGuid).m_connectedBss;
        REQUIRE(connectedBss.has_value());

        // Simply send a notification to annonce the disconnection completion

        // "Disconnect"
        SendWlansvcNotif(interfaceGuid, [interfaceGuid, bss = connectedBss->bss](const auto& send) {
            // All we care about are the result code and ssid
            WLAN_CONNECTION_NOTIFICATION_DATA data{};
            data.dot11Ssid = bss.ssid;
            data.wlanReasonCode = WLAN_REASON_CODE_SUCCESS;
            send({WLAN_NOTIFICATION_SOURCE_ACM, wlan_notification_acm_disconnected, interfaceGuid, sizeof data, &data});
        });

        connectedBss = std::nullopt;
    }

    void SetSignalQuality(const GUID& interfaceGuid, unsigned long signalQuality)
    {
        // Simply send a notification to annonce the scan completion
        SendWlansvcNotif(interfaceGuid, [interfaceGuid, signalQuality](const auto& send) mutable {
            send(WLAN_NOTIFICATION_DATA{
                WLAN_NOTIFICATION_SOURCE_MSM, wlan_notification_msm_signal_quality_change, interfaceGuid, sizeof signalQuality, &signalQuality});
        });
    }

    // Allows test code to wait until a notification is processed by an interface
    void WaitForNotifComplete()
    {
        if (m_notifThread.joinable())
        {
            m_notifThread.join();
        }
    }

    // Call counters
    struct CallCount
    {
        int connect = 0;
        int disconnect = 0;
    };
    CallCount callCount{};

private:
    using NotifBuilder = std::function<void(const std::function<void(const WLAN_NOTIFICATION_DATA&)>&)>;
    void SendWlansvcNotif(const GUID& intfGuid, NotifBuilder notifBuilder)
    {
        WaitForNotifComplete();

        m_notifThread = std::thread([this, intfGuid, notifBuilder = std::move(notifBuilder)] {
            auto lock = m_notifLock.lock_shared();
            const auto callback = m_notifCallbacks.find(intfGuid);
            // Null guid subscription get all the notifications
            const auto allIntfCallback = m_notifCallbacks.find(GUID{});
            notifBuilder([&](const auto& n) {
                if (callback != m_notifCallbacks.end())
                {
                    callback->second(n);
                }
                if (allIntfCallback != m_notifCallbacks.end())
                {
                    allIntfCallback->second(n);
                }
            });
        });
    }

    // Fake Wlansvc state
    struct WlanInterface
    {
        std::vector<Network> m_visibleNetworks;
        std::optional<Network> m_connectedBss;
    };
    std::unordered_map<GUID, WlanInterface> m_interfaces{};
    std::vector<Network> m_visibleNetworks{};

    wil::srwlock m_notifLock;
    std::unordered_map<GUID, std::function<void(const WLAN_NOTIFICATION_DATA&)>> m_notifCallbacks;
    std::thread m_notifThread;
};
} // namespace Mock