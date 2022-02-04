// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <optional>
#include <vector>

#include "Iee80211Utils.hpp"

namespace ProxyWifi {

/// @brief Define fake bss, to emulate a non-existing network
struct FakeBss
{
    BssCapability capabilities = BssCapability::Ess;
    int32_t rssi = -50;
    uint32_t channelCenterFreq = 2432000; // 2.4GHz by default
    uint16_t beaconInterval = 0;
    Bssid bssid{};
    Ssid ssid;
    std::vector<AkmSuite> akmSuites;
    std::vector<CipherSuite> cipherSuites;
    std::optional<CipherSuite> groupCipher;
    std::vector<uint8_t> key;

    std::vector<uint8_t> BuildInformationElements() const;

    /// @brief The quantity of memory needed to store contain the IE for this network.
    /// The value is an approximation, it may be bigger than the actual size needed.
    size_t IeAllocationSize() const;
};

/// @brief Information about a BSS reported by a scan
struct ScannedBss
{
    ScannedBss() = default;
    explicit ScannedBss(const FakeBss& fakeBss);
    ScannedBss(Bssid bssid, Ssid ssid, uint16_t capabilities, int8_t rssi, uint32_t channelCenterFreq, uint16_t beaconInterval, std::vector<uint8_t> ies);

    Bssid bssid{};
    Ssid ssid;
    uint16_t capabilities = 0;
    int32_t rssi = -50;
    uint32_t channelCenterFreq = 2432000; // 2.4GHz by default
    uint16_t beaconInterval = 0;
    std::vector<uint8_t> ies;
};

struct ConnectedNetwork
{
    Ssid ssid;
    Bssid bssid{};
    DOT11_AUTH_ALGORITHM auth = DOT11_AUTH_ALGO_80211_OPEN;
};

enum class ScanStatus
{
    Running,
    Completed
};

} // namespace ProxyWifi