// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "Networks.hpp"

#include <cassert>
#include <stdexcept>
#include <string>
#include <wil/safecast.h>

namespace ProxyWifi {

namespace {

enum class Endianness
{
    Little,
    Big
};

/// @brief Append an unsigned integer to a vector as a list of bytes with specified endianness
/// @tparam N The number of bytes to append to the vector
/// @tparam E The endianness (Little = CPU order, Big = Network order)
/// @example appendBytes<4, Endianness::Big>(vec, 0x000fac04) -> vec = {..., 0x00, 0x0f, 0xac, 0x04}
template <size_t N, Endianness E, class T, class V, std::enable_if_t<std::is_integral_v<V> && !std::is_signed_v<V>, int> = 1>
void appendBytes(std::vector<T>& vector, V value)
{
    vector.reserve(vector.size() + N);
    for (auto i = 0u; i < N; ++i)
    {
        auto bitShift = 0u;
        if constexpr (E == Endianness::Big)
        {
            bitShift = (N - 1 - i) * 8;
        }
        else
        {
            bitShift = i * 8;
        }
        auto byte = static_cast<uint8_t>(value >> bitShift);
        vector.push_back(byte);
    }
}

} // namespace

size_t FakeBss::IeAllocationSize() const
{
    constexpr auto ieHeaderSize = 2;       // IE id + IE size
    constexpr auto rsnIeConstantSize = 12; // Version, Group cipher, Num ciphers, Num akms, capabilities
    constexpr auto suiteBlockSize = 4;

    return ieHeaderSize + ssid.size() + ieHeaderSize + rsnIeConstantSize + (akmSuites.size() + cipherSuites.size()) * suiteBlockSize;
}

std::vector<uint8_t> FakeBss::BuildInformationElements() const
{
    std::vector<uint8_t> ies;
    const std::vector<uint8_t>& rawSsid = ssid.value();
    if (!rawSsid.empty())
    {
        // Build an SSID element
        if (rawSsid.size() > c_wlan_max_ssid_len)
        {
            throw std::invalid_argument("Invalid ssid length: " + std::to_string(rawSsid.size()));
        }

        ies.insert(ies.end(), {WI_EnumValue(ElementId::Ssid), static_cast<uint8_t>(rawSsid.size())});
        ies.insert(ies.end(), rawSsid.begin(), rawSsid.end());
    }

    if (!akmSuites.empty())
    {
        assert(!cipherSuites.empty() && groupCipher.has_value());

        // Build an RSNIE
        // Warning: Assume all provided akm and cipher are compatibles
        constexpr auto rsnIeBaseSize = 12; // Version, Group cipher, Num ciphers, Num akms, capabilities
        constexpr auto suiteBlockSize = 4;
        const auto rsnIeSize = wil::safe_cast<uint8_t>(rsnIeBaseSize + (akmSuites.size() + cipherSuites.size()) * suiteBlockSize);

        ies.insert(ies.end(), {WI_EnumValue(ElementId::Rsn), rsnIeSize});

        // Add the version
        appendBytes<2, Endianness::Little>(ies, 0x0001u);

        // Add the group cipher
        appendBytes<4, Endianness::Big>(ies, WI_EnumValue(*groupCipher));

        // Add the pairwise cipher suites
        appendBytes<2, Endianness::Little>(ies, cipherSuites.size());
        for (const auto cipher : cipherSuites)
        {
            appendBytes<4, Endianness::Big>(ies, WI_EnumValue(cipher));
        }

        // Add the akm suites
        appendBytes<2, Endianness::Little>(ies, akmSuites.size());
        for (const auto akm : akmSuites)
        {
            appendBytes<4, Endianness::Big>(ies, WI_EnumValue(akm));
        }

        // Add the RSN capabilities
        appendBytes<2, Endianness::Little>(ies, 0x0000u);
    }

    return ies;
}

ScannedBss::ScannedBss(const FakeBss& fakeBss)
    : bssid{fakeBss.bssid},
      capabilities{WI_EnumValue(fakeBss.capabilities)},
      rssi{fakeBss.rssi},
      channelCenterFreq{fakeBss.channelCenterFreq},
      beaconInterval{fakeBss.beaconInterval},
      ies{fakeBss.BuildInformationElements()}
{
}

ScannedBss::ScannedBss(Bssid bssid, Ssid ssid, uint16_t capabilities, int8_t rssi, uint32_t channelCenterFreq, uint16_t beaconInterval, std::vector<uint8_t> ies)
    : bssid{bssid}, ssid{std::move(ssid)}, capabilities{capabilities}, rssi{rssi}, channelCenterFreq{channelCenterFreq}, beaconInterval{beaconInterval}, ies{std::move(ies)}
{
}

} // namespace ProxyWifi