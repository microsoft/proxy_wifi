// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <algorithm>
#include <memory>
#include <utility>
#include <string>

#include <Windows.h>
#include <wlanapi.h>
#include <wlantypes.h>

#include <gsl/span>

#include "Iee80211Utils.hpp"

/// @brief Helpers for working with WlanSvc on Windows.
namespace ProxyWifi::Wlansvc {

/// @brief Get a log-friendly string describing the notification code from a WLAN_NOTIFICATION_DATA structure.
std::string GetWlanNotificationCodeString(const WLAN_NOTIFICATION_DATA& data);

/// @brief Indicate whether a BSSID is {00-00-00-00-00-00}
bool IsNullBssid(const DOT11_MAC_ADDRESS& bssid);

/// @brief Build a DOT11_BSSID_LIST from a list of BSSIDs
/// @return A pointer to the created DOT11_BSSID_LIST and a smart pointer to the memory allocated for it
std::pair<DOT11_BSSID_LIST*, std::unique_ptr<uint8_t[]>> BuildBssidList(gsl::span<const DOT11_MAC_ADDRESS> bssids);

/// @brief Map a 802.11 cipher suite to the corresponding Windows API enumeration
DOT11_CIPHER_ALGORITHM CipherSuiteToWindowsEnum(CipherSuite cipherSuite);

/// @brief Convert a link quality in percentage to an RSSI in dBm
inline constexpr int8_t LinkQualityToRssi(unsigned long signal)
{
    signal = std::clamp(signal, 0ul, 100ul);
    return static_cast<int8_t>(signal) / 2 - 100;
}

/// @brief Convert an authentication algorithm to a string for pretty printing
std::wstring AuthAlgoToString(DOT11_AUTH_ALGORITHM authAlgo) noexcept;

/// @brief Convert a cipher algorithm to a string for pretty printing
std::wstring CipherAlgoToString(DOT11_CIPHER_ALGORITHM cipher) noexcept;

/// @brief Convert an authentication algorithm to the string used in a wlan profile
std::wstring AuthAlgoToProfileString(DOT11_AUTH_ALGORITHM authAlgo);

/// @brief Convert a cipher algorithm to the string used in a wlan profile
std::wstring CipherAlgoToProfileString(DOT11_CIPHER_ALGORITHM cipher);

/// @brief Attempt to create a valid profile name from an SSID
/// If the SSID cannot be converted to a valid string, return a default name
std::wstring ProfileNameFromSSID(const Ssid& ssid);

/// @brief Build a valid, basic, wlan profile from the parameters
std::wstring MakeConnectionProfile(const Ssid& ssid, DOT11_AUTH_CIPHER_PAIR authCipher, const gsl::span<const uint8_t>& key);

/// @brief Determine whether an authentication/cipher is supported by the lib for real host connections
bool IsAuthCipherPairSupported(const std::pair<DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM>& authCipher);

/// @brief Build a DOT11_AUTH_CIPHER_PAIR from security parameters, throw if the parameters are invalid or unsupported
DOT11_AUTH_CIPHER_PAIR DetermineAuthCipherPair(const WlanSecurity& secInfo);

} // namespace ProxyWifi::Wlansvc
