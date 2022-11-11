// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "WlanSvcHelpers.hpp"

#include <array>
#include <stdexcept>

#include <wil/common.h>
#include <wil/result_macros.h>
#include <wil/safecast.h>

#include "StringUtils.hpp"

namespace ProxyWifi {
namespace {

static constexpr std::array AcmNotificationCodeStrings = {
    /* wlan_notification_acm_autoconf_enabled           */ "AutoconfEnabled",
    /* wlan_notification_acm_autoconf_disabled          */ "AutoconfDisabled",
    /* wlan_notification_acm_background_scan_enabled    */ "BackgroundScanEnabled",
    /* wlan_notification_acm_background_scan_disabled   */ "BackgroundScanDisabled",
    /* wlan_notification_acm_bss_type_change            */ "BssTypeChange",
    /* wlan_notification_acm_power_setting_change       */ "PowerSettingChange",
    /* wlan_notification_acm_scan_complete              */ "ScanComplete",
    /* wlan_notification_acm_scan_fail                  */ "ScanFail",
    /* wlan_notification_acm_connection_start           */ "ConnectionStart",
    /* wlan_notification_acm_connection_complete        */ "ConnectionComplete",
    /* wlan_notification_acm_connection_attempt_fail    */ "ConnectionAttemptFail",
    /* wlan_notification_acm_filter_list_change         */ "FilterListChange",
    /* wlan_notification_acm_interface_arrival          */ "InterfaceArrival",
    /* wlan_notification_acm_interface_removal          */ "InterfaceRemoval",
    /* wlan_notification_acm_profile_change             */ "ProfileChange",
    /* wlan_notification_acm_profile_name_change        */ "ProfileNameChange",
    /* wlan_notification_acm_profiles_exhausted         */ "ProfilesExhausted",
    /* wlan_notification_acm_network_not_available      */ "NetworkNotAvailable",
    /* wlan_notification_acm_network_available          */ "NetworkAvailable",
    /* wlan_notification_acm_disconnecting              */ "Disconnecting",
    /* wlan_notification_acm_disconnected               */ "Disconnected",
    /* wlan_notification_acm_adhoc_network_state_change */ "AdhocNetworkStateChange",
    /* wlan_notification_acm_profile_unblocked          */ "ProfileUnblocked",
    /* wlan_notification_acm_screen_power_change        */ "ScreenPowerChange",
    /* wlan_notification_acm_profile_blocked            */ "ProfileBlocked",
    /* wlan_notification_acm_scan_list_refresh          */ "ScanListRefresh",
    /* wlan_notification_acm_operational_state_change   */ "OperationalStateChange"};

static constexpr std::array MsmNotificationCodeStrings = {
    /* wlan_notification_msm_associating                   */ "associating",
    /* wlan_notification_msm_associated                    */ "associated",
    /* wlan_notification_msm_authenticating                */ "authenticating",
    /* wlan_notification_msm_connected                     */ "connected",
    /* wlan_notification_msm_roaming_start                 */ "roamingStart",
    /* wlan_notification_msm_roaming_end                   */ "roamingEnd",
    /* wlan_notification_msm_radio_state_change            */ "radioStateChange",
    /* wlan_notification_msm_signal_quality_change         */ "signalQualityChange",
    /* wlan_notification_msm_disassociating                */ "disassociating",
    /* wlan_notification_msm_disconnected                  */ "disconnected",
    /* wlan_notification_msm_peer_join                     */ "peerJoin",
    /* wlan_notification_msm_peer_leave                    */ "peerLeave",
    /* wlan_notification_msm_adapter_removal               */ "adapterRemoval",
    /* wlan_notification_msm_adapter_operation_mode_change */ "adapterOperationModeChange",
    /* wlan_notification_msm_link_degraded                 */ "linkDegraded",
    /* wlan_notification_msm_link_improved                 */ "linkImproved"};

inline std::string AcmNotificationCodeToString(const WLAN_NOTIFICATION_ACM& acm)
{
    if (acm <= wlan_notification_acm_start || acm >= wlan_notification_acm_end)
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "invalid WLAN_NOTIFICATION_ACM value (%d)", acm);

    return AcmNotificationCodeStrings[acm - 1];
}

inline std::string MsmNotificationCodeToString(const WLAN_NOTIFICATION_MSM& msm)
{
    if (msm <= wlan_notification_msm_start || msm >= wlan_notification_msm_end)
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "invalid WLAN_NOTIFICATION_MSM value (%d)", msm);

    return MsmNotificationCodeStrings[msm - 1];
}

} // namespace

namespace Wlansvc {

std::string GetWlanNotificationCodeString(const WLAN_NOTIFICATION_DATA& data)
{
    switch (data.NotificationSource)
    {
    case WLAN_NOTIFICATION_SOURCE_ACM:
        return AcmNotificationCodeToString(static_cast<WLAN_NOTIFICATION_ACM>(data.NotificationCode));
    case WLAN_NOTIFICATION_SOURCE_MSM:
        return MsmNotificationCodeToString(static_cast<WLAN_NOTIFICATION_MSM>(data.NotificationCode));
    default:
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "Wlan notification source not supported");
    }
}

bool IsNullBssid(const DOT11_MAC_ADDRESS& bssid)
{
    static constexpr DOT11_MAC_ADDRESS nullBssid{};
    return memcmp(&nullBssid, &bssid, sizeof(DOT11_MAC_ADDRESS)) == 0;
}

std::pair<DOT11_BSSID_LIST*, std::unique_ptr<uint8_t[]>> BuildBssidList(std::span<const DOT11_MAC_ADDRESS> bssids)
{
    auto buffer = std::make_unique<uint8_t[]>(sizeof(DOT11_BSSID_LIST) + bssids.size() * sizeof(DOT11_MAC_ADDRESS));
    auto* pBssidList = reinterpret_cast<DOT11_BSSID_LIST*>(buffer.get());

    pBssidList->uTotalNumOfEntries = wil::safe_cast<ULONG>(bssids.size());
    pBssidList->uNumOfEntries = wil::safe_cast<ULONG>(bssids.size());
    memcpy_s(pBssidList->BSSIDs, pBssidList->uNumOfEntries * sizeof(DOT11_MAC_ADDRESS), bssids.data(), bssids.size() * sizeof(DOT11_MAC_ADDRESS));

    return {pBssidList, std::move(buffer)};
}

DOT11_CIPHER_ALGORITHM CipherSuiteToWindowsEnum(CipherSuite cipherSuite)
{
    switch (cipherSuite)
    {
    case CipherSuite::Wep40:
        return DOT11_CIPHER_ALGO_WEP40;
    case CipherSuite::Tkip:
        return DOT11_CIPHER_ALGO_TKIP;
    case CipherSuite::Ccmp:
        return DOT11_CIPHER_ALGO_CCMP;
    case CipherSuite::Wep104:
        return DOT11_CIPHER_ALGO_WEP104;
    case CipherSuite::AesCmac:
        return DOT11_CIPHER_ALGO_BIP;
    case CipherSuite::Gcmp:
        return DOT11_CIPHER_ALGO_GCMP;
    case CipherSuite::Gcmp256:
        return DOT11_CIPHER_ALGO_GCMP_256;
    case CipherSuite::Ccmp256:
        return DOT11_CIPHER_ALGO_CCMP_256;
    case CipherSuite::BipGmac128:
        return DOT11_CIPHER_ALGO_BIP_GMAC_128;
    case CipherSuite::BipGmac256:
        return DOT11_CIPHER_ALGO_BIP_GMAC_256;
    case CipherSuite::BipCmac256:
        return DOT11_CIPHER_ALGO_BIP_CMAC_256;
    default:
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "Unknown cipher suite: %d", WI_EnumValue(cipherSuite));
    }
}

std::wstring AuthAlgoToString(DOT11_AUTH_ALGORITHM authAlgo) noexcept
{
    switch (authAlgo)
    {
    case DOT11_AUTH_ALGO_80211_OPEN:
        return L"OPEN";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
        return L"SHARED_KEY";
    case DOT11_AUTH_ALGO_WPA:
        return L"WPA";
    case DOT11_AUTH_ALGO_WPA_PSK:
        return L"WPA_PSK";
    case DOT11_AUTH_ALGO_WPA_NONE:
        return L"WPA_NONE";
    case DOT11_AUTH_ALGO_RSNA:
        return L"RSNA";
    case DOT11_AUTH_ALGO_RSNA_PSK:
        return L"RSNA_PSK";
    case DOT11_AUTH_ALGO_WPA3:
        return L"WPA3";
    case DOT11_AUTH_ALGO_WPA3_SAE:
        return L"WPA3_SAE";
    case DOT11_AUTH_ALGO_OWE:
        return L"OWE";
    default:
        return L"Unknown auth algo " + std::to_wstring(authAlgo);
    }
}

std::wstring CipherAlgoToString(DOT11_CIPHER_ALGORITHM cipher) noexcept
{
    switch (cipher)
    {
    case DOT11_CIPHER_ALGO_NONE:
        return L"NONE";
    case DOT11_CIPHER_ALGO_WEP40:
        return L"WEP40";
    case DOT11_CIPHER_ALGO_TKIP:
        return L"TKIP";
    case DOT11_CIPHER_ALGO_CCMP:
        return L"CCMP";
    case DOT11_CIPHER_ALGO_WEP104:
        return L"WEP104";
    case DOT11_CIPHER_ALGO_BIP:
        return L"BIP";
    case DOT11_CIPHER_ALGO_GCMP:
        return L"GCMP";
    case DOT11_CIPHER_ALGO_GCMP_256:
        return L"GCMP_256";
    case DOT11_CIPHER_ALGO_CCMP_256:
        return L"CCMP_256";
    case DOT11_CIPHER_ALGO_BIP_GMAC_128:
        return L"BIP_GMAC_128";
    case DOT11_CIPHER_ALGO_BIP_GMAC_256:
        return L"BIP_GMAC_256";
    case DOT11_CIPHER_ALGO_BIP_CMAC_256:
        return L"BIP_CMAC_256";
    default:
        return L"Unknown cipher algo " + std::to_wstring(cipher);
    }
}

std::wstring AuthAlgoToProfileString(DOT11_AUTH_ALGORITHM authAlgo)
{
    switch (authAlgo)
    {
    case DOT11_AUTH_ALGO_80211_OPEN:
        return L"open";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
        return L"shared";
    case DOT11_AUTH_ALGO_WPA_PSK:
        return L"WPAPSK";
    case DOT11_AUTH_ALGO_RSNA_PSK:
        return L"WPA2PSK";
    case DOT11_AUTH_ALGO_WPA3_SAE:
        return L"WPA3SAE";
    default:
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "Unsupported authentication algorithm %d", authAlgo);
    }
}

std::wstring CipherAlgoToProfileString(DOT11_CIPHER_ALGORITHM cipher)
{
    switch (cipher)
    {
    case DOT11_CIPHER_ALGO_NONE:
        return L"none";
    case DOT11_CIPHER_ALGO_WEP40:
        return L"WEP";
    case DOT11_CIPHER_ALGO_TKIP:
        return L"TKIP";
    case DOT11_CIPHER_ALGO_GCMP:
    case DOT11_CIPHER_ALGO_CCMP:
        return L"AES";
    default:
        THROW_WIN32_MSG(ERROR_INVALID_PARAMETER, "Unsupported cipher suite: %d", cipher);
    }
}

std::wstring ProfileNameFromSSID(const Ssid& ssid)
{
    constexpr auto c_defaultProfileName = L"ProxyWifi Network";

    std::array<wchar_t, WLAN_MAX_NAME_LENGTH> profileName{WLAN_MAX_NAME_LENGTH, L'\0'};
    const auto retValue = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(ssid.value().data()),
        ssid.size(),
        profileName.data(),
        wil::safe_cast<int>(profileName.size()));

    if (retValue > 0)
    {
        return std::wstring(profileName.begin(), profileName.begin() + retValue);
    }
    else
    {
        LOG_WIN32_MSG(GetLastError(), "Could not get a profile name from the SSID. Using default value.");
        return c_defaultProfileName;
    }
}

std::wstring MakeConnectionProfile(const Ssid& ssid, DOT11_AUTH_CIPHER_PAIR authCipher, const std::span<const uint8_t>& key)
{
    std::wostringstream profileXmlBuilder;
    profileXmlBuilder << L"<?xml version=\"1.0\"?>\r\n"
                         "<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\r\n"
                         "	<name>"
                      << ProfileNameFromSSID(ssid)
                      << "</name>\r\n"
                         "	<SSIDConfig>\r\n"
                         "		<SSID>\r\n"
                         "			<hex>";
    AppendByteBufferAsHexString(profileXmlBuilder, ssid.value());
    profileXmlBuilder << "</hex>\r\n"
                         "		</SSID>\r\n"
                         "	</SSIDConfig>\r\n"
                         "	<connectionType>ESS</connectionType>\r\n"
                         "	<connectionMode>manual</connectionMode>\r\n"
                         "	<MSM>\r\n"
                         "		<security>\r\n"
                         "			<authEncryption>\r\n"
                         "				<authentication>"
                      << Wlansvc::AuthAlgoToProfileString(authCipher.AuthAlgoId)
                      << "</authentication>\r\n"
                         "				<encryption>"
                      << Wlansvc::CipherAlgoToProfileString(authCipher.CipherAlgoId)
                      << "</encryption>\r\n"
                         "				<useOneX>false</useOneX>\r\n"
                         "			</authEncryption>\r\n";
    if (!key.empty())
    {
        profileXmlBuilder << "			<sharedKey>\r\n"
                             "				<keyType>networkKey</keyType>\r\n"
                             "               <protected>false</protected>\r\n"
                             "               <keyMaterial>";
        AppendByteBufferAsHexString(profileXmlBuilder, key);
        profileXmlBuilder << "</keyMaterial>\r\n"
                             "			</sharedKey>\r\n";
    }
    profileXmlBuilder << "		</security>\r\n"
                         "	</MSM>\r\n"
                         "</WLANProfile>\r\n";

    return profileXmlBuilder.str();
}

bool IsAuthCipherPairSupported(const std::pair<DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM>& authCipher)
{
    constexpr std::array supportedAuthCiphers = {
        std::make_pair(DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_NONE),
        std::make_pair(DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_CCMP),
        std::make_pair(DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_GCMP)};

    return std::ranges::find(supportedAuthCiphers, authCipher) != supportedAuthCiphers.cend();
}

namespace {
std::vector<DOT11_CIPHER_ALGORITHM> ConvertCipherSuites(std::span<const CipherSuite> ciphers)
{
    if (ciphers.empty())
    {
        return {DOT11_CIPHER_ALGO_NONE};
    }
    std::vector<DOT11_CIPHER_ALGORITHM> r;
    std::ranges::transform(ciphers, std::back_inserter(r), CipherSuiteToWindowsEnum);
    return r;
}

constexpr DOT11_AUTH_ALGORITHM DetermineAuth(AuthAlgo auth, uint8_t wpaVersion, std::span<const AkmSuite> akms)
{
    if (auth == AuthAlgo::OpenSystem)
    {
        if (wpaVersion == 0)
        {
            return DOT11_AUTH_ALGO_80211_OPEN;
        }
        else if (wpaVersion == 2)
        {
            constexpr std::array wpa2akms{AkmSuite::Psk, AkmSuite::PskSha256, AkmSuite::PskSha384, AkmSuite::FtPsk, AkmSuite::FtPskSha384};
            if (std::ranges::find_first_of(akms, wpa2akms) == akms.end())
            {
                throw std::invalid_argument("Unsupported authentication algorithm: Open/Wpa2, but no PSK AKM");
            }
            return DOT11_AUTH_ALGO_RSNA_PSK;
        }
        else
        {
            throw std::invalid_argument("Unsupported Open authentication algorithm");
        }
    }
    else if (auth == AuthAlgo::Sae)
    {
        if (std::ranges::find(akms, AkmSuite::Sae) == akms.end())
        {
            throw std::invalid_argument("Unsupported SAE authentication algorithm: No SAE AKM");
        }
        return DOT11_AUTH_ALGO_WPA3_SAE;
    }
    else
    {
        throw std::invalid_argument("Unsupported authentication algorithm: " + std::to_string(WI_EnumValue(auth)));
    }
}

} // namespace

DOT11_AUTH_CIPHER_PAIR DetermineAuthCipherPair(const WlanSecurity& secInfo)
{
    const auto auth = DetermineAuth(secInfo.auth, secInfo.wpaVersion, secInfo.akmSuites);

    const auto candidateCiphers = ConvertCipherSuites(secInfo.cipherSuites);
    for (auto cipher: candidateCiphers)
    {
        auto pair = std::make_pair(auth, cipher);
        if (IsAuthCipherPairSupported(pair))
        {
            return {pair.first, pair.second};
        }
    }
    throw std::invalid_argument("Could not find a supported auth/cipher pair");
}

} // namespace Wlansvc
} // namespace ProxyWifi