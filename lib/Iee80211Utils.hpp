// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <Windows.h>
#include <wlanapi.h>
#include <wil/common.h>
#include <gsl/span>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/// @brief Defines 802.11 enums and types

namespace ProxyWifi {

static constexpr size_t c_wlan_max_ssid_len = DOT11_SSID_MAX_LENGTH;
static constexpr size_t c_wlan_bssid_len = sizeof(DOT11_MAC_ADDRESS);

enum class AuthAlgo : uint8_t
{
    OpenSystem,
    SharedKey,
    Ft,
    NetworkEap,
    Sae,
    FilsSk,
    FilsSkPfs,
    FilsPk,
};

inline constexpr uint32_t suite(uint32_t oui, uint8_t id)
{
    return (oui << 8) | id;
}

enum class AkmSuite : uint32_t
{
    OneX = suite(0x000FAC, 1),
    Psk = suite(0x000FAC, 2),
    Ft8021x = suite(0x000FAC, 3),
    FtPsk = suite(0x000FAC, 4),
    OneXSha256 = suite(0x000FAC, 5),
    PskSha256 = suite(0x000FAC, 6),
    Tdls = suite(0x000FAC, 7),
    Sae = suite(0x000FAC, 8),
    FtOverSae = suite(0x000FAC, 9),
    ApPeerKey = suite(0x000FAC, 10),
    OneXSuiteB = suite(0x000FAC, 11),
    OneXSuiteB192 = suite(0x000FAC, 12),
    Ft8021xSha384 = suite(0x000FAC, 13),
    FilsSha256 = suite(0x000FAC, 14),
    FilsSha384 = suite(0x000FAC, 15),
    FtFilsSha256 = suite(0x000FAC, 16),
    FtFilsSha384 = suite(0x000FAC, 17),
    Owe = suite(0x000FAC, 18),
    FtPskSha384 = suite(0x000FAC, 19),
    PskSha384 = suite(0x000FAC, 20)
};

enum class CipherSuite : uint32_t
{
    Wep40 = suite(0x000FAC, 1),
    Tkip = suite(0x000FAC, 2),
    // Reserved: 3
    Ccmp = suite(0x000FAC, 4),
    Wep104 = suite(0x000FAC, 5),
    AesCmac = suite(0x000FAC, 6),
    Gcmp = suite(0x000FAC, 8),
    Gcmp256 = suite(0x000FAC, 9),
    Ccmp256 = suite(0x000FAC, 10),
    BipGmac128 = suite(0x000FAC, 11),
    BipGmac256 = suite(0x000FAC, 12),
    BipCmac256 = suite(0x000FAC, 13)
};

/// @brief 802.11 IE ids
///
/// Incomplete, value can be added as needed
enum class ElementId : uint8_t
{
    Ssid = 0,
    Rsn = 48
};

enum class BssCapability : uint16_t
{
    Ess = 1 << 0,
    Ibss = 1 << 1,
    CfPollable = 1 << 2,
    CfPollRequest = 1 << 3,
    Privacy = 1 << 4,
    ShortPreamble = 1 << 5,
    Pbcc = 1 << 6,
    ChannelAgility = 1 << 7,
    SpectrumMgmt = 1 << 8,
    Qos = 1 << 9,
    ShortSlotTime = 1 << 10,
    Apsd = 1 << 11,
    RadioMeasure = 1 << 12,
    DsssOfdm = 1 << 13,
    DelBack = 1 << 14,
    ImmBack = 1 << 15,
};
DEFINE_ENUM_FLAG_OPERATORS(BssCapability);

/// @brief The 80211 status codes
enum class WlanStatus : uint16_t
{
    Success = 0,
    UnspecifiedFailure = 1,
    CapsUnsupported = 10,
    ReassocNoAssoc = 11,
    AssocDeniedUnspec = 12,
    NotSupportedAuthAlg = 13,
    UnknownAuthTransaction = 14,
    ChallengeFail = 15,
    AuthTimeout = 16,
    ApUnableToHandleNewSta = 17,
    AssocDeniedRates = 18,
    /* 802.11b */
    AssocDeniedNoshortpreamble = 19,
    AssocDeniedNopbcc = 20,
    AssocDeniedNoagility = 21,
    /* 802.11h */
    AssocDeniedNospectrum = 22,
    AssocRejectedBadPower = 23,
    AssocRejectedBadSuppChan = 24,
    /* 802.11g */
    AssocDeniedNoshorttime = 25,
    AssocDeniedNodsssofdm = 26,
    /* 802.11w */
    AssocRejectedTemporarily = 30,
    RobustMgmtFramePolicyViolation = 31,
    /* 802.11i */
    InvalidIe = 40,
    InvalidGroupCipher = 41,
    InvalidPairwiseCipher = 42,
    InvalidAkmp = 43,
    UnsuppRsnVersion = 44,
    InvalidRsnIeCap = 45,
    CipherSuiteRejected = 46,
    /* 802.11e */
    UnspecifiedQos = 32,
    AssocDeniedNobandwidth = 33,
    AssocDeniedLowack = 34,
    AssocDeniedUnsuppQos = 35,
    RequestDeclined = 37,
    InvalidQosParam = 38,
    ChangeTspec = 39,
    WaitTsDelay = 47,
    NoDirectLink = 48,
    StaNotPresent = 49,
    StaNotQsta = 50,
    /* 802.11s */
    AntiClogRequired = 76,
    FcgNotSupp = 78,
    StaNoTbtt = 78,
    /* 802.11ad */
    RejectedWithSuggestedChanges = 39,
    RejectedForDelayPeriod = 47,
    RejectWithSchedule = 83,
    PendingAdmittingFstSession = 86,
    PerformingFstNow = 87,
    PendingGapInBaWindow = 88,
    RejectUPidSetting = 89,
    RejectDseBand = 96,
    DeniedWithSuggestedBandAndChannel = 99,
    DeniedDueToSpectrumManagement = 103,
    /* 802.11ai */
    FilsAuthenticationFailure = 108,
    UnknownAuthenticationServer = 109,
    SaeHashToElement = 126,
    SaePk = 127,
};

class Ssid {

public:
    Ssid() = default;

    Ssid(DOT11_SSID rhs) :
        m_ssid{rhs.ucSSID, rhs.ucSSID + rhs.uSSIDLength}
    {
    }

    Ssid(const gsl::span<const uint8_t> rhs) :
        m_ssid{rhs.begin(), rhs.end()}
    {
        if (rhs.size() > c_wlan_max_ssid_len)
        {
            throw std::invalid_argument("Ssid too long: " + std::to_string(rhs.size()));
        }
    }

    Ssid(const std::string_view rhs) :
        m_ssid{rhs.begin(), rhs.end()}
    {
        if (rhs.size() > c_wlan_max_ssid_len)
        {
            throw std::invalid_argument("Ssid too long: " + std::to_string(rhs.size()));
        }
    }

    operator DOT11_SSID() const noexcept
    {
        DOT11_SSID r;
        r.uSSIDLength = size();
        std::copy_n(m_ssid.data(), m_ssid.size(), r.ucSSID);
        return r;
    }

    friend bool operator==(const Ssid& lhs, const Ssid& rhs) noexcept
    {
        return lhs.m_ssid == rhs.m_ssid;
    }

    friend bool operator!=(const Ssid& lhs, const Ssid& rhs) noexcept
    {
        return !(lhs == rhs);
    }

    friend bool operator==(const Ssid& lhs, const DOT11_SSID& rhs) noexcept
    {
        return lhs.m_ssid.size() == rhs.uSSIDLength && std::equal(lhs.m_ssid.begin(), lhs.m_ssid.end(), rhs.ucSSID);
    }

    friend bool operator==(const DOT11_SSID& lhs, const Ssid& rhs) noexcept
    {
        return rhs == lhs;
    }

    friend bool operator!=(const Ssid& lhs, const DOT11_SSID& rhs) noexcept
    {
        return !(lhs == rhs);
    }

    friend bool operator!=(const DOT11_SSID& lhs, const Ssid& rhs) noexcept
    {
        return !(lhs == rhs);
    }

    const std::vector<uint8_t>& value() const noexcept
    {
        return m_ssid;
    }

    uint8_t size() const noexcept
    {
        // `m_ssid.size()` <= c_max_ssid_length = 32 as a class invariant
        return static_cast<uint8_t>(m_ssid.size());
    }

private:
    std::vector<uint8_t> m_ssid;
};

using Bssid = std::array<uint8_t, c_wlan_bssid_len>;

inline Bssid toBssid(const uint8_t bssid[c_wlan_bssid_len])
{
    Bssid r;
    std::copy_n(bssid, c_wlan_bssid_len, r.begin());
    return r;
}

struct WlanSecurity
{
    AuthAlgo auth;
    uint8_t wpaVersion;
    std::vector<AkmSuite> akmSuites;
    std::vector<CipherSuite> cipherSuites;
    CipherSuite groupCipher;
    std::vector<uint8_t> key;
};

} // namespace ProxyWifi