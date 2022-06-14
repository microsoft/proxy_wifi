// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// @brief Helper types to build messages

#pragma once

#include <array>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include <gsl/span>
#include <wil/safecast.h>

#include "Iee80211Utils.hpp"
#include "Networks.hpp"
#include "Protocol.hpp"
#include "StringUtils.hpp"

namespace ProxyWifi {

static constexpr std::array operation_names = {
    /* WIFI_INVALID                */ L"Invalid",
    /* WIFI_OP_SCAN_REQUEST        */ L"ScanRequest",
    /* WIFI_OP_SCAN_RESPONSE       */ L"ScanResponse",
    /* WIFI_OP_CONNECT_REQUEST     */ L"ConnectRequest",
    /* WIFI_OP_CONNECT_RESPONSE    */ L"ConnectResponse",
    /* WIFI_OP_DISCONNECT_REQUEST  */ L"DisconnectRequest",
    /* WIFI_OP_DISCONNECT_RESPONSE */ L"DisconnectResponse",
    /* WIFI_NOTIF_DISCONNECTED     */ L"EventDisconnected",
    /* WIFI_NOTIF_SIGNAL_QUALITY   */ L"EventSignalQuality"};

static_assert(operation_names.size() == WIFI_OP_MAX);

constexpr const wchar_t* GetProtocolMessageTypeName(uint8_t operation) noexcept
{
    return (operation < WIFI_OP_MAX) ? operation_names[operation] : L"Invalid";
}

/// @brief Helper to manipulate full messages (header + body)
struct Message
{
    Message() = default;

    Message(proxy_wifi_operation op, std::vector<uint8_t> buffer)
        : hdr{op, wil::safe_cast<uint32_t>(buffer.size()), proxy_wifi_version::VERSION_0_1}, body{std::move(buffer)}
    {
    }

    struct proxy_wifi_hdr hdr{};
    std::vector<uint8_t> body;
};

/// @brief Return the size of a message.
/// Should be specialized for messages which size is larger than the size of the
/// type representing it (VLA, data happened to the message itself...).
template <class T>
inline uint32_t size(const T& msg)
{
    return wil::safe_cast<uint32_t>(sizeof(msg));
}

template <>
inline uint32_t size<proxy_wifi_disconnect_response>(const proxy_wifi_disconnect_response&)
{
    // sizeof = 1 for an empty struct
    return 0;
}

template <>
inline uint32_t size<proxy_wifi_scan_response>(const proxy_wifi_scan_response& msg)
{
    return msg.total_size;
}

template <>
inline uint32_t size<proxy_wifi_connect_request>(const proxy_wifi_connect_request& msg)
{
    return sizeof(proxy_wifi_connect_request) + msg.key_len;
}

/// @brief Handle a buffer of bytes and allow to view it as a message body of the specified type
template<class T, proxy_wifi_operation Operation>
class StructuredBuffer
{
    using MsgType = T;

public:
    StructuredBuffer()
        : m_buffer(sizeof(MsgType))
    {
    }

    explicit StructuredBuffer(size_t allocSize)
        : m_buffer(std::max(allocSize, sizeof(MsgType)))
    {
    }

    StructuredBuffer(std::vector<uint8_t> buffer)
        : m_buffer{std::move(buffer)}
    {
        if (m_buffer.size() < sizeof(MsgType))
        {
            throw std::invalid_argument(
                "Message too small: " + std::to_string(buffer.size()) + "bytes but " + std::to_string(sizeof(MsgType)) +
                "at least bytes expected");
        }

        // `size()` might access the fixed data to get the size of variable length data, so a check with `sizeof` must
        // be done first
        if (m_buffer.size() != size(*get()))
        {
            throw std::invalid_argument(
                "Unexpected message size:" + std::to_string(buffer.size()) + "bytes but " + std::to_string(size(*get())) +
                "bytes expected");
        }
    }

    MsgType* get()
    {
        return reinterpret_cast<MsgType*>(m_buffer.data());
    }

    MsgType* operator*()
    {
        return get();
    }

    MsgType* operator->()
    {
        return get();
    }

    const MsgType* get() const
    {
        return reinterpret_cast<const MsgType*>(m_buffer.data());
    }

    const MsgType* operator*() const
    {
        return get();
    }

    const MsgType* operator->() const
    {
        return get();
    }

    gsl::span<uint8_t> AsBytes()
    {
        return gsl::span{m_buffer};
    }

    static Message ToMessage(StructuredBuffer&& buffer)
    {
        // Get the size before moving the buffer, or it may get invalidated
        return Message(Operation, std::move(buffer.m_buffer));
    }

    std::wstring Describe() const
    {
        return GetProtocolMessageTypeName(Operation);
    }

private:
    std::vector<uint8_t> m_buffer;
};

class ConnectRequest: public StructuredBuffer<proxy_wifi_connect_request, WIFI_OP_CONNECT_REQUEST>
{
public:
    ConnectRequest(std::vector<uint8_t> buffer)
        : StructuredBuffer{std::move(buffer)}
    {
    }

    std::wstring Describe() const
    {
        std::wostringstream stream;
        stream << L"Connect request, Ssid: "
               << SsidToLogString({get()->ssid, std::min(c_wlan_max_ssid_len, wil::safe_cast<size_t>(get()->ssid_len))});
        stream << L", Bssid: " << BssidToString(get()->bssid);
        stream << L", Auth: " << get()->auth_type;
        stream << L", WPA version: " << get()->wpa_versions;

        stream << std::hex << std::setfill(L'0');
        stream << L", AKM Suites: {";
        for (const auto& akm :
             wil::make_range(get()->akm_suites, std::min(wil::safe_cast<size_t>(get()->num_akm_suites), c_wlan_max_akm_suites)))
        {
            stream << L" 0x" << std::setw(8) << akm;
        }
        stream << L" }, Pairwise Cipher Suites: {";
        for (const auto& cipher : wil::make_range(
                 get()->pairwise_cipher_suites,
                 std::min(wil::safe_cast<size_t>(get()->num_pairwise_cipher_suites), c_wlan_max_pairwise_cipher_suites)))
        {
            stream << L" 0x" << std::setw(8) << cipher;
        }
        stream << L" }, Group Cipher Suite: 0x" << std::setw(8) << get()->group_cipher_suite;
        stream << std::dec << std::setfill(L' ');

        stream << L", Key present: " + (get()->key_len > 0 ? std::wstring(L"True") : std::wstring(L"False"));
        return stream.str();
    }
};

class ConnectResponse: public StructuredBuffer<proxy_wifi_connect_response, WIFI_OP_CONNECT_RESPONSE>
{
public:
    ConnectResponse(WlanStatus resultCode, gsl::span<const uint8_t, c_wlan_bssid_len> bssid, uint64_t sessionId)
    {
        get()->result_code = WI_EnumValue(resultCode);
        memcpy_s(get()->bssid, sizeof get()->bssid, bssid.data(), bssid.size());
        get()->session_id = sessionId;
    }

    std::wstring Describe() const
    {
        return L"Connect response, Result code: " + std::to_wstring(get()->result_code) + L", Session id: " +
               std::to_wstring(get()->session_id) + L", BssId: " + BssidToString(get()->bssid);
    }
};

class DisconnectRequest: public StructuredBuffer<proxy_wifi_disconnect_request, WIFI_OP_DISCONNECT_REQUEST>
{
public:
    DisconnectRequest(std::vector<uint8_t> buffer)
        : StructuredBuffer{std::move(buffer)}
    {
    }

    std::wstring Describe() const
    {
        return L"Disconnect request, Session id: " + std::to_wstring(get()->session_id);
    }
};

class DisconnectResponse: public StructuredBuffer<proxy_wifi_disconnect_response, WIFI_OP_DISCONNECT_RESPONSE>
{
};

class ScanRequest : public StructuredBuffer<proxy_wifi_scan_request, WIFI_OP_SCAN_REQUEST>
{
public:
    ScanRequest(std::vector<uint8_t> buffer)
        : StructuredBuffer{std::move(buffer)}
    {
    }

    std::wstring Describe() const
    {
        return L"Scan request, Target ssid: " +
               (get()->ssid_len == 0
                    ? L"*"
                    : SsidToLogString({get()->ssid, std::min(c_wlan_max_ssid_len, wil::safe_cast<size_t>(get()->ssid_len))}));
    }
};

class ScanResponse : public StructuredBuffer<proxy_wifi_scan_response, WIFI_OP_SCAN_RESPONSE>
{
public:
    ScanResponse(size_t totalSize, size_t numBss, bool scanComplete)
        : StructuredBuffer{totalSize},
          m_ies{AsBytes().subspan(sizeof(proxy_wifi_scan_response) + numBss * sizeof(proxy_wifi_bss))}
    {
        get()->total_size = wil::safe_cast<uint32_t>(totalSize);
        get()->num_bss = wil::safe_cast<uint32_t>(numBss);
        get()->scan_complete = scanComplete;
    }

    gsl::span<uint8_t> getIes() const
    {
        return m_ies;
    }

    std::wstring Describe() const
    {
        return L"Scan response, Scan complete: " + std::wstring(get()->scan_complete ? L"true" : L"false") +
               L", Number of reported Bss: " + std::to_wstring(get()->num_bss) + L", Total size " +
               std::to_wstring(get()->total_size) + L" bytes";
    }

private:
    gsl::span<uint8_t> m_ies;
};

/// @brief Builder class to create a scan response
///
/// Since all information elements are appended at the end of the message and are accessed through offsets,
/// it is necessary to collect all the results first to allocate and build the response message.
class ScanResponseBuilder
{
public:
    void AddBss(ScannedBss bss);
    ScanResponse Build() const;
    void SetScanComplete(bool isComplete) noexcept;

private:
    bool IsBssAlreadyPresent(const Bssid& bssid);
    bool m_scanComplete = false;
    std::vector<ScannedBss> m_bssList;
};

class DisconnectNotif: public StructuredBuffer<proxy_wifi_disconnect_notif, WIFI_NOTIF_DISCONNECTED>
{
public:
    explicit DisconnectNotif(uint64_t sessionId)
    {
        get()->session_id = sessionId;
    }

    std::wstring Describe() const
    {
        return L"Disconnect notification, Session id: " + std::to_wstring(get()->session_id);
    }
};

class SignalQualityNotif: public StructuredBuffer<proxy_wifi_signal_quality_notif, WIFI_NOTIF_SIGNAL_QUALITY>
{
public:
    explicit SignalQualityNotif(int8_t signal)
    {
        get()->signal = signal;
    }

    std::wstring Describe() const
    {
        return L"Signal quality notification, Signal: " + std::to_wstring(get()->signal);
    }
};

} // namespace ProxyWifi