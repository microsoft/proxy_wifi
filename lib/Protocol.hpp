// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// @brief Defines the types used in messages exchanged with the virt_wifi driver
/// Types defined here **must** have the same binary layout as their counterpart in the driver
///
/// # Protocol
///
/// ## Message structure
/// Each message is composed of a header `proxy_wifi_hdr` followed by a body.
/// The operation code in the header indicate the type of the body, and its size
/// must match the size indicated in the header.
///
/// ## Message categories
///
/// ### Request / Response
/// Requests are messages sent by the guest to the host. Each request must be followed by a
/// response from the host to the guest, whether it has been handled successfuly or not.
/// The guest should wait for this response before sending another request.
///
/// ### Notification
/// Notifications are messages sent spontaneously by the host to the guest.
/// No response is expected after a notification.

#pragma once

#include "Iee80211Utils.hpp"

namespace ProxyWifi {

static constexpr size_t c_wlan_max_akm_suites = 2;
static constexpr size_t c_wlan_max_pairwise_cipher_suites = 5;

#pragma pack(push, 1)

enum proxy_wifi_operation : uint8_t
{
    WIFI_INVALID = 0,
    WIFI_OP_SCAN_REQUEST,
    WIFI_OP_SCAN_RESPONSE,
    WIFI_OP_CONNECT_REQUEST,
    WIFI_OP_CONNECT_RESPONSE,
    WIFI_OP_DISCONNECT_REQUEST,
    WIFI_OP_DISCONNECT_RESPONSE,
    WIFI_NOTIF_DISCONNECTED,
    WIFI_NOTIF_SIGNAL_QUALITY,
    WIFI_OP_MAX
};

enum proxy_wifi_version : uint16_t
{
    VERSION_0_1 = 0x0001
};

struct proxy_wifi_hdr
{
    proxy_wifi_operation operation;
    uint32_t size;
    proxy_wifi_version version;
};

struct proxy_wifi_scan_request
{
    uint8_t ssid_len;
    uint8_t ssid[c_wlan_max_ssid_len];
};

struct proxy_wifi_bss
{
    uint8_t bssid[c_wlan_bssid_len];
    uint16_t capabilities;
    int32_t rssi;
    uint16_t beacon_interval;
    uint32_t channel_center_freq;
    uint32_t ie_size;
    uint32_t ie_offset;
};

/// @brief A list of bss information
///
/// The information elements for each BSS are appended to the structure (allocated in the same memory block)
/// and can be accessed using the `ie_offset` and `ie_size` field of the `proxy_wifi_bss` structure.
/// | num_bss | total_size | bss 1 | ... | bss n | ie bss 1 | ... | ie bss n |
#pragma warning(disable : 4200)
struct proxy_wifi_scan_response
{
    uint8_t scan_complete;
    uint32_t num_bss;
    uint32_t total_size;
    proxy_wifi_bss bss[];
};

#pragma warning(disable : 4200)
struct proxy_wifi_connect_request
{
    uint8_t ssid_len;
    uint8_t ssid[c_wlan_max_ssid_len];
    uint8_t bssid[c_wlan_bssid_len];
    uint8_t auth_type;
    uint8_t wpa_versions;
    uint8_t num_akm_suites;
    uint32_t akm_suites[c_wlan_max_akm_suites];
    uint8_t num_pairwise_cipher_suites;
    uint32_t pairwise_cipher_suites[c_wlan_max_pairwise_cipher_suites];
    uint32_t group_cipher_suite;
    uint8_t key_len;
    uint8_t key[];
};

struct proxy_wifi_connect_response
{
    uint16_t result_code;
    uint8_t bssid[c_wlan_bssid_len];
    uint64_t session_id;
};

struct proxy_wifi_disconnect_request
{
    uint64_t session_id;
};

struct proxy_wifi_disconnect_response
{
};

struct proxy_wifi_disconnect_notif
{
    uint64_t session_id;
};

struct proxy_wifi_signal_quality_notif
{
    int8_t signal;
};

#pragma pack(pop)

} // namespace ProxyWifi