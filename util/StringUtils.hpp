// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <codecvt>
#include <iomanip>
#include <locale>
#include <string>
#include <gsl/span>
#include <sstream>

#include <Windows.h>
#include <wil/win32_helpers.h>

/// @brief Allow to convert a buffer of bytes as a string of hexadecimal two-digit values
/// @example [8, 10, 20] -> "080a14"
inline static void AppendByteBufferAsHexString(std::wostringstream& stream, const gsl::span<const uint8_t>& byteBuffer)
{
    stream << std::hex << std::setfill(L'0');
    for (const auto& byte : byteBuffer)
    {
        stream << std::setw(2) << byte;
    }
    stream << std::dec << std::setfill(L' ');
}

inline static std::wstring ByteBufferToHexString(const gsl::span<const uint8_t>& byteBuffer)
{
    std::wostringstream stream;
    AppendByteBufferAsHexString(stream, byteBuffer);
    return stream.str();
}

inline static std::vector<uint8_t> HexStringToByteBuffer(const std::wstring_view& s)
{
    // Need an even string size, since two digits = 1 byte (assume leading zeros)
    if (s.size() % 2 != 0)
    {
        throw std::invalid_argument("String size must be even");
    }

    std::vector<uint8_t> byteBuffer;
    for (auto i = 0u; i < s.size(); i += 2)
    {
        std::wstring t{s.substr(i, 2)};
        byteBuffer.push_back(static_cast<uint8_t>(std::stoul(t, nullptr, 16)));
    }
    return byteBuffer;
}

/// @brief Convert a GUID to a string
/// @example "{FEF2F808-F267-4728-A0C5-0A6240D01B33}"
inline static std::wstring GuidToString(const GUID& guid) noexcept
{
    wchar_t guidAsString[wil::guid_string_buffer_length];
    StringFromGUID2(guid, guidAsString, wil::guid_string_buffer_length);
    return guidAsString;
}

/// @brief Convert a bssid to a string, as hexadecimal
/// @example [216, 236, 94, 16, 126, 22] -> "d8:ec:5e:10:7e:16"
inline static std::wstring BssidToString(const gsl::span<const uint8_t, 6> bssid)
{
    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');

    stream << std::setw(2) << bssid.front();
    for (const auto& byte : bssid.subspan<1>())
    {
        stream << L':' << std::setw(2) << byte;
    }
    stream << std::dec << std::setfill(L' ');
    return stream.str();
}

/// @brief Convert a ssid to a string for *logging only*, with ASCII and hexadecimal representations
/// If the ssid isn't an ascii string, invalid character will be replaced by '?'
/// @example ['m', 'y', ' ', 'w', 'i', 'f', 'i'] -> "'my wifi' [226422226d792077696669]"
inline static std::wstring SsidToLogString(const gsl::span<const uint8_t> ssid)
{
    std::wostringstream stream;
    stream << L"'" << std::wstring{ssid.begin(), ssid.end()} << L"' [";
    for (const auto b : ssid)
    {
        stream << std::isprint(b) ? b : '?';
    }
    AppendByteBufferAsHexString(stream, ssid);
    stream << L"]";

    return stream.str();
}

template <class T, std::enable_if_t<std::is_enum_v<T>, int> = 1>
inline static std::wstring ListEnumToHexString(const gsl::span<T> list, std::wstring_view sep = L" ", int width = 8)
{
    if (list.empty())
    {
        return L"";
    }

    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');
    stream << std::setw(width) << WI_EnumValue(list.front());
    for (const auto& e : list.subspan<1>())
    {
        stream << sep << std::setw(width) << WI_EnumValue(e);
    }
    return stream.str();
}