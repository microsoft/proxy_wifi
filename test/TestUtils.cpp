// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "catch2/catch.hpp"
#include "StringUtils.hpp"

// Tests for StringUtils.hpp

TEST_CASE("ByteBufferToHexString format correctly", "[stringUtils]")
{
    CHECK(ByteBufferToHexString(std::array<uint8_t, 3>{8, 10, 20}) == std::wstring(L"080a14"));
    CHECK(ByteBufferToHexString(std::array<uint8_t, 0>{}) == std::wstring());
}

TEST_CASE("HexStringToByteBuffer parse correctly", "[stringUtils]")
{
    CHECK(HexStringToByteBuffer(L"080a14") == std::vector<uint8_t>{8, 10, 20});
    CHECK(HexStringToByteBuffer(L"") == std::vector<uint8_t>{});
    CHECK_THROWS(HexStringToByteBuffer(L"080a1"));
}

TEST_CASE("GuidToString format correctly", "[stringUtils]")
{
    GUID guid{0xfef2f808, 0xf267, 0x4728, {0xa0, 0xc5, 0x0a, 0x62, 0x40, 0xd0, 0x1b, 0x33}};
    CHECK(GuidToString(guid) == std::wstring(L"{FEF2F808-F267-4728-A0C5-0A6240D01B33}"));
}

TEST_CASE("BssidToString format correctly", "[stringUtils]")
{
    CHECK(BssidToString(std::array<uint8_t, 6>{216, 236, 94, 16, 126, 22}) == std::wstring(L"d8:ec:5e:10:7e:16"));
    CHECK(BssidToString(std::array<uint8_t, 6>{0, 0, 1, 0, 0, 0}) == std::wstring(L"00:00:01:00:00:00"));
}

TEST_CASE("SsidToLogString format correctly", "[stringUtils]")
{
    CHECK(SsidToLogString(std::array<uint8_t, 7>{'m', 'y', ' ', 'w', 'i', 'f', 'i'}) == std::wstring(L"'my wifi' [226422226d792077696669]"));
    CHECK(SsidToLogString(std::array<uint8_t, 0>{}) == std::wstring(L"'' []"));
}

TEST_CASE("ListEnumToHexString format correctly", "[stringUtils]")
{
    enum class Breakfast : uint32_t
    {
        Croissant = 0xabc11100,
        Chocolatine = 0xdef22200,
        Coffee = 0xabcdef00
    };

    enum class Pizza
    {
        Cheese,
        Peperoni
    };

    CHECK(ListEnumToHexString(gsl::span{std::vector{Breakfast::Croissant, Breakfast::Chocolatine}}) == std::wstring(L"abc11100 def22200"));
    CHECK(ListEnumToHexString(gsl::span{std::vector{Breakfast::Coffee}}) == std::wstring(L"abcdef00"));
    CHECK(ListEnumToHexString(gsl::span{std::vector<Breakfast>{}}) == std::wstring(L""));

    CHECK(ListEnumToHexString(gsl::span{std::vector{Pizza::Cheese}}, L"-", 4) == std::wstring(L"0000"));
    CHECK(ListEnumToHexString(gsl::span{std::vector{Pizza::Peperoni, Pizza::Cheese}}, L"-", 4) == std::wstring(L"0001-0000"));
}
