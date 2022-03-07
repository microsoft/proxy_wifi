// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <catch2/catch.hpp>

#include "WlanSvcWrapper.hpp"
#include "OperationHandlerBuilder.hpp"

using namespace ProxyWifi;

TEST_CASE("Creating a WlanApiWrapper doesn't cause a crash", "[init]")
{
    // The operation can succeed or fail depending on whether wlanapi.dll is available on the SKU
    // But the executable must load and not crash
    try
    {
        auto _ = std::make_unique<Wlansvc::WlanApiWrapperImpl>();
    }
    catch (...)
    {
    }
}

TEST_CASE("WlanApiWrapper is optionnal to create an OperationHandler", "[init]")
{
    auto opHandler = MakeWlansvcOperationHandler(std::shared_ptr<Wlansvc::WlanApiWrapper>{}, {}, {});
    CHECK(opHandler);
}
