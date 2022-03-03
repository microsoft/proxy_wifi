// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <memory>

#include <wil/result_macros.h>

#include "ProxyWifi/Logs.hpp"
#include "OperationHandler.hpp"
#include "ClientWlanInterface.hpp"
#include "RealWlanInterface.hpp"
#include "TestWlanInterface.hpp"
#include "WlansvcOperationHandler.hpp"

namespace ProxyWifi {

inline std::unique_ptr<OperationHandler> MakeWlansvcOperationHandler(std::shared_ptr<Wlansvc::WlanApiWrapper> wlansvc, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
{
    std::vector<std::unique_ptr<IWlanInterface>> wlanInterfaces;
    // Add an interface for user defined networks, if a callback is provided. Must be first to take priority over the other interfaces
    if (fakeNetworkCallback)
    {
        Log::Info(L"Adding client interface %ws", GuidToString(FakeInterfaceGuid).c_str());
        wlanInterfaces.push_back(std::make_unique<ClientWlanInterface>(FakeInterfaceGuid, std::move(fakeNetworkCallback)));
    }

    // Add the real wlan interfaces
    if (wlansvc)
    {
        const auto interfaces = wlansvc->EnumerateInterfaces();
        for (const auto& i : interfaces)
        {
            Log::Info(L"Adding interface %ws", GuidToString(i).c_str());
            try
            {
                wlanInterfaces.push_back(std::make_unique<RealWlanInterface>(wlansvc, i));
            }
            catch (...)
            {
                LOG_CAUGHT_EXCEPTION_MSG("Failed to initialize a wlansvc interface. Skipping it.");
            }
        }

        Log::Info(L"Creating a Wlansvc enabled operation handler");
        return std::make_unique<WlansvcOperationHandler>(pObserver, std::move(wlanInterfaces), wlansvc);
    }
    else
    {
        // Without wlansvc, we can't handle interfaces arrival/departures anyway, so an `OperationHandler` is enough
        Log::Info(L"Creating a client network only operation handler");
        return std::make_unique<OperationHandler>(pObserver, std::move(wlanInterfaces));
    }
}

inline std::unique_ptr<OperationHandler> MakeManualTestOperationHandler(FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
{
    std::vector<std::unique_ptr<IWlanInterface>> wlanInterfaces;
    // Add an interface for user defined networks if a callback is provided
    if (fakeNetworkCallback)
    {
        wlanInterfaces.push_back(std::make_unique<ClientWlanInterface>(FakeInterfaceGuid, std::move(fakeNetworkCallback)));
    }

    // Add a test interface simulating networks
    wlanInterfaces.push_back(
        std::make_unique<TestWlanInterface>(GUID{0xc386c570, 0xf576, 0x4f7e, {0xbf, 0x19, 0xd2, 0x32, 0x3a, 0xf8, 0xdd, 0x19}}));

    return std::make_unique<OperationHandler>(pObserver, std::move(wlanInterfaces));
}

} // namespace ProxyWifi