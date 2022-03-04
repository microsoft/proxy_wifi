// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <windows.h>
#include <wlanapi.h>
#include <wil/resource.h>

#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "DynamicFunction.hpp"
#include "GuidUtils.hpp"
#include "Networks.hpp"

namespace ProxyWifi::Wlansvc {

/// @brief Wrapper around the Wlansvc API
/// Expose the parts of the Wlansvc API used by the lib in a more C++ compatible way and facilitate unit-testing
class WlanApiWrapper
{
public:
    virtual ~WlanApiWrapper() = default;

    /// @brief Provide the GUIDS of all station interfaces on the system
    virtual std::vector<GUID> EnumerateInterfaces() = 0;

    /// @brief Allow a client to subscribe to notification for a specific interface
    /// Use the null guid to receive all notifications
    virtual void Subscribe(const GUID& interfaceGuid, std::function<void(const WLAN_NOTIFICATION_DATA&)> callback) = 0;

    /// @brief Allow a client to unsubscribe to notification for a specific interface
    virtual void Unsubscribe(const GUID& interfaceGuid) = 0;

    /// @brief Provide information about the currently connected network on `interfaceGuid`
    virtual WLAN_CONNECTION_ATTRIBUTES GetCurrentConnection(const GUID& interfaceGuid) = 0;

    /// @brief Connect to a wlan network using a temporary profile
    virtual void Connect(const GUID& interfaceGuid, const std::wstring& profile, const DOT11_MAC_ADDRESS& bssid) = 0;

    /// @brief Disconnect the interface
    virtual void Disconnect(const GUID& interfaceGuid) = 0;

    /// @brief Schedule a scan on the interface
    /// @param ssid If non-null, a targeted scan will be done on this ssid (for hiden networks)
    virtual void Scan(const GUID& interfaceGuid, DOT11_SSID* ssid = nullptr) = 0;

    /// @brief Provide the list of scanned BSS
    /// It is flushed when a scan is scheduled and will be empty until a scan succeeds
    virtual std::vector<ScannedBss> GetScannedBssList(const GUID& interfaceGuid) = 0;

    /// @brief Provide the list of scanned networks
    /// It is flushed when a scan is scheduled and will be empty until a scan succeeds
    virtual std::vector<WLAN_AVAILABLE_NETWORK> GetScannedNetworkList(const GUID& interfaceGuid) = 0;
};

/// @brief Implementation of WlanApiWrapper targetting the real Windows Wlan API
class WlanApiWrapperImpl : public WlanApiWrapper
{
public:
    WlanApiWrapperImpl();
    ~WlanApiWrapperImpl() override;

    std::vector<GUID> EnumerateInterfaces() override;
    void Subscribe(const GUID& interfaceGuid, std::function<void(const WLAN_NOTIFICATION_DATA&)> callback) override;
    void Unsubscribe(const GUID& interfaceGuid) override;
    WLAN_CONNECTION_ATTRIBUTES GetCurrentConnection(const GUID& interfaceGuid) override;
    void Connect(const GUID& interfaceGuid, const std::wstring& profile, const DOT11_MAC_ADDRESS& bssid) override;
    void Disconnect(const GUID& interfaceGuid) override;
    void Scan(const GUID& interfaceGuid, DOT11_SSID* ssid = nullptr) override;
    std::vector<ScannedBss> GetScannedBssList(const GUID& interfaceGuid) override;
    std::vector<WLAN_AVAILABLE_NETWORK> GetScannedNetworkList(const GUID& interfaceGuid) override;

private:

    static void OnWlansvcEventCallback(PWLAN_NOTIFICATION_DATA pNotification, void* pContext) noexcept;
    void HandleWlansvcNotification(PWLAN_NOTIFICATION_DATA pNotification);

private:

    HANDLE m_wlanHandle;
    wil::srwlock m_callbacksLock;
    std::unordered_map<GUID, std::function<void(const WLAN_NOTIFICATION_DATA&)>> m_callbacks;

    struct WlanApiDynFunctions
    {
        DynamicFunction<decltype(::WlanCloseHandle)> WlanCloseHandle{L"wlanApi.dll", "WlanCloseHandle"};
        DynamicFunction<decltype(::WlanConnect)> WlanConnect{L"wlanApi.dll", "WlanConnect"};
        DynamicFunction<decltype(::WlanDisconnect)> WlanDisconnect{L"wlanApi.dll", "WlanDisconnect"};
        DynamicFunction<decltype(::WlanEnumInterfaces)> WlanEnumInterfaces{L"wlanApi.dll", "WlanEnumInterfaces"};
        DynamicFunction<decltype(::WlanFreeMemory)> WlanFreeMemory{L"wlanApi.dll", "WlanFreeMemory"};
        DynamicFunction<decltype(::WlanGetAvailableNetworkList)> WlanGetAvailableNetworkList{L"wlanApi.dll", "WlanGetAvailableNetworkList"};
        DynamicFunction<decltype(::WlanGetNetworkBssList)> WlanGetNetworkBssList{L"wlanApi.dll", "WlanGetNetworkBssList"};
        DynamicFunction<decltype(::WlanOpenHandle)> WlanOpenHandle{L"wlanApi.dll", "WlanOpenHandle"};
        DynamicFunction<decltype(::WlanQueryInterface)> WlanQueryInterface{L"wlanApi.dll", "WlanQueryInterface"};
        DynamicFunction<decltype(::WlanRegisterNotification)> WlanRegisterNotification{L"wlanApi.dll", "WlanRegisterNotification"};
        DynamicFunction<decltype(::WlanScan)> WlanScan{L"wlanApi.dll", "WlanScan"};
    };
    WlanApiDynFunctions m_wlanApi{};
};

} // namespace ProxyWifi::Wlansvc