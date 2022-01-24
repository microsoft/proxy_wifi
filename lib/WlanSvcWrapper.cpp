// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "WlanSvcWrapper.hpp"

#include "LogsHelpers.hpp"
#include "StringUtils.hpp"
#include "WlanSvcHelpers.hpp"

#include <wil/result_macros.h>
#include <wil/safecast.h>

#include <algorithm>
#include <iterator>

namespace ProxyWifi::Wlansvc {

WlanApiWrapperImpl::WlanApiWrapperImpl()
{
    DWORD negotiatedVersion = 0;
    THROW_IF_WIN32_ERROR(WlanOpenHandle(WLAN_API_VERSION_2_0, nullptr, &negotiatedVersion, &m_wlanHandle));
    THROW_IF_WIN32_ERROR(WlanRegisterNotification(
        m_wlanHandle.get(), WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM, true, OnWlansvcEventCallback, this, nullptr, nullptr));
}

WlanApiWrapperImpl::~WlanApiWrapperImpl()
{
    // Best effort to unregister, wlansvc will do it when the handle is closed otherwise
    LOG_IF_WIN32_ERROR(WlanRegisterNotification(m_wlanHandle.get(), WLAN_NOTIFICATION_SOURCE_NONE, true, nullptr, nullptr, nullptr, nullptr));
}

void WlanApiWrapperImpl::OnWlansvcEventCallback(PWLAN_NOTIFICATION_DATA pNotification, void* pContext) noexcept
try
{
    SetThreadWilFailureLogger();
    THROW_IF_NULL_ALLOC(pContext);
    auto& wlansvc = *reinterpret_cast<WlanApiWrapperImpl*>(pContext);
    wlansvc.HandleWlansvcNotification(pNotification);
}
CATCH_LOG()

void WlanApiWrapperImpl::HandleWlansvcNotification(PWLAN_NOTIFICATION_DATA pNotification)
{
    Log::Debug(
        L"Receving Wlansvc notification %hs on interface %ws",
        Wlansvc::GetWlanNotificationCodeString(*pNotification).c_str(),
        GuidToString(pNotification->InterfaceGuid).c_str());

    auto lock = m_callbacksLock.lock_shared();
    const auto callback = m_callbacks.find(pNotification->InterfaceGuid);
    if (callback != m_callbacks.end())
    {
        callback->second(*pNotification);
    }

    // The callback on the null GUID receive all notifications
    const auto allIntfCallback = m_callbacks.find(GUID{});
    if (allIntfCallback != m_callbacks.end())
    {
        allIntfCallback->second(*pNotification);
    }
}

void WlanApiWrapperImpl::Subscribe(const GUID& interfaceGuid, std::function<void(const WLAN_NOTIFICATION_DATA&)> callback)
{
    auto lock = m_callbacksLock.lock_exclusive();
    m_callbacks[interfaceGuid] = callback;
}

void WlanApiWrapperImpl::Unsubscribe(const GUID& interfaceGuid)
{
    auto lock = m_callbacksLock.lock_exclusive();
    m_callbacks.erase(interfaceGuid);
}

std::vector<GUID> WlanApiWrapperImpl::EnumerateInterfaces()
{
    wil::unique_wlan_ptr<WLAN_INTERFACE_INFO_LIST> interfaces;
    THROW_IF_WIN32_ERROR(WlanEnumInterfaces(m_wlanHandle.get(), nullptr, wil::out_param(interfaces)));

    if (!interfaces || interfaces->dwNumberOfItems == 0)
    {
        return {};
    }

    std::vector<GUID> result;
    std::transform(interfaces->InterfaceInfo, interfaces->InterfaceInfo + interfaces->dwNumberOfItems, std::back_inserter(result), [](const auto& i) {
        return i.InterfaceGuid;
    });
    return result;
}

WLAN_CONNECTION_ATTRIBUTES WlanApiWrapperImpl::GetCurrentConnection(const GUID& interfaceGuid)
{
    DWORD dataSize = 0;
    wil::unique_wlan_ptr<WLAN_CONNECTION_ATTRIBUTES> currentConnection;
    THROW_IF_WIN32_ERROR(WlanQueryInterface(
        m_wlanHandle.get(), &interfaceGuid, wlan_intf_opcode_current_connection, nullptr, &dataSize, wil::out_param_ptr<void**>(currentConnection), nullptr));
    THROW_IF_NULL_ALLOC(currentConnection);
    return *currentConnection;
}

void WlanApiWrapperImpl::Connect(const GUID& interfaceGuid, const std::wstring& profile, const DOT11_MAC_ADDRESS& bssid)
{
    WLAN_CONNECTION_PARAMETERS connectionParameters{};
    connectionParameters.wlanConnectionMode = wlan_connection_mode_temporary_profile;
    connectionParameters.strProfile = profile.data();
    connectionParameters.pDot11Ssid = nullptr;
    connectionParameters.dot11BssType = dot11_BSS_type_infrastructure;

    // Set the requested BSSID if present in the request
    std::unique_ptr<uint8_t[]> bssidListBuffer;
    if (!Wlansvc::IsNullBssid(bssid))
    {
        std::tie(connectionParameters.pDesiredBssidList, bssidListBuffer) = Wlansvc::BuildBssidList({&bssid, 1});
    }

    THROW_IF_WIN32_ERROR(WlanConnect(m_wlanHandle.get(), &interfaceGuid, &connectionParameters, nullptr));
}

void WlanApiWrapperImpl::Disconnect(const GUID& interfaceGuid)
{
    THROW_IF_WIN32_ERROR(WlanDisconnect(m_wlanHandle.get(), &interfaceGuid, nullptr));
}

void WlanApiWrapperImpl::Scan(const GUID& interfaceGuid, DOT11_SSID* ssid)
{
    THROW_IF_WIN32_ERROR(WlanScan(m_wlanHandle.get(), &interfaceGuid, ssid, nullptr, nullptr));
}

std::vector<ScannedBss> WlanApiWrapperImpl::GetScannedBssList(const GUID& interfaceGuid)
{
    wil::unique_wlan_ptr<WLAN_BSS_LIST> bssList;
    THROW_IF_WIN32_ERROR(WlanGetNetworkBssList(
        m_wlanHandle.get(), &interfaceGuid, nullptr, dot11_BSS_type_infrastructure, false, nullptr, wil::out_param(bssList)));

    std::vector<ScannedBss> scannedBss;
    for (const auto& bss : wil::make_range(bssList->wlanBssEntries, bssList->dwNumberOfItems))
    {
        auto ieStart = reinterpret_cast<const uint8_t*>(&bss) + bss.ulIeOffset;
        scannedBss.emplace_back(
            toBssid(bss.dot11Bssid),
            bss.dot11Ssid,
            bss.usCapabilityInformation,
            wil::safe_cast<int8_t>(bss.lRssi),
            bss.ulChCenterFrequency,
            bss.usBeaconPeriod,
            std::vector<uint8_t>{ieStart, ieStart + bss.ulIeSize});
    }
    return scannedBss;
}

std::vector<WLAN_AVAILABLE_NETWORK> WlanApiWrapperImpl::GetScannedNetworkList(const GUID& interfaceGuid)
{
    wil::unique_wlan_ptr<WLAN_AVAILABLE_NETWORK_LIST> scannedNetworks;
    THROW_IF_WIN32_ERROR(WlanGetAvailableNetworkList(
        m_wlanHandle.get(), &interfaceGuid, dot11_BSS_type_infrastructure, nullptr, wil::out_param(scannedNetworks)));
    return {scannedNetworks->Network, scannedNetworks->Network + scannedNetworks->dwNumberOfItems};
}

} // namespace ProxyWifi::Wlansvc