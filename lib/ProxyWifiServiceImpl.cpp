// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include <utility>

#include <wil/result.h>

#include "ClientWlanInterface.hpp"
#include "LogsHelpers.hpp"
#include "OperationHandlerBuilder.hpp"
#include "StringUtils.hpp"
#include "ProxyWifiServiceImpl.hpp"

namespace ProxyWifi {

namespace {

constexpr const char* GetProxyModeName(OperationMode mode)
{
    switch (mode)
    {
    case OperationMode::Simulated:
        return "Simulated";
    case OperationMode::Normal:
        return "Normal";
    default:
        throw std::runtime_error("Unsupported proxy mode");
    }
}

std::shared_ptr<OperationHandler> GetOperationHandler(
    const OperationMode proxyMode, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
{
    switch (proxyMode)
    {
    case OperationMode::Simulated:
        return MakeManualTestOperationHandler(std::move(fakeNetworkCallback), pObserver);
    case OperationMode::Normal:
    {
        std::shared_ptr<Wlansvc::WlanApiWrapper> wlansvc;
        try
        {
            wlansvc = std::make_shared<Wlansvc::WlanApiWrapperImpl>();
        }
        catch(...)
        {
            LOG_CAUGHT_EXCEPTION_MSG("Failed to get a Wlansvc handle. Will only support fake networks.");
        }
        return MakeWlansvcOperationHandler(wlansvc, std::move(fakeNetworkCallback), pObserver);
    }
    default:
        throw std::runtime_error("Unsupported proxy mode selected");
    }
}
} // namespace

WifiNetworkInfo::WifiNetworkInfo(const DOT11_SSID& ssid, const DOT11_MAC_ADDRESS& bssid)
{
    this->ssid = ssid;
    memcpy_s(this->bssid, sizeof this->bssid, bssid, sizeof bssid);
}

ProxyWifiCommon::ProxyWifiCommon(OperationMode mode, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
    : m_mode{mode}, m_operationHandler{GetOperationHandler(mode, std::move(fakeNetworkCallback), pObserver)}
{
}

ProxyWifiCommon::~ProxyWifiCommon()
{
    Stop();
}

void ProxyWifiCommon::Start()
{
    Log::Info(L"Starting the Wifi proxy");
    m_transport = CreateTransport();
    m_transport->Start();
}

void ProxyWifiCommon::Stop()
{
    if (!m_transport)
        return;

    Log::Info(L"Stopping the Wifi proxy");
    m_transport->Shutdown();
    m_transport = nullptr;
}

ProxyWifiHyperVSettings::ProxyWifiHyperVSettings(const GUID& guestVmId, unsigned short requestResponsePort, unsigned short notificationPort, OperationMode mode)
    : GuestVmId(guestVmId),
      RequestResponsePort(requestResponsePort),
      NotificationPort(notificationPort),
      ProxyMode(mode)
{
}

ProxyWifiHyperVSettings::ProxyWifiHyperVSettings(const GUID& guestVmId)
    : GuestVmId(guestVmId)
{
}

ProxyWifiHyperV::ProxyWifiHyperV(const ProxyWifiHyperVSettings& settings, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
    : ProxyWifiCommon(settings.ProxyMode, std::move(fakeNetworkCallback), pObserver), m_settings(settings)
{
}

std::unique_ptr<Transport> ProxyWifiHyperV::CreateTransport()
{
    return std::make_unique<HyperVTransport>(
        m_operationHandler, m_settings.RequestResponsePort, m_settings.NotificationPort, m_settings.GuestVmId);
}

const ProxyWifiHyperVSettings& ProxyWifiHyperV::Settings() const
{
    return m_settings;
}

ProxyWifiTcpSettings::ProxyWifiTcpSettings(const std::string& listenIp, unsigned short requestResponsePort, unsigned short notificationPort, OperationMode proxyMode)
    : ListenIp(listenIp),
      RequestResponsePort(requestResponsePort),
      NotificationPort(notificationPort),
      ProxyMode(proxyMode)
{
}

ProxyWifiTcpSettings::ProxyWifiTcpSettings(const std::string& listenIp)
    : ListenIp(listenIp)
{
}

ProxyWifiTcp::ProxyWifiTcp(
    const ProxyWifiTcpSettings& settings, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
    : ProxyWifiCommon(settings.ProxyMode, std::move(fakeNetworkCallback), pObserver), m_settings(settings)
{
}

std::unique_ptr<Transport> ProxyWifiTcp::CreateTransport()
{
    return std::make_unique<TcpTransport>(
        m_operationHandler, m_settings.RequestResponsePort, m_settings.NotificationPort, m_settings.ListenIp);
}

const ProxyWifiTcpSettings& ProxyWifiTcp::Settings() const
{
    return m_settings;
}

std::unique_ptr<ProxyWifiService> BuildProxyWifiService(
    const ProxyWifiHyperVSettings& settings, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
{
    Log::Info(
        L"Building a Wifi proxy. Mode: %hs, Transport: HvSocket, VM Guid: %ws, Request port: %d, Notification port: %d",
        GetProxyModeName(settings.ProxyMode),
        GuidToString(settings.GuestVmId).c_str(),
        settings.RequestResponsePort,
        settings.NotificationPort);
    return std::make_unique<ProxyWifiHyperV>(settings, std::move(fakeNetworkCallback), pObserver);
}

std::unique_ptr<ProxyWifiService> BuildProxyWifiService(
    const ProxyWifiTcpSettings& settings, FakeNetworkProvider fakeNetworkCallback, ProxyWifiObserver* pObserver)
{
    Log::Info(
        L"Building a Wifi proxy. Mode: %hs, Transport: TCP, Listen IP: %hs, Request port: %d, Notification port: %d",
        GetProxyModeName(settings.ProxyMode),
        settings.ListenIp.c_str(),
        settings.RequestResponsePort,
        settings.NotificationPort);
    return std::make_unique<ProxyWifiTcp>(settings, std::move(fakeNetworkCallback), pObserver);
}

} // namespace ProxyWifi