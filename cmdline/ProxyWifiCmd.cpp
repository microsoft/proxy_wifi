// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "ProxyWifi/Logs.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"

#include <rpc.h>
#include <WinSock2.h>

#include <charconv>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <iostream>

#include <wil/resource.h>

using namespace ProxyWifi;

static void print_help()
{
    std::cout << "\nCommand line arguments:\n\n"
                 "-vmid <id (guid) of guest vm from which to accept connections>\n"
                 "-p <Request/response port number>\n"
                 "-n <Notification port number>\n"
                 "-k (Use hv_sockets - default)\n"
                 "-l <Server IPv4 Address>\n"
                 "-f (Fake wlansvc - for tests)\n"
                 "-tlog (Log to tracelogging in addition to console output)\n"
                 "-h (Print this help)";
}

enum class TransportType
{
    HyperVSocket,
    TcpSocket,
};

std::wstring ToString(TransportType e)
{
    switch (e)
    {
    case TransportType::HyperVSocket:
        return L"Hyper-V";
    case TransportType::TcpSocket:
        return L"Tcp";
    default:
        throw std::invalid_argument("Invalid enum value");
    }
}

struct ProxyWifiConfig
{
    GUID VmId{};
    std::optional<std::string> ListenIp;
    unsigned short RequestResponsePort = RequestResponsePortDefault;
    unsigned short NotificationPort = NotificationPortDefault;
    OperationMode Mode = OperationMode::Normal;
    TransportType Transport = TransportType::HyperVSocket;
    bool UseTracelogging = false;
};

std::optional<ProxyWifiConfig> CreateProxyConfigFromArguments(int argc, const char* argv[])
{
    ProxyWifiConfig manager{};

    auto i = 1;
    while (i < argc)
    {
        const std::string_view option(argv[i]);
        if (option == "-h")
        {
            print_help();
            return std::nullopt;
        }
        else if (option == "-p")
        {
            std::string_view value(argv[++i]);
            const auto res = std::from_chars(value.data(), value.data() + value.size(), manager.RequestResponsePort);
            if (res.ec == std::errc::invalid_argument)
            {
                throw std::invalid_argument("Invalid port number");
            }
        }
        else if (option == "-n")
        {
            std::string_view value(argv[++i]);
            const auto res = std::from_chars(value.data(), value.data() + value.size(), manager.NotificationPort);
            if (res.ec == std::errc::invalid_argument)
            {
                throw std::invalid_argument("Invalid port number");
            }
        }
        else if (option == "-k")
        {
            manager.Transport = TransportType::HyperVSocket;
        }
        else if (option == "-f")
        {
            manager.Mode = OperationMode::Simulated;
        }
        else if (option == "-l")
        {
            manager.ListenIp = argv[++i];
            manager.Transport = TransportType::TcpSocket;
        }
        else if (option == "-vmid")
        {
            GUID guestVmId;
            const char* guestVmIdStr = argv[++i];
            if (UuidFromStringA((unsigned char*)guestVmIdStr, &guestVmId) != RPC_S_OK)
            {
                throw std::invalid_argument("Invalid VM Guid");
            }
            manager.VmId = guestVmId;
        }
        else if (option == "-tlog")
        {
            manager.UseTracelogging = true;
        }
        else
        {
            throw std::invalid_argument("Invalid argument " + std::string(argv[i]));
        }

        i++;
    }

    switch (manager.Transport)
    {
    case TransportType::TcpSocket:
        if (!manager.ListenIp)
        {
            throw std::invalid_argument("An ip address is required when using tcp transport");
        }
        break;
    case TransportType::HyperVSocket:
        if (manager.ListenIp)
        {
            throw std::invalid_argument("An ip address not not be provided when using HyperV socket transport");
        }
        break;
    default:
        throw std::runtime_error("unsupported proxy transport specified");
    }

    if (manager.VmId == GUID{})
    {
        throw std::invalid_argument("A VM GUID is required.");
    }

    return manager;
}

std::unique_ptr<ProxyWifiService> BuildProxyWifiService(const ProxyWifiConfig& settings)
{
    wil::unique_rpc_wstr vmStr;
    THROW_IF_FAILED(UuidToString(&settings.VmId, &vmStr));

    Log::Info(L"Creating %ws Wi-Fi Proxy for VM id=%ws, request port=%u, notification port=%u", ToString(settings.Transport).c_str(), vmStr.get(), settings.RequestResponsePort, settings.NotificationPort);

    switch (settings.Transport)
    {
    case TransportType::HyperVSocket:
    {
        const ProxyWifiHyperVSettings proxySettings{settings.VmId, settings.RequestResponsePort, settings.NotificationPort, settings.Mode};
        return BuildProxyWifiService(proxySettings, {});
    }
    case TransportType::TcpSocket:
    {
        const ProxyWifiTcpSettings proxySettings{settings.ListenIp.value(), settings.RequestResponsePort, settings.NotificationPort, settings.Mode};
        return BuildProxyWifiService(proxySettings, {});
    }
    default:
        throw std::runtime_error("unsupported proxy protocol transport selected");
    }
}

int main(int argc, const char* argv[])
try
{
    Log::AddLogger(std::make_unique<Log::ConsoleLogger>());

    // Redirect WIL failures as logs
    wil::SetResultLoggingCallback([](const wil::FailureInfo& failure) noexcept {
        constexpr std::size_t sizeOfLogMessageWithNul = 2048;

        wchar_t logMessage[sizeOfLogMessageWithNul]{};
        wil::GetFailureLogString(logMessage, sizeOfLogMessageWithNul, failure);
        Log::WilFailure(logMessage);
    });

    // Initialize winsock.
    {
        WSADATA wsaData;
        const auto wsError = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsError != 0)
        {
            LOG_WIN32_MSG(wsError, "WSAStartup failed");
            return -1;
        }
    }

    auto wsaCleanupOnExit = wil::scope_exit([&] { WSACleanup(); });

    std::optional<ProxyWifiConfig> proxyConfig;
    try
    {
        proxyConfig = CreateProxyConfigFromArguments(argc, argv);
    }
    catch (const std::invalid_argument& e)
    {
        std::cerr << "Invalid parameter: " << e.what() << std::endl;
        print_help();
        return -1;
    }

    if (!proxyConfig)
    {
        return 0;
    }

    if (proxyConfig->UseTracelogging)
    {
        Log::AddLogger(std::make_unique<Log::TraceLoggingLogger>());
    }

    const auto proxyService = BuildProxyWifiService(*proxyConfig);
    proxyService->Start();

    // Sleep until the program is interrupted with Ctrl-C
    Sleep(INFINITE);

    return 0;
}
catch (const wil::ResultException& ex)
{
    std::wcerr << "Caught unhandled exception: " << ex.GetErrorCode();
    if (ex.GetFailureInfo().pszMessage)
    {
        std::wcerr << ", " << ex.GetFailureInfo().pszMessage;
    }
    std::wcerr << std::endl;

    return -1;
}
catch (const std::exception& ex)
{
    std::cerr << "Caught unhandled exception: " << ex.what() << std::endl;
    return -1;
}
catch (...)
{
    std::cerr << "Caught unhandled exception" << std::endl;
    FAIL_FAST_MSG("FATAL: UNHANDLED EXCEPTION");
}
