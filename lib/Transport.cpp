// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "Transport.hpp"

#include <WS2tcpip.h>

#include "LogsHelpers.hpp"
#include "SocketHelpers.hpp"
#include "ProxyWifi/Logs.hpp"

namespace ProxyWifi {

Transport::Transport(std::shared_ptr<OperationHandler>& operationHandler, unsigned short requestResponsePort, unsigned short notificationPort)
    : m_operationHandler{operationHandler}, m_requestResponsePort(requestResponsePort), m_notificationPort(notificationPort)
{
    m_operationHandler->RegisterGuestNotificationCallback([this](auto notif) noexcept {
        try
        {
            std::visit(
                [this](auto&& n) {
                    using T = std::decay_t<decltype(n)>;
                    Log::Info(L"Adding notification to queue: %ws", n.Describe().c_str());
                    QueueNotification(T::ToMessage(std::forward<T>(n)));
                },
                notif);
        }
        CATCH_LOG()
    });
}

Transport::~Transport()
{
    Shutdown();
}

void Transport::AcceptConnections()
{
    auto listenSocket = CreateListenSocket();

    // Start listening for connections.
    if (listen(listenSocket.get(), 1) != 0)
    {
        THROW_LAST_ERROR_MSG("Failed to listen on socket");
    }

    while (true)
    {
        auto acceptContext = AcceptAsyncContext::Accept(listenSocket, [this] { return CreateAcceptSocket(); });

        // Accept connection.
        Log::Debug(L"Waiting for connection...");
        const std::array events = {m_shutdownEvent.get(), acceptContext.getOnAcceptEvent().get()};
        const auto waitResults = WSAWaitForMultipleEvents(static_cast<DWORD>(events.size()), events.data(), false, WSA_INFINITE, false);
        if (waitResults == WSA_WAIT_EVENT_0)
        {
            // This is the shutdown event
            Log::Debug(L"Completing the transport runner thread");
            // Close the listen socket first, the accept context will then wait for the pending IO before destroying itself
            listenSocket.reset();
            return;
        }
        else if (waitResults == WSA_WAIT_EVENT_0 + 1)
        {
            Log::Debug(L"Got connection");

            // The guest is now ready, this will let host notification be sent
            m_guestWasPresent = true;

            // Handle the connection synchronously: the guest requests are serialized
            auto connection = ConnectionSocket{acceptContext.releaseSocket(), m_operationHandler};
            connection.Run();
        }
        else if (waitResults == WSA_WAIT_FAILED)
        {
            LOG_WIN32_MSG(WSAGetLastError(), "Failed to wait on for an incomming connection");

            // Try to recover by reseting the listen socket
            listenSocket.reset();
            const auto waitRecover = WSAWaitForMultipleEvents(static_cast<DWORD>(events.size()), events.data(), false, WSA_INFINITE, false);
            if (waitRecover == WSA_WAIT_EVENT_0)
            {
                // This is the shutdown event, end the thread
                Log::Debug(L"Completing the transport runner thread while trying to recover from bad wait");
                return;
            }
            else if (waitRecover != WSA_WAIT_EVENT_0 + 1)
            {
                // Still failing, abort
                FAIL_FAST();
            }

            // Start listening for connections again
            listenSocket = CreateListenSocket();
            if (listen(listenSocket.get(), 1) != 0)
            {
                THROW_LAST_ERROR_MSG("Failed to listen on socket");
            }
            continue;
        }
        else
        {
            FAIL_FAST_IF_WIN32_ERROR_MSG(ERROR_INVALID_STATE, "Received unexpected value from WSAWaitForMultipleEvents: %d", waitResults);
        }
    }
}

void Transport::QueueNotification(Message&& msg)
{
    if (!m_guestWasPresent)
    {
        Log::Trace(L"Dropping a notification: no guest request have been received, it might not be ready yet");
    }

    m_notifQueue.Submit([this, n = std::move(msg)]() noexcept {
        try
        {
            SendNotification(n);
        }
        CATCH_LOG_MSG("Failed to send a notification")
    });
}

void Transport::SendNotification(const Message& message)
{
    Log::Trace(L"Sending notification <%ws> (%d bytes)", GetProtocolMessageTypeName(message.hdr.operation), message.hdr.size);
    auto socket = CreateNotificationSocket();
    SendProxyWifiMessage(socket, message);
}

void Transport::Start()
{
    m_shutdownEvent.ResetEvent();

    m_runnerThread = std::thread([this] {
        const auto logger = SetThreadWilFailureLogger();
        AcceptConnections();
    });
}

void Transport::Shutdown()
{
    // Stop accepting request from the guest
    std::thread thread;
    std::swap(thread, m_runnerThread);

    m_shutdownEvent.SetEvent();

    if (thread.joinable())
    {
        thread.join();
    }

    // Stop sending notification to the guest
    // First, clear the operation handler callback (and wait for any currently executing one),
    // to ensure nothing is queued after `m_notifQueue` is stopped
    m_operationHandler->ClearGuestNotificationCallback();
    m_notifQueue.Cancel();
}

HyperVTransport::HyperVTransport(
    std::shared_ptr<OperationHandler>& operationHandler, unsigned short requestResponsePort, unsigned short notificationPort, const GUID& guestVmId)
    : Transport(operationHandler, requestResponsePort, notificationPort), m_guestVmId(guestVmId)
{
}

wil::unique_socket HyperVTransport::CreateListenSocket()
{
    return CreateSocketWithUse<SOCKADDR_HV>(
        SocketUse::Bound, [&]() { return CreateHyperVSocket(m_guestVmId, m_requestResponsePort); });
}

wil::unique_socket HyperVTransport::CreateNotificationSocket()
{
    return CreateSocketWithUse<SOCKADDR_HV>(
        SocketUse::Connected, [&]() { return CreateHyperVSocket(m_guestVmId, m_notificationPort); });
}

std::pair<wil::unique_socket, size_t> HyperVTransport::CreateAcceptSocket()
{
    wil::unique_socket sock{WSASocket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW, nullptr, 0, 0)};
    if (!sock.is_valid())
    {
        THROW_WIN32_MSG(WSAGetLastError(), "Failed to create an hv socket");
    }
    return std::make_pair(std::move(sock), sizeof(SOCKADDR_HV));
}

TcpTransport::TcpTransport(
    std::shared_ptr<OperationHandler>& operationHandler, unsigned short requestResponsePort, unsigned short notificationPort, const std::string& listenIp)
    : Transport(operationHandler, requestResponsePort, notificationPort), m_listenIp(listenIp)
{
    if (inet_pton(AF_INET, listenIp.c_str(), &m_listenIpAddr) != 1)
    {
        THROW_WIN32_MSG(WSAGetLastError(), "listenIP: %hs", listenIp.c_str());
    }
}

wil::unique_socket TcpTransport::CreateListenSocket()
{
    return CreateSocketWithUse<sockaddr_in>(
        SocketUse::Bound, [&]() { return CreateTcpSocket(m_listenIpAddr, m_requestResponsePort); });
}

wil::unique_socket TcpTransport::CreateNotificationSocket()
{
    return CreateSocketWithUse<sockaddr_in>(
        SocketUse::Connected, [&]() { return CreateTcpSocket(m_listenIpAddr, m_notificationPort); });
}

std::pair<wil::unique_socket, size_t> TcpTransport::CreateAcceptSocket()
{
    wil::unique_socket sock{WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0)};
    if (!sock.is_valid())
    {
        THROW_WIN32_MSG(WSAGetLastError(), "Failed to create a tcp socket");
    }
    return std::make_pair(std::move(sock), sizeof(sockaddr_in));
}

} // namespace ProxyWifi