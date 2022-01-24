// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "SocketHelpers.hpp"

#include <mswsock.h>

#include <array>
#include <cstdio>
#include <memory>
#include <gsl/span>

#include "ProxyWifi/Logs.hpp"

namespace ProxyWifi {

std::pair<wil::unique_socket, SOCKADDR_HV> CreateHyperVSocket(const GUID& vmId, unsigned int port)
{
    wil::unique_socket sock{WSASocket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW, nullptr, 0, WSA_FLAG_OVERLAPPED)};
    if (!sock.is_valid())
    {
        THROW_WIN32_MSG(WSAGetLastError(), "Failed to create an hv socket");
    }

    SOCKADDR_HV sockAddrHv{};
    memset(&sockAddrHv, 0, sizeof sockAddrHv);
    sockAddrHv.Family = AF_HYPERV;
    sockAddrHv.VmId = vmId;
    sockAddrHv.ServiceId = HV_GUID_VSOCK_TEMPLATE;
    sockAddrHv.ServiceId.Data1 = port;

    // Ensure the socket stays connected when the VM is suspended.
    ULONG enable = 1;
    THROW_LAST_ERROR_IF(
        setsockopt(sock.get(), HV_PROTOCOL_RAW, HVSOCKET_CONNECTED_SUSPEND, reinterpret_cast<char*>(&enable), sizeof enable) == SOCKET_ERROR);

    return {std::move(sock), sockAddrHv};
}

std::pair<wil::unique_socket, sockaddr_in> CreateTcpSocket(const IN_ADDR& listenIpAddr, unsigned short port)
{
    wil::unique_socket sock{WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED)};
    if (!sock.is_valid())
    {
        THROW_WIN32_MSG(WSAGetLastError(), "Failed to create a tcp socket");
    }

    // Bind address to server socket.
    sockaddr_in sockaddrIn;
    memset(&sockaddrIn, 0, sizeof(sockaddrIn));
    sockaddrIn.sin_family = AF_INET;
    sockaddrIn.sin_port = htons(port);
    sockaddrIn.sin_addr = listenIpAddr;

    return {std::move(sock), sockaddrIn};
}

AcceptAsyncContext::AcceptAsyncContext(
    wil::unique_socket acceptSocket, wil::unique_event onAcceptEvent, std::unique_ptr<uint8_t[]> buffer, std::unique_ptr<OVERLAPPED> overlapped) noexcept
    : m_acceptSocket{std::move(acceptSocket)}, m_onAcceptEvent{std::move(onAcceptEvent)}, m_buffer{std::move(buffer)}, m_overlapped{std::move(overlapped)}
{
}

AcceptAsyncContext::~AcceptAsyncContext()
{
    // Make sure the pending IO is completed before destroying the context
    if (m_onAcceptEvent.is_valid())
    {
        m_onAcceptEvent.wait();
    }
}

AcceptAsyncContext AcceptAsyncContext::Accept(const wil::unique_socket& listenSocket, std::function<std::pair<wil::unique_socket, size_t>()> createSocket)
{
    auto [acceptSocket, addrSize] = createSocket();
    if (!acceptSocket.is_valid())
    {
        THROW_WIN32_MSG(WSAGetLastError(), "Failed to create an hv socket");
    }

    // `AcceptEx` requires an extra 16 bytes for every addresses in the buffer for an internal representation
    constexpr auto extraAddressSize = 16;

    auto buffer = std::make_unique<uint8_t[]>(2 * (addrSize + extraAddressSize));
    auto acceptEvent = wil::unique_event(wil::EventOptions::ManualReset);
    auto overlapped = std::make_unique<OVERLAPPED>();
    overlapped->hEvent = acceptEvent.get();

    DWORD bytes{};
    const auto addrSizeWithExtra = wil::safe_cast<DWORD>(addrSize + extraAddressSize);
    if (!AcceptEx(
            listenSocket.get(), acceptSocket.get(), buffer.get(), 0, addrSizeWithExtra, addrSizeWithExtra, &bytes, overlapped.get()))
    {
        if (WSAGetLastError() != ERROR_IO_PENDING)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "Failed to accept the connection");
        }
    }

    // Create the context only after the call to `AcceptEx` succeeded, to ensure the event will be signaled
    return AcceptAsyncContext(std::move(acceptSocket), std::move(acceptEvent), std::move(buffer), std::move(overlapped));
}

static bool ReceiveBytes(wil::unique_socket& socket, gsl::span<uint8_t> buffer)
{
    while (buffer.size_bytes() > 0)
    {
        const auto transfer_size = recv(socket.get(), reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size_bytes()), 0);
        if (transfer_size < 0)
        {
            const auto err = WSAGetLastError();
            THROW_WIN32_MSG(err, "Received invalid message (transfer_size=%d)", transfer_size);
        }
        if (transfer_size == 0)
        {
            return false;
        }

        buffer = buffer.subspan(transfer_size);
    }

    return true;
}

std::optional<Message> ReceiveProxyWifiMessage(wil::unique_socket& socket)
{
    Message message;
    if (!ReceiveBytes(socket, {reinterpret_cast<uint8_t*>(&message.hdr), sizeof(message.hdr)}))
    {
        // The guest closed the connection
        return std::nullopt;
    }

    if (message.hdr.size == 0)
    {
        return message;
    }

    // Allocate body
    message.body.resize(message.hdr.size);

    if (!ReceiveBytes(socket, {message.body.data(), message.hdr.size}))
    {
        LOG_HR_MSG(E_UNEXPECTED, "Connection closed when expecting a message body");
        return std::nullopt;
    }

    return message;
}

static void SendBytes(wil::unique_socket& socket, gsl::span<const uint8_t> dataToSend)
{
    // TODO: Is it needed to loop on a send?
    while (dataToSend.size_bytes() > 0)
    {
        const auto transfer_size =
            send(socket.get(), reinterpret_cast<const char*>(dataToSend.data()), wil::safe_cast<int>(dataToSend.size_bytes()), 0);
        if (transfer_size <= 0)
        {
            const auto err = WSAGetLastError();
            THROW_WIN32_MSG(err, "Send failed (transfer_size=%d)", transfer_size);
        }

        dataToSend = dataToSend.subspan(transfer_size);
    }
}

void SendProxyWifiMessage(wil::unique_socket& socket, const Message& message)
{
    SendBytes(socket, {reinterpret_cast<const uint8_t*>(&message.hdr), sizeof(message.hdr)});
    if (!message.body.empty())
    {
        SendBytes(socket, {message.body.data(), message.hdr.size});
    }
}

} // namespace ProxyWifi