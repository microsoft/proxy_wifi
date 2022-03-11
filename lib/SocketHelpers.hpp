// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <functional>
#include <optional>
#include <stdexcept>
#include <utility>

#include <WinSock2.h>
#include <hvsocket.h>
#include <wil/resource.h>

#include "Messages.hpp"

namespace ProxyWifi {

enum class SocketUse
{
    Bound, ///< The socket should be bound, as by calling bind().
    Connected, ///< The socket should be connected, as by calling connect().
};

/// @brief Create a socket of a specific type.
///
/// This will create a socket and then perform some action on the socket
/// following its creation, preparing it for use.
///
/// @tparam SockAddrType The type of the generic transport descriptor.
/// @param type The type of socket to create. This dictates the action taken on the socket after it is created.
/// @param createSocket A function used to create the socket and its transport descriptor.
template <typename SockAddrType>
wil::unique_socket CreateSocketWithUse(SocketUse type, std::function<std::pair<wil::unique_socket, SockAddrType>()> createSocket)
{
    auto [socket, sockAddr] = createSocket();

    switch (type)
    {
    case SocketUse::Bound:
        if (bind(socket.get(), reinterpret_cast<SOCKADDR*>(&sockAddr), sizeof sockAddr) != 0)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "Socket bind failed");
        }
        break;
    case SocketUse::Connected:
        if (connect(socket.get(), reinterpret_cast<SOCKADDR*>(&sockAddr), sizeof sockAddr) != ERROR_SUCCESS)
        {
            THROW_WIN32_MSG(WSAGetLastError(), "Socket connect failed");
        }
        break;
    default:
        throw std::invalid_argument("Unsupported socket type");
    }

    return std::move(socket);
}

/// @brief Helper function to create a HyperV socket.
/// @param vmId The vm if for which the socket should be restricted to.
/// @param port The port of the socket to bind.
std::pair<wil::unique_socket, SOCKADDR_HV> CreateHyperVSocket(const GUID& vmId, unsigned int port);

/// @brief Helper function to create a TCP/IP socket.
/// @param listenIpAddr The TCP/IP address the socket should be bound to.
/// @param port The TCP/IP port number the socket should be bound to.
std::pair<wil::unique_socket, sockaddr_in> CreateTcpSocket(const IN_ADDR& listenIpAddr, unsigned short port);

class AcceptAsyncContext
{
public:
    /// @brief Asynchronously accept a connection
    /// @param listenSocket The socket connection are listened on
    /// @return The socket the connection will be accepted on
    static AcceptAsyncContext Accept(const wil::unique_socket& listenSocket, const std::function<std::pair<wil::unique_socket, size_t>()>& createSocket);

    ~AcceptAsyncContext();

    const wil::unique_event& getOnAcceptEvent() const noexcept
    {
        return m_onAcceptEvent;
    }

    const wil::unique_socket& getSocket() noexcept
    {
        return m_acceptSocket;
    }

    wil::unique_socket releaseSocket() noexcept
    {
        return std::move(m_acceptSocket);
    }

private:
    explicit AcceptAsyncContext(
        wil::unique_socket acceptSocket, wil::unique_event onAcceptEvent, std::unique_ptr<uint8_t[]> buffer, std::unique_ptr<OVERLAPPED> overlapped) noexcept;

    wil::unique_socket m_acceptSocket;
    wil::unique_event m_onAcceptEvent{wil::EventOptions::ManualReset};
    std::unique_ptr<uint8_t[]> m_buffer;
    std::unique_ptr<WSAOVERLAPPED> m_overlapped;
};

/// @brief Helper function which receives a single protocol message on a generic socket.
std::optional<Message> ReceiveProxyWifiMessage(const wil::unique_socket& socket);

/// @brief Helper function which sends a single protocol message on a generic socket.
void SendProxyWifiMessage(wil::unique_socket& socket, const Message& message);

} // namespace ProxyWifi