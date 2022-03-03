// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <WinSock2.h>

#include <wil/resource.h>

#include "Connection.hpp"
#include "OperationHandler.hpp"
#include "WorkQueue.hpp"

namespace ProxyWifi {

/// @brief Represents a transport for exchanging data between the host and
/// guest, using generic sockets.
///
/// The transport has no awareness of a protocol. It is responsible for accepting
/// connections and exchanging data between two endpoints.
class Transport
{
public:
    /// @brief Construct a new Transport Socket object.
    /// @param requestResponsePort The request/response port to bind to.
    /// @param notificationPort The notification port to connect to.
    Transport(std::shared_ptr<OperationHandler>& operationHandler, unsigned short requestResponsePort, unsigned short notificationPort);

    Transport(const Transport&) = delete;
    Transport(Transport&&) = delete;
    Transport& operator=(const Transport&) = delete;
    Transport& operator=(Transport&&) = delete;

    /// @brief Destroy the Wifi Proxy Transport Socket object.
    virtual ~Transport();

    /// @brief Start accepting connection asynchronounsly.
    void Start();

    /// @brief Shutdown the transport and stop accepting connections.
    void Shutdown();

protected:
    /// @brief Start accepting connections.
    void AcceptConnections();

    /// @brief Interface function to create the request/response socket.
    /// Implementations must return a socket that is listening on the configured
    /// request/response port.
    virtual wil::unique_socket CreateListenSocket() = 0;

    /// @brief Interface function to create a bound socket. Implementations must
    /// return a socket that is bound to the confitured notification port.
    virtual wil::unique_socket CreateNotificationSocket() = 0;

    /// @brief Interface function to create a socket for an accepted connection.
    /// Implementation must return a socket unbound and unconnected
    virtual std::pair<wil::unique_socket, size_t> CreateAcceptSocket() = 0;

private:
    /// @brief Queue a notification to send it asynchronously
    void QueueNotification(Message&& msg);

    /// @brief Send a single protocol message as a notification.
    void SendNotification(const Message& message);

protected:
    std::shared_ptr<OperationHandler> m_operationHandler;

    std::thread m_runnerThread;
    wil::unique_event m_shutdownEvent{wil::EventOptions::ManualReset};
    unsigned short m_requestResponsePort;

    SerializedWorkQueue<std::function<void()>> m_notifQueue;
    unsigned short m_notificationPort;

    std::atomic_bool m_guestWasPresent = false;
};

/// @brief Proxy transport which uses HyperV (AF_HYPERV) sockets.
///
/// This facilitates proxying Wi-Fi operations to Hyper-V container endpoints.
class HyperVTransport : public Transport
{
public:
    /// @brief Creates a new Hyper-V transport which listens for connections
    /// on the specified ports and is restricted to the specified guest vm id
    /// @param operationHandler The operation handler for the transport.
    /// @param requestResponsePort The HyperV socket port for the request/response communication channel.
    /// @param notificationPort The HyperV socket port for the notification communication channel.
    /// @param guestVmId The vm if for which the transport should be restricted to.
    HyperVTransport(
        std::shared_ptr<OperationHandler>& operationHandler, unsigned short requestResponsePort, unsigned short notificationPort, const GUID& guestVmId);

private:
    wil::unique_socket CreateListenSocket() override;
    wil::unique_socket CreateNotificationSocket() override;
    std::pair<wil::unique_socket, size_t> CreateAcceptSocket() override;

private:
    const GUID m_guestVmId;
};

/// @brief Proxy transport using TCP/IP sockets.
///
/// This facilitates proxying Wi-Fi operations to TCP/IP endpoints. This can
/// include remote systems if the transport is bound to a publicly routable
/// TCP/IP address.
class TcpTransport : public Transport
{
public:
    /// @brief Construct a new Tcp Transport object
    /// @param operationHandler The operation handler for the transport.
    /// @param listenIp The TCP/IP address to listen on for request, in a format compatible with `inet_pton`.
    /// @param requestResponsePort The TCP/IP port number for the request/response communication channel.
    /// @param notificationPort The TCP/IP port number for the notification communication channel.
    TcpTransport(std::shared_ptr<OperationHandler>& operationHandler, unsigned short requestResponsePort, unsigned short notificationPort, const std::string& listenIp);

private:
    wil::unique_socket CreateListenSocket() override;
    wil::unique_socket CreateNotificationSocket() override;
    std::pair<wil::unique_socket, size_t> CreateAcceptSocket() override;

private:
    const std::string m_listenIp;
    IN_ADDR m_listenIpAddr{};
};

} // namespace ProxyWifi