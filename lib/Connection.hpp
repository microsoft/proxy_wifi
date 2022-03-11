// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <memory>
#include <optional>

#include <WinSock2.h>
#include <wil/resource.h>

#include "Messages.hpp"
#include "OperationHandler.hpp"

namespace ProxyWifi {

/// @brief Represents a connection with a proxy client. Defines an interface for
/// sending and receiving protocol messages, and receiving protocol
/// notifications.
///
/// This is a base class meant to be derived for specific transports.
class Connection
{
public:
    /// @brief Creates a new wifi proxy connection.
    ///
    /// @param operations The object used to handle protocol messages.
    Connection(std::shared_ptr<OperationHandler> operations);

    /// @brief Destroy the Connection object.
    virtual ~Connection() = default;

    /// @brief Start accepting requests on this connection.
    ///
    /// This must be invoked to enable communication on the connection and is
    /// stopped when the Teardown() function is called.
    void Run();

protected:
    /// @brief Receive a single protocol message on the connection.
    ///
    /// This call must block if no message is available on the socket. Once
    /// available, the message should be returned.
    ///
    /// @return std::optional<Message> The message received, if one was available.
    virtual std::optional<Message> ReceiveMessage() = 0;

    /// @brief Send a single protocol message on the connection.
    /// @param message The protocol message to send.
    virtual void SendMessage(const Message& message) = 0;

private:
    const std::shared_ptr<OperationHandler> m_operations;
};

/// @brief A connection that uses a generic socket as the transport.
class ConnectionSocket : public Connection
{
public:
    /// @brief Create a new connection using a socket as the transport.
    /// @param socket The socket used for the connection
    /// @param operations The object used to handle protocol messages.
    ConnectionSocket(wil::unique_socket socket, const std::shared_ptr<OperationHandler>& operations);

private:
    /// @brief Sends a protocol message on the connection.
    void SendMessage(const Message& message) override;

    /// @brief Receives a protocol message on the connection.
    std::optional<Message> ReceiveMessage() override;

private:
    wil::unique_socket m_socket;
};

} // namespace ProxyWifi