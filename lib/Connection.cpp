// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <wil/result_macros.h>

#include "Connection.hpp"
#include "ProxyWifi/Logs.hpp"
#include "SocketHelpers.hpp"

namespace ProxyWifi {

Connection::Connection(std::shared_ptr<OperationHandler> operations)
    : m_operations(std::move(operations))
{
}

void Connection::Run()
{
    std::optional<Message> request{};

    try
    {
        request = ReceiveMessage();
    }
    catch (...)
    {
        LOG_WIN32_MSG(ERROR_INVALID_MESSAGE, "Failed to received a message");
        return;
    }

    if (!request.has_value())
    {
        LOG_WIN32_MSG(ERROR_NO_DATA, "No message received");
        return;
    }

    Log::Trace(L"Received request <%ws> (%d bytes)", GetProtocolMessageTypeName(request->hdr.operation), request->hdr.size);

    try
    {
        Message responseMessage{};
        if (request->hdr.version != proxy_wifi_version::VERSION_0_1)
        {
            throw std::runtime_error(
                "Unsuported request version: " + std::to_string(request->hdr.version) +
                ", version expected: " + std::to_string(proxy_wifi_version::VERSION_0_1));
        }

        switch (request->hdr.operation)
        {
        case WIFI_OP_SCAN_REQUEST:
        {
            const auto command = ScanRequest{std::move(request->body)};
            Log::Info(L"Received: %ws", command.Describe().c_str());

            auto response = m_operations->HandleScanRequest(command);
            Log::Info(L"Answering: %ws", response.Describe().c_str());

            responseMessage = ScanResponse::ToMessage(std::move(response));
            break;
        }
        case WIFI_OP_CONNECT_REQUEST:
        {
            const auto command = ConnectRequest{std::move(request->body)};

            Log::Info(L"Received: %ws", command.Describe().c_str());
            auto response = m_operations->HandleConnectRequest(command);

            Log::Info(L"Answering: %ws", response.Describe().c_str());
            responseMessage = ConnectResponse::ToMessage(std::move(response));

            break;
        }
        case WIFI_OP_DISCONNECT_REQUEST:
        {
            const auto command = DisconnectRequest{std::move(request->body)};
            Log::Info(L"Received: %ws", command.Describe().c_str());

            auto response = m_operations->HandleDisconnectRequest(command);
            Log::Info(L"Answering: %ws", response.Describe().c_str());

            responseMessage = DisconnectResponse::ToMessage(std::move(response));
            break;
        }
        default:
            THROW_WIN32_MSG(ERROR_INVALID_MESSAGE, "Ignoring unknown command ID: %d", request->hdr.operation);
        }

        Log::Trace(
            L"Answering with <%ws> (%d bytes)", GetProtocolMessageTypeName(responseMessage.hdr.operation), responseMessage.hdr.size);
        SendMessage(responseMessage);
    }
    catch (...)
    {
        // Inform the client there was an issue
        LOG_CAUGHT_EXCEPTION_MSG("Failed to process message, answering with an error message.");
        SendMessage({WIFI_INVALID, {}});
    }
}

ConnectionSocket::ConnectionSocket(wil::unique_socket socket, const std::shared_ptr<OperationHandler>& operations)
    : Connection(operations), m_socket(std::move(socket))
{
}

void ConnectionSocket::SendMessage(const Message& message)
{
    SendProxyWifiMessage(m_socket, message);
}

std::optional<Message> ConnectionSocket::ReceiveMessage()
{
    return ReceiveProxyWifiMessage(m_socket);
}

} // namespace ProxyWifi