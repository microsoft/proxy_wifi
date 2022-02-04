// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include <Windows.h>
#include <wlantypes.h>

#include <future>
#include <optional>
#include <vector>

#include "Networks.hpp"
#include "Iee80211Utils.hpp"

namespace ProxyWifi {

/// @brief Interface for classes that implementents the callbacks called by an `IWlanInterface`
class INotificationHandler
{
public:
    virtual ~INotificationHandler() = default;

    /// @brief Must be called by the interfaces when they connect to a network
    virtual void OnHostConnection(const GUID& interfaceGuid, const Ssid& ssid, DOT11_AUTH_ALGORITHM authAlgo) = 0;

    /// @brief Must be called by the interfaces when they disconnect to a network
    virtual void OnHostDisconnection(const GUID& interfaceGuid, const Ssid& ssid) = 0;

    /// @brief Must be called by the interfaces when the signal quality changes
    virtual void OnHostSignalQualityChange(const GUID& interfaceGuid, unsigned long signalQuality) = 0;

    /// @brief Must be called by the interfaces when scan results are availables
    virtual void OnHostScanResults(const GUID& interfaceGuid, const std::vector<ScannedBss>& scannedBss, ScanStatus status) = 0;
};

/// @brief Interface for classes representing a wlan interface (real or simulated)
/// An `OperationHandler` will use this interface to dispatch requests to the interfaces and collect the results
class IWlanInterface
{
public:
    virtual ~IWlanInterface() = default;

    /// @brief Allows to provide the callback the interface will call on specific events
    virtual void SetNotificationHandler(INotificationHandler* notificationHandler) = 0;

    /// @brief Access the interface GUID (unique identifier)
    virtual const GUID& GetGuid() const noexcept = 0;

    /// @brief Indicate whether the interface is connected to a specific network
    /// @param requestedSsid The Ssid of the network
    /// @return the BSSID of the connected BSS if it is connected to the requested network, std::nulopt otherwise
    virtual std::optional<ConnectedNetwork> IsConnectedTo(const Ssid& requestedSsid) noexcept = 0;

    /// @brief Request that the interface connect to a specific network
    /// @param requestedSsid The Ssid of the network to connect to
    /// @param bssid The bss to connect to. Ignored if all zeros.
    /// @param securityInfo The authencation, cipher, key... to use for the connection
    /// @return A future indicating whether the connection was successful or not and the connected network when it is ready
    virtual std::future<std::pair<WlanStatus, ConnectedNetwork>> Connect(const Ssid& requestedSsid, const Bssid& bssid, const WlanSecurity& securityInfo) = 0;

    /// @brief Request that the interface disconnect
    /// @return A future indicating when the disconnection is complete
    virtual std::future<void> Disconnect() = 0;

    /// @brief Request that the interface schedule a scan
    /// @param ssid The if present, request a targeted scan on this ssid (needed to scan hidden networks)
    /// @return A future containing the current scan results, and whether the scan is still running
    virtual std::future<std::pair<std::vector<ScannedBss>, ScanStatus>> Scan(std::optional<const Ssid>& ssid) = 0;
};


} // namespace ProxyWifi