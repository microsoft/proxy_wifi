// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <wil/result.h>
#include "ProxyWifi/Logs.hpp"

namespace ProxyWifi {

/// @brief Add a WIL failure callback for the current thread.
/// This allows to log messages from WIL macro and exceptions
inline auto SetThreadWilFailureLogger()
{
    return wil::ThreadFailureCallback([](const wil::FailureInfo& failure) noexcept {
        constexpr std::size_t sizeOfLogMessageWithNul = 2048;

        wchar_t logMessage[sizeOfLogMessageWithNul]{};
        wil::GetFailureLogString(logMessage, sizeOfLogMessageWithNul, failure);
        Log::WilFailure(logMessage);
        return false; // This doesn't report any telemetry
    });
}

} // namespace ProxyWifi