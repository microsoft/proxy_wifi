// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "ProxyWifi/Logs.hpp"

#include <array>
#include <wil/common.h>

#include "Tracelog.hpp"

namespace ProxyWifi::Log {

namespace {
    static constexpr std::array levelNames = {"Error", "Info", "Trace", "Debug"};

    constexpr const char* LevelToCStr(Level lvl) noexcept
    {
        return levelNames[WI_EnumValue(lvl)];
    }
} // namespace

void ConsoleLogger::Log(Level level, const wchar_t* message) noexcept
{
    printf_s("%hs: %ws\n", LevelToCStr(level), message);
}

void TraceLoggingLogger::Log(Level level, const wchar_t* message) noexcept
{
    switch (level)
    {
    case Level::Debug:
        TraceProvider::Debug(message);
        break;
    case Level::Trace:
        TraceProvider::Trace(message);
        break;
    case Level::Info:
        TraceProvider::Info(message);
        break;
    case Level::Error:
        TraceProvider::Error(message);
        break;
    }
}

} // namespace ProxyWifi::Log