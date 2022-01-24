// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <wil/Tracelogging.h>

namespace ProxyWifi::Log {

#if MICROSOFT_TELEMETRY
#define IMPLEMENT_TRACELOGGING_CLASS_WRAP IMPLEMENT_TRACELOGGING_CLASS_WITH_MICROSOFT_TELEMETRY
#else
#define IMPLEMENT_TRACELOGGING_CLASS_WRAP IMPLEMENT_TRACELOGGING_CLASS_WITHOUT_TELEMETRY
#endif

/// @brief Tracelogging provider
///
/// It should be used directly only for structured logs (telemetry, performances...)
/// For logs that will be read, use the helper functions and WIL error helpers
class TraceProvider : public wil::TraceLoggingProvider
{
    IMPLEMENT_TRACELOGGING_CLASS_WRAP(
        TraceProvider,
        "Microsoft.WslCore.ProxyWifi",
        // 872a70db-e765-45e5-9141-4b35732837b6
        (0x872a70db, 0xe765, 0x45e5, 0x91, 0x41, 0x4b, 0x35, 0x73, 0x28, 0x37, 0xb6));

    DEFINE_TRACELOGGING_EVENT_STRING(Debug, Log, TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE));
    DEFINE_TRACELOGGING_EVENT_STRING(Trace, Log, TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE));
    DEFINE_TRACELOGGING_EVENT_STRING(Info, Log, TraceLoggingLevel(WINEVENT_LEVEL_INFO));
    DEFINE_TRACELOGGING_EVENT_STRING(Error, Log, TraceLoggingLevel(WINEVENT_LEVEL_ERROR));
};

} // namespace ProxyWifi::Log