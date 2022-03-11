// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <memory>
#include <vector>

namespace ProxyWifi::Log {

enum class Level
{
    Error,
    Info,
    Trace,
    Debug
};

/// @brief Interface to implement for defining a new log output target
class Logger
{
public:
    virtual void Log(Level level, const wchar_t* message) noexcept = 0;
    virtual ~Logger() = default;
};

/// @brief Logger printing to the standard console output
class ConsoleLogger : public Logger
{
public:
    void Log(Level level, const wchar_t* message) noexcept override;
};

/// @brief Logger generating Tracelogging events
class TraceLoggingLogger : public Logger
{
public:
    void Log(Level level, const wchar_t* message) noexcept override;
};

namespace Details {

    /// @brief `LogManager` formats log messages and dispatch them to a list of `Logger`s
    ///
    /// It is built as a singleton and should be accessed through a set of helper functions
    class LogManager
    {
    public:
        LogManager(const LogManager&) = delete;
        LogManager(LogManager&&) = delete;
        LogManager& operator=(const LogManager&) = delete;
        LogManager& operator=(LogManager&&) = delete;

        static LogManager& Get() noexcept
        {
            static LogManager defaultLogger{};
            return defaultLogger;
        }

        void AddLogger(std::unique_ptr<Logger> logger)
        {
            m_loggers.emplace_back(std::move(logger));
        }

        template <class... T>
        inline void Log(Level level, const wchar_t* format, T&&... args) const noexcept
        {
            // Ensure only funadamental types or pointer to fundamental types are used
            // Because of the indirection, the compiler doesn't check the format,
            // this at least check parameters have been converted to a fundamental type or C-string.
            static_assert(all(std::is_fundamental_v<std::remove_pointer_t<std::decay_t<T>>>...));

            wchar_t message[2048]{};
            swprintf_s(message, format, std::forward<T>(args)...);

            for (auto& logger : m_loggers)
            {
                logger->Log(level, message);
            }
        }

    private:
        std::vector<std::unique_ptr<Logger>> m_loggers;
        LogManager() = default;

        template<typename... Args>
        static constexpr bool all(Args... args) { return (... && args); }
    };

} // namespace Details

inline void AddLogger(std::unique_ptr<Logger> logger)
{
    Details::LogManager::Get().AddLogger(std::move(logger));
}

/// @brief Handler for WIL reported failures
/// There is intentionaly no function for "Error" level logs: they should be reported through WIL error handlers
inline void WilFailure(const wchar_t* message)
{
    Details::LogManager::Get().Log(Level::Error, L"%ws", message);
}

template <class... T>
inline void Info(const wchar_t* format, T&&... args)
{
    Details::LogManager::Get().Log(Level::Info, format, std::forward<T>(args)...);
}

template <class... T>
inline void Trace(const wchar_t* format, T&&... args)
{
    Details::LogManager::Get().Log(Level::Trace, format, std::forward<T>(args)...);
}

template <class... T>
inline void Debug(const wchar_t* format, T&&... args)
{
    Details::LogManager::Get().Log(Level::Debug, format, std::forward<T>(args)...);
}
} // namespace ProxyWifi::Log