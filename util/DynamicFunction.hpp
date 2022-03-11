// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <libloaderapi.h>
#include <wil/resource.h>
#include <functional>

template <class T>
class DynamicFunction;

/// @brief Wrapper for a runtime dynamically loaded function
template <class R, class... Args>
class DynamicFunction<R(Args...)>
{
public:
    DynamicFunction(const std::wstring& moduleName, const std::string& functionName)
        : m_module{LoadModule(moduleName)}, m_function{LoadFunction(m_module, functionName)}
    {
    }

    decltype(auto) operator()(Args... args) const
    {
        return m_function(std::forward<Args>(args)...);
    }

private:
    static wil::unique_hmodule LoadModule(const std::wstring& name)
    {
        wil::unique_hmodule module{LoadLibraryEx(name.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)};
        THROW_LAST_ERROR_IF(!module);
        return module;
    }

    static std::function<R(Args...)> LoadFunction(const wil::unique_hmodule& module, const std::string& name)
    {
        std::function<R(Args...)> function = reinterpret_cast<R (*)(Args...)>(GetProcAddress(module.get(), name.c_str()));
        THROW_LAST_ERROR_IF(!function);
        return function;
    }

private:
    wil::unique_hmodule m_module;
    std::function<R(Args...)> m_function;
};