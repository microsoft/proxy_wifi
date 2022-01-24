// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <cstring>
#include <rpc.h>
#include <guiddef.h>

namespace std {
template <>
struct hash<GUID>
{
    std::size_t operator()(const GUID& guid) const noexcept
    {
        RPC_STATUS status = RPC_S_OK;
        return ::UuidHash(&const_cast<GUID&>(guid), &status);
    }
};
} // namespace std

inline bool operator<(const GUID& lhs, const GUID& rhs)
{
    return memcmp(&lhs, &rhs, sizeof lhs) < 0;
}