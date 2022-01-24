// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h>
#include <wlanapi.h>

#include <catch2/catch.hpp>

/// Stubs for WlanApi
/// These stubs are needed to avoid linking the test executable against wlanapi.lib:
/// this caused it to load WlanApi.dll, which isn't present on server SKUs used by github CI runners
/// The stubs should never be called: `WlansvcWrapper` and `WlansvcFake` allows to never call into WlanApi for tests

extern "C" {

PVOID WINAPI WlanAllocateMemory(_In_ DWORD)
{
    INFO("WlanAllocateMemory stub called");
    REQUIRE(false);
    return NULL;
}

VOID WINAPI WlanFreeMemory(_In_ PVOID)
{
    INFO("WlanFreeMemory stub called");
    REQUIRE(false);
}

DWORD WINAPI WlanOpenHandle(_In_ DWORD, _Reserved_ PVOID, _Out_ PDWORD, _Out_ PHANDLE)
{
    INFO("WlanOpenHandle stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanCloseHandle(_In_ HANDLE, _Reserved_ PVOID)
{
    INFO("WlanCloseHandle stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanEnumInterfaces(_In_ HANDLE, _Reserved_ PVOID, _Outptr_ PWLAN_INTERFACE_INFO_LIST*)
{
    INFO("WlanEnumInterfaces stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanQueryInterface(
    _In_ HANDLE, _In_ CONST GUID*, _In_ WLAN_INTF_OPCODE, _Reserved_ PVOID, _Out_ PDWORD pdwDataSize, _Outptr_result_bytebuffer_(*pdwDataSize) PVOID*, _Out_opt_ PWLAN_OPCODE_VALUE_TYPE)
{
    (void)pdwDataSize;
    INFO("WlanQueryInterface stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanScan(_In_ HANDLE, _In_ CONST GUID*, _In_opt_ CONST PDOT11_SSID, _In_opt_ CONST PWLAN_RAW_DATA, _Reserved_ PVOID)
{
    INFO("WlanScan stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanGetAvailableNetworkList(_In_ HANDLE, _In_ CONST GUID*, _In_ DWORD, _Reserved_ PVOID, _Outptr_ PWLAN_AVAILABLE_NETWORK_LIST*)
{
    INFO("WlanGetAvailableNetworkList stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanGetNetworkBssList(_In_ HANDLE, _In_ CONST GUID*, _In_opt_ CONST PDOT11_SSID, _In_ DOT11_BSS_TYPE, _In_ BOOL, _Reserved_ PVOID, _Outptr_ PWLAN_BSS_LIST*)
{
    INFO("WlanGetNetworkBssList stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanConnect(_In_ HANDLE, _In_ CONST GUID*, _In_ CONST PWLAN_CONNECTION_PARAMETERS, _Reserved_ PVOID)
{
    INFO("WlanConnect stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanDisconnect(_In_ HANDLE, _In_ CONST GUID*, _Reserved_ PVOID)
{
    INFO("WlanDisconnect stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI WlanRegisterNotification(_In_ HANDLE, _In_ DWORD, _In_ BOOL, _In_opt_ WLAN_NOTIFICATION_CALLBACK, _In_opt_ PVOID, _Reserved_ PVOID, _Out_opt_ PDWORD)
{
    INFO("WlanRegisterNotification stub called");
    REQUIRE(false);
    return ERROR_CALL_NOT_IMPLEMENTED;
}
}