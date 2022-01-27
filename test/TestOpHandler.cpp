// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <catch2/catch.hpp>
#include "OperationHandlerBuilder.hpp"

#include "StringUtils.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"
#include "Iee80211Utils.hpp"
#include "ProxyWifi/Logs.hpp"
#include "WlansvcMock.hpp"

#include <memory>
#include <chrono>

using namespace std::chrono_literals;
using namespace ProxyWifi;

// Setup helper functions
std::unique_ptr<OperationHandler> MakeUnitTestOperationHandler(ProxyWifiCallbacks callbacks, std::shared_ptr<Wlansvc::WlanApiWrapper> fakeWlansvc)
{
    return MakeWlansvcOperationHandler(fakeWlansvc, std::move(callbacks));
}

ConnectRequest MakeWpa2PskConnectRequest(const Ssid& ssid)
{
    const std::vector<uint8_t> key{'p', 'i', 'z', 'z', 'a'};
    const auto bodySize = sizeof(proxy_wifi_connect_request) + key.size();
    auto body = std::vector<uint8_t>(bodySize);
    auto connectRequest = reinterpret_cast<proxy_wifi_connect_request*>(body.data());

    connectRequest->ssid_len = ssid.size();
    std::copy_n(ssid.value().begin(), connectRequest->ssid_len, connectRequest->ssid);
    connectRequest->wpa_versions = 2;
    connectRequest->num_akm_suites = 1;
    connectRequest->akm_suites[0] = WI_EnumValue(AkmSuite::Psk);
    connectRequest->num_pairwise_cipher_suites = 1;
    connectRequest->pairwise_cipher_suites[0] = WI_EnumValue(CipherSuite::Ccmp);
    connectRequest->group_cipher_suite = WI_EnumValue(CipherSuite::Ccmp);
    connectRequest->key_len = wil::safe_cast<uint8_t>(key.size());
    std::copy(key.begin(), key.end(), connectRequest->key);

    return ConnectRequest{std::move(body)};
}

ConnectRequest MakeOpenConnectRequest(const Ssid& ssid)
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_connect_request));
    auto connectRequest = reinterpret_cast<proxy_wifi_connect_request*>(body.data());

    connectRequest->ssid_len = ssid.size();
    std::copy_n(ssid.value().begin(), connectRequest->ssid_len, connectRequest->ssid);
    connectRequest->wpa_versions = 0;
    connectRequest->num_akm_suites = 0;
    connectRequest->num_pairwise_cipher_suites = 0;
    connectRequest->key_len = 0;

    return ConnectRequest{std::move(body)};
}

DisconnectRequest MakeDisconnectRequest(uint32_t sessionId)
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_disconnect_request));
    auto disconnectRequest = reinterpret_cast<proxy_wifi_disconnect_request*>(body.data());
    disconnectRequest->session_id = sessionId;

    return DisconnectRequest{std::move(body)};
}

// Tests for WlansvcOperationHandler.cpp

TEST_CASE("The WlanApiWrapper is optionnal", "[wlansvcOpHandler]")
{
    auto opHandler = MakeWlansvcOperationHandler(std::shared_ptr<Wlansvc::WlanApiWrapper>{}, {});
    CHECK(opHandler);
}

TEST_CASE("Process a scan requests", "[wlansvcOpHandler]")
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));

    SECTION("No visible networks")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1});
        auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);
        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});

        CHECK(scanResponse->num_bss == 0);
        CHECK(scanResponse->total_size == 8);
    }

    SECTION("Report supported networks")
    {
        auto fakeWlansvc =
            std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});
        auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        CHECK(scanResponse->num_bss == 2);

        // The BSSID are correct
        CHECK(Mock::c_wpa2PskNetwork.bss.bssid == toBssid(scanResponse->bss[0].bssid));
        CHECK(Mock::c_openNetwork.bss.bssid == toBssid(scanResponse->bss[1].bssid));

        // The IE are correct
        gsl::span<uint8_t> ie0{
            reinterpret_cast<uint8_t*>(&scanResponse->bss[0]) + scanResponse->bss[0].ie_offset, scanResponse->bss[0].ie_size};
        CHECK(std::equal(ie0.begin(), ie0.end(), Mock::c_wpa2PskNetwork.bss.ies.begin(), Mock::c_wpa2PskNetwork.bss.ies.end()));

        gsl::span<uint8_t> ie1{
            reinterpret_cast<uint8_t*>(&scanResponse->bss[1]) + scanResponse->bss[1].ie_offset, scanResponse->bss[1].ie_size};
        CHECK(std::equal(ie1.begin(), ie1.end(), Mock::c_openNetwork.bss.ies.begin(), Mock::c_openNetwork.bss.ies.end()));
    }

    SECTION("Replace unsupported networks")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_enterpriseNetwork});
        auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});

        REQUIRE(scanResponse->num_bss == 1);
        CHECK(scanResponse->total_size == 65);
        CHECK(Mock::c_enterpriseNetwork.bss.bssid == toBssid(scanResponse->bss[0].bssid));

        // Check the ie are not the original ones, but are for a WPA2PSK network with the same SSID
        gsl::span<uint8_t> ie{
            reinterpret_cast<uint8_t*>(&scanResponse->bss[0]) + scanResponse->bss[0].ie_offset, scanResponse->bss[0].ie_size};
        CHECK(!std::equal(ie.begin(), ie.end(), Mock::c_enterpriseNetwork.bss.ies.begin(), Mock::c_enterpriseNetwork.bss.ies.end()));
        CHECK(
            std::search(
                ie.begin(),
                ie.end(),
                Mock::c_enterpriseNetwork.bss.ssid.value().cbegin(),
                Mock::c_enterpriseNetwork.bss.ssid.value().cend()) != ie.end());
        CHECK(std::search(ie.begin(), ie.end(), Mock::c_wpa2pskRsnIe.begin(), Mock::c_wpa2pskRsnIe.end()) != ie.end());
    }

    SECTION("Add client fake networks")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>();
        Ssid ssid{"ethernet"};
        DOT11_MAC_ADDRESS bssid{0, 0, 0, 0, 0, 1};

        auto opHandler = MakeUnitTestOperationHandler(
            {{},
             {},
             {},
             [&] {
                 return std::vector<WifiNetworkInfo>{{static_cast<DOT11_SSID>(ssid), bssid}};
             }},
            fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});

        REQUIRE(scanResponse->num_bss == 1);
        CHECK(scanResponse->total_size == 66);
        CHECK(toBssid(bssid) == toBssid(scanResponse->bss[0].bssid));
        // Check the ie are not the original ones, but are for a WPA2PSK network with the same SSID
        gsl::span<uint8_t> ie{
            reinterpret_cast<uint8_t*>(&scanResponse->bss[0]) + scanResponse->bss[0].ie_offset, scanResponse->bss[0].ie_size};
        CHECK(std::search(ie.begin(), ie.end(), ssid.value().begin(), ssid.value().end()) != ie.end());
        CHECK(std::search(ie.begin(), ie.end(), Mock::c_wpa2pskRsnIe.begin(), Mock::c_wpa2pskRsnIe.end()) != ie.end());
    }
}

TEST_CASE("Handle scan on multiple interfaces", "[wlansvcOpHandler][multiInterface]")
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));

    SECTION("No visible networks")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2});
        auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
    }
    SECTION("Scanned network are reported for all interfaces")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2});
        fakeWlansvc->AddNetwork(Mock::c_intf1, Mock::c_openNetwork);
        fakeWlansvc->AddNetwork(Mock::c_intf2, Mock::c_wpa2PskNetwork);
        auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        REQUIRE(scanResponse->num_bss == 2);
        CHECK(toBssid(scanResponse->bss[0].bssid) == Mock::c_openNetwork.bss.bssid);
        CHECK(toBssid(scanResponse->bss[1].bssid) == Mock::c_wpa2PskNetwork.bss.bssid);
    }

    SECTION("Bss scanned by both interfaces are reported only once")
    {
        auto fakeWlansvc =
            std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2}, std::vector{Mock::c_wpa2PskNetwork});
        fakeWlansvc->AddNetwork(Mock::c_intf1, Mock::c_openNetwork);
        auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        REQUIRE(scanResponse->num_bss == 2);
        CHECK(toBssid(scanResponse->bss[0].bssid) == Mock::c_wpa2PskNetwork.bss.bssid);
        CHECK(toBssid(scanResponse->bss[1].bssid) == Mock::c_openNetwork.bss.bssid);
    }

    SECTION("User provided networks take priority over real ones")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2});
        fakeWlansvc->AddNetwork(Mock::c_intf1, Mock::c_openNetwork);
        fakeWlansvc->AddNetwork(Mock::c_intf2, Mock::c_wpa2PskNetwork);

        Ssid ssid{"ethernet"};
        DOT11_MAC_ADDRESS bssid{};
        std::copy(Mock::c_wpa2PskNetwork.bss.bssid.cbegin(), Mock::c_wpa2PskNetwork.bss.bssid.cend(), bssid);

        auto opHandler = MakeUnitTestOperationHandler(
            {{},
             {},
             {},
             [&] {
                 return std::vector<WifiNetworkInfo>{{static_cast<DOT11_SSID>(ssid), bssid}};
             }},
            fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        REQUIRE(scanResponse->num_bss == 2);
        CHECK(toBssid(scanResponse->bss[0].bssid) == Mock::c_wpa2PskNetwork.bss.bssid);
        CHECK(toBssid(scanResponse->bss[1].bssid) == Mock::c_openNetwork.bss.bssid);
        // Check the SSID correspond to the user provided network
        gsl::span<uint8_t> ie{
            reinterpret_cast<uint8_t*>(&scanResponse->bss[0]) + scanResponse->bss[0].ie_offset, scanResponse->bss[0].ie_size};
        CHECK(std::search(ie.begin(), ie.end(), ssid.value().begin(), ssid.value().end()) != ie.end());
    }
}

TEST_CASE("Process a connection request")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);
    auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);

    // Guest connection request on new network result in call to wlansvc
    SECTION("Guest new connection request connect the host")
    {
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->session_id == 1);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(toBssid(connectResponse->bssid) == Mock::c_wpa2PskNetwork.bss.bssid);
        CHECK(fakeWlansvc->callCount.connect == 1);
    }

    SECTION("Guest reflecting the host connection request is a no-op")
    {
        // The host connects
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        // The proxy receive a request to mirror the connection
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->session_id == 1);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(toBssid(connectResponse->bssid) == Mock::c_wpa2PskNetwork.bss.bssid);
        CHECK(fakeWlansvc->callCount.connect == 0);
    }
}

TEST_CASE("Handle connect requests with multiple interfaces", "[wlansvcOpHandler][multiInterface]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2}, std::vector{Mock::c_pizzaNetwork});
    fakeWlansvc->AddNetwork(Mock::c_intf1, Mock::c_openNetwork);
    fakeWlansvc->AddNetwork(Mock::c_intf2, Mock::c_wpa2PskNetwork);

    DOT11_MAC_ADDRESS bssid{0, 0, 0, 0, 0, 1};
    auto opHandler = MakeUnitTestOperationHandler(
        {{},
         {},
         {},
         [&] {
             return std::vector<WifiNetworkInfo>{{Mock::c_pizzaNetwork.network.dot11Ssid, bssid}};
         }},
        fakeWlansvc);

    SECTION("First interface can connect")
    {
        auto connectRequest = MakeOpenConnectRequest(Mock::c_openNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->session_id == 1);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(fakeWlansvc->callCount.connect == 1);
    }

    SECTION("Second interface is used when first fails")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->session_id == 1);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        // Interface 1 must try to connect and fail, then interface 2 must succeed
        CHECK(fakeWlansvc->callCount.connect == 2);
    }

    SECTION("User networks take priority")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_pizzaNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->session_id == 1);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        // No wlansvc connect call: the user network must be used
        CHECK(fakeWlansvc->callCount.connect == 0);
    }
}

TEST_CASE("Process a disconnect request", "[wlansvcOpHandler]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
    auto disconnectRequest = MakeDisconnectRequest(1);

    // Guest connection request on new network result in call to wlansvc
    SECTION("Disconnect the host if the network was connected by the guest")
    {
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->session_id == 1);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(fakeWlansvc->callCount.connect == 1);
        CHECK(fakeWlansvc->callCount.disconnect == 0);

        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        CHECK(fakeWlansvc->callCount.disconnect == 1);
    }

    SECTION("No-op if the network was connected by the host")
    {
        // The host connects
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        // The proxy receive a request to mirror the connection
        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        CHECK(fakeWlansvc->callCount.connect == 0);
        CHECK(fakeWlansvc->callCount.disconnect == 0);
    }

    SECTION("No-op if the network was reflected by the guest")
    {

        // The host connects
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(fakeWlansvc->callCount.connect == 0);
        CHECK(fakeWlansvc->callCount.disconnect == 0);

        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        CHECK(fakeWlansvc->callCount.connect == 0);
        CHECK(fakeWlansvc->callCount.disconnect == 0);
    }

    SECTION("No-op if the network session id was expired")
    {
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(connectResponse->session_id == 1);
        CHECK(fakeWlansvc->callCount.connect == 1);
        CHECK(fakeWlansvc->callCount.disconnect == 0);

        disconnectRequest->session_id = 0;
        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        CHECK(fakeWlansvc->callCount.connect == 1);
        CHECK(fakeWlansvc->callCount.disconnect == 0);
    }
}

TEST_CASE("Handle disconnect requests with multiple interfaces", "[wlansvcOpHandler][multiInterface]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2}, std::vector{Mock::c_wpa2PskNetwork});

    Ssid ssid{"ethernet"};
    DOT11_MAC_ADDRESS bssid{0, 0, 0, 0, 0, 1};
    auto opHandler = MakeUnitTestOperationHandler(
        {{},
         {},
         {},
         [&] {
             return std::vector<WifiNetworkInfo>{{static_cast<DOT11_SSID>(ssid), bssid}};
         }},
        fakeWlansvc);

    SECTION("Only disconnect the guest connected interface")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));

        fakeWlansvc->ConnectHost(Mock::c_intf2, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        auto disconnectResponse = opHandler->HandleDisconnectRequest(MakeDisconnectRequest(1));
        CHECK(fakeWlansvc->callCount.disconnect == 1);
        CHECK(fakeWlansvc->GetCurrentConnection(Mock::c_intf1).isState == wlan_interface_state_disconnected);
        CHECK(fakeWlansvc->GetCurrentConnection(Mock::c_intf2).isState == wlan_interface_state_connected);
    }

    SECTION("Don't disconnect the host when connected to a user network")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));

        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        auto disconnectResponse = opHandler->HandleDisconnectRequest(MakeDisconnectRequest(1));
        CHECK(fakeWlansvc->callCount.disconnect == 0);
        CHECK(fakeWlansvc->GetCurrentConnection(Mock::c_intf1).isState == wlan_interface_state_connected);
    }
}

TEST_CASE("Notify client on host connection and disconnection", "[wlansvcOpHandler]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});

    int hostConnect = 0;
    int guestConnect = 0;
    int hostDisconnect = 0;
    int guestDisconnect = 0;
    auto opHandler = MakeUnitTestOperationHandler(
        {[&](auto origin, auto) { origin == EventSource::Host ? ++hostConnect : ++guestConnect; },
         [&](auto origin, auto) { origin == EventSource::Host ? ++hostDisconnect : ++guestDisconnect; },
         {},
         {}},
        fakeWlansvc);

    auto connectRequest = MakeOpenConnectRequest(Mock::c_openNetwork.bss.ssid);
    auto disconnectRequest = MakeDisconnectRequest(1);

    // Guest connection request on new network result in call to wlansvc
    SECTION("Notifications on guest initiated operations")
    {
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(fakeWlansvc->callCount.connect == 1);
        CHECK(hostConnect == 1);
        CHECK(guestConnect == 1);
        CHECK(hostDisconnect == 0);
        CHECK(guestDisconnect == 0);

        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        CHECK(fakeWlansvc->callCount.disconnect == 1);
        CHECK(hostConnect == 1);
        CHECK(guestConnect == 1);
        CHECK(hostDisconnect == 1);
        CHECK(guestDisconnect == 1);
    }

    SECTION("Notifications on host initiated operations")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        CHECK(hostConnect == 1);
        CHECK(guestConnect == 0);
        CHECK(hostDisconnect == 0);
        CHECK(guestDisconnect == 0);

        fakeWlansvc->DisconnectHost(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();

        CHECK(hostConnect == 1);
        CHECK(guestConnect == 0);
        CHECK(hostDisconnect == 1);
        CHECK(guestDisconnect == 0);
    }

    SECTION("Notifications on mirroring operations")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_openNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        CHECK(hostConnect == 1);
        CHECK(guestConnect == 0);
        CHECK(hostDisconnect == 0);
        CHECK(guestDisconnect == 0);

        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(fakeWlansvc->callCount.connect == 0);
        CHECK(hostConnect == 1);
        CHECK(guestConnect == 1);
        CHECK(hostDisconnect == 0);
        CHECK(guestDisconnect == 0);

        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        CHECK(fakeWlansvc->callCount.disconnect == 0);
        CHECK(hostConnect == 1);
        CHECK(guestConnect == 1);
        CHECK(hostDisconnect == 0);
        CHECK(guestDisconnect == 1);

        fakeWlansvc->DisconnectHost(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();

        CHECK(hostConnect == 1);
        CHECK(guestConnect == 1);
        CHECK(hostDisconnect == 1);
        CHECK(guestDisconnect == 1);
    }
}

TEST_CASE("Provide the authentication algorithm on host connections", "[wlansvcOpHandler]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork, Mock::c_enterpriseNetwork});

    std::vector<std::pair<EventSource, OnConnectionArgs>> notifParams;
    auto opHandler = MakeUnitTestOperationHandler({[&](auto origin, auto p) { notifParams.push_back({origin, p}); }, {}, {}, {}}, fakeWlansvc);


    SECTION("Correct auth algo for host wpa2psk connection")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        REQUIRE(notifParams.size() == 1);
        CHECK(notifParams[0].first == EventSource::Host);
        CHECK(notifParams[0].second.authAlgo == DOT11_AUTH_ALGO_RSNA_PSK);
    }

    SECTION("Correct auth algo for host open connection")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_openNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        REQUIRE(notifParams.size() == 1);
        CHECK(notifParams[0].first == EventSource::Host);
        CHECK(notifParams[0].second.authAlgo == DOT11_AUTH_ALGO_80211_OPEN);
    }

    SECTION("Auth algo is adapted to what the guest sees")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_enterpriseNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        REQUIRE(notifParams.size() == 1);
        CHECK(notifParams[0].first == EventSource::Host);
        CHECK(notifParams[0].second.authAlgo == DOT11_AUTH_ALGO_RSNA_PSK);
    }

    SECTION("Correct auth algo for guest connection")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        REQUIRE(notifParams.size() == 2);
        CHECK(notifParams[0].first == EventSource::Host);
        CHECK(notifParams[0].second.authAlgo == DOT11_AUTH_ALGO_RSNA_PSK);
        CHECK(notifParams[1].first == EventSource::Guest);
        CHECK(notifParams[1].second.authAlgo == DOT11_AUTH_ALGO_RSNA_PSK);
    }
}

TEST_CASE("Notify client for guest directed connection progress", "[wlansvcOpHandler]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});

    auto starting = 0;
    auto succeeded = 0;
    auto opHandler = MakeUnitTestOperationHandler(
        {{},
         {},
         [&](auto status) {
             if (status == GuestConnectStatus::Starting)
             {
                 ++starting;
             }
             else if (status == GuestConnectStatus::Succeeded)
             {
                 ++succeeded;
             }
             else
             {
                 CHECK(false);
             }
         },
         {}},
        fakeWlansvc);

    auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
    auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
    CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
    CHECK(fakeWlansvc->callCount.connect == 1);
    CHECK(starting == 1);
    CHECK(succeeded == 1);
}

TEST_CASE("Notification for guest directed connection are in order", "[wlansvcOpHandler]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});

    enum class TestNotif
    {
        HostConnected,
        GuestConnected,
        ConnectStarting,
        ConnectSucceeded,
    };
    std::vector<TestNotif> notifs;
    auto opHandler = MakeUnitTestOperationHandler(
        {[&](auto origin, auto) { notifs.push_back(origin == EventSource::Host ? TestNotif::HostConnected : TestNotif::GuestConnected); },
         {},
         [&](auto status) { notifs.push_back(status == GuestConnectStatus::Starting ? TestNotif::ConnectStarting : TestNotif::ConnectSucceeded); },
         {}},
        fakeWlansvc);

    auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
    auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
    CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
    CHECK(fakeWlansvc->callCount.connect == 1);
    CHECK(notifs == std::vector{TestNotif::ConnectStarting, TestNotif::HostConnected, TestNotif::GuestConnected, TestNotif::ConnectSucceeded});
}

TEST_CASE("Notify client for initially connected networks", "[wlansvcOpHandler]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});

    fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
    fakeWlansvc->WaitForNotifComplete();

    int hostConnect = 0;
    int guestConnect = 0;
    int hostDisconnect = 0;
    int guestDisconnect = 0;
    auto opHandler = MakeUnitTestOperationHandler(
        {[&](auto origin, auto) { origin == EventSource::Host ? ++hostConnect : ++guestConnect; },
         [&](auto origin, auto) { origin == EventSource::Host ? ++hostDisconnect : ++guestDisconnect; },
         {},
         {}},
        fakeWlansvc);

    CHECK(hostConnect == 1);
    CHECK(guestConnect == 0);
    CHECK(hostDisconnect == 0);
    CHECK(guestDisconnect == 0);
}

TEST_CASE("Handle graciously non-expected wlansvc notifications", "[wlansvcOpHandler")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    SECTION("Do crash on spontaneous scan complete notification")
    {
        fakeWlansvc->Scan(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();
    }

    SECTION("Do crash on spontaneous connection complete notification")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
    }
}

TEST_CASE("Don't notify guest on host disconnection", "[wlansvcOpHandler]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    auto callCount = 0;
    // An event is needed (and not only `WaitForNotifComplete`) since the callback is
    // called async in the operation handler workqueue
    wil::slim_event disconnectNotifDone;
    uint64_t sessionId = 0;

    opHandler->RegisterGuestNotificationCallback([&](auto notif) {
        ++callCount;
        REQUIRE(std::holds_alternative<DisconnectNotif>(notif));
        const auto& disconnectNotif = std::get<DisconnectNotif>(notif);
        CHECK(disconnectNotif->session_id == sessionId);
        disconnectNotifDone.SetEvent();
    });

    SECTION("Ignore notification on non-connected interface")
    {
        // Connect only the host, not the guest
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        fakeWlansvc->DisconnectHost(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();
        CHECK(!disconnectNotifDone.wait(10));
        CHECK(callCount == 0);
    }

    SECTION("Also ignore notification on connected interface")
    {
        const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        REQUIRE(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        sessionId = connectResponse->session_id;

        fakeWlansvc->DisconnectHost(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();
        CHECK(!disconnectNotifDone.wait(10));
        CHECK(callCount == 0);
    }
}

TEST_CASE("Notify guest on signal quality change", "[wlansvcOpHandler]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    unsigned long signalQuality = 80;
    int8_t rssi = -60; // (rssi + 100) * 2 = signalQuality
    auto callCount = 0;
    // An event is needed (and not only `WaitForNotifComplete`) since the callback is
    // called async in the operation handler workqueue
    wil::slim_event signalNotifDone;

    opHandler->RegisterGuestNotificationCallback([&](auto notif) {
        ++callCount;
        REQUIRE(std::holds_alternative<SignalQualityNotif>(notif));
        const auto& signalNotif = std::get<SignalQualityNotif>(notif);
        CHECK(signalNotif->signal == rssi);
        signalNotifDone.SetEvent();
    });

    SECTION("Ignore notification when disconnected")
    {
        fakeWlansvc->SetSignalQuality(Mock::c_intf1, signalQuality);
        fakeWlansvc->WaitForNotifComplete();
        CHECK(!signalNotifDone.wait(10));
        CHECK(callCount == 0);
    }

    SECTION("Forward notification when connected")
    {
        const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        REQUIRE(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));

        fakeWlansvc->SetSignalQuality(Mock::c_intf1, signalQuality);
        fakeWlansvc->WaitForNotifComplete();
        CHECK(signalNotifDone.wait(50));
        CHECK(callCount == 1);
    }
}

TEST_CASE("Ignore notification from other interfaces", "[wlansvcOpHandler][multiInterface]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2}, std::vector{Mock::c_wpa2PskNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    unsigned long signalQuality = 80;
    int8_t rssi = -60; // (rssi + 100) * 2 = signalQuality
    auto callCount = 0;
    // An event is needed (and not only `WaitForNotifComplete`) since the callback is
    // called async in the operation handler workqueue
    wil::slim_event signalNotifDone;

    opHandler->RegisterGuestNotificationCallback([&](auto notif) {
        ++callCount;
        REQUIRE(std::holds_alternative<SignalQualityNotif>(notif));
        const auto& signalNotif = std::get<SignalQualityNotif>(notif);
        CHECK(signalNotif->signal == rssi);
        signalNotifDone.SetEvent();
    });

    SECTION("Ignore notification on the non-connected interface")
    {
        const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);

        fakeWlansvc->ConnectHost(Mock::c_intf2, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        fakeWlansvc->SetSignalQuality(Mock::c_intf2, signalQuality);
        fakeWlansvc->WaitForNotifComplete();

        CHECK(!signalNotifDone.wait(10));
        CHECK(callCount == 0);
    }

    SECTION("Forward notification on the connected interface")
    {
        const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);

        fakeWlansvc->ConnectHost(Mock::c_intf2, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        fakeWlansvc->SetSignalQuality(Mock::c_intf1, signalQuality);
        fakeWlansvc->WaitForNotifComplete();

        CHECK(signalNotifDone.wait(50));
        CHECK(callCount == 1);
    }
}

TEST_CASE("Notifications for fake networks use FakeInterfaceGuid")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>();

    DOT11_MAC_ADDRESS bssid{0, 0, 0, 0, 0, 1};
    auto origin = EventSource::Host;
    auto guid = GUID{};

    auto opHandler = MakeUnitTestOperationHandler(
        {[&](auto o, auto a) {
             origin = o;
             guid = a.interfaceGuid;
         },
         [&](auto o, auto a) {
             origin = o;
             guid = a.interfaceGuid;
         },
         {},
         [&] {
             return std::vector<WifiNetworkInfo>{{Mock::c_pizzaNetwork.network.dot11Ssid, bssid}};
         }},
        fakeWlansvc);

    auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_pizzaNetwork.bss.ssid);
    auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
    CHECK(origin == EventSource::Guest);
    CHECK(guid == FakeInterfaceGuid);

    auto disconnectRequest = MakeDisconnectRequest(1);
    auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
    CHECK(origin == EventSource::Guest);
    CHECK(guid == FakeInterfaceGuid);
}

TEST_CASE("Handle interface arrival", "[wlansvcOpHandler][multiInterface]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>();
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    fakeWlansvc->AddInterface(Mock::c_intf2);
    fakeWlansvc->AddNetwork(Mock::c_intf2, Mock::c_wpa2PskNetwork);
    fakeWlansvc->WaitForNotifComplete();

    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));
    auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});

    // Indirectly check that the interface has been added and is in use
    CHECK(scanResponse->num_bss == 1);
}

TEST_CASE("Handle interface departure", "[wlansvcOpHandler][multiInterface]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});
    auto opHandler = MakeUnitTestOperationHandler({}, fakeWlansvc);

    fakeWlansvc->RemoveInterface(Mock::c_intf1);
    fakeWlansvc->WaitForNotifComplete();

    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));
    auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});

    // Indirectly check that the interface is no longer present
    CHECK(scanResponse->num_bss == 0);
}