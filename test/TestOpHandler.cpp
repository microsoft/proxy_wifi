// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <catch2/catch.hpp>
#include "OperationHandlerBuilder.hpp"

#include "StringUtils.hpp"
#include "ProxyWifi/ProxyWifiService.hpp"
#include "Iee80211Utils.hpp"
#include "WlansvcMock.hpp"

#include <memory>
#include <chrono>

using namespace std::chrono_literals;
using namespace ProxyWifi;

// Setup helper functions
std::unique_ptr<OperationHandler> MakeUnitTestOperationHandler(
    std::shared_ptr<Wlansvc::WlanApiWrapper> fakeWlansvc, FakeNetworkProvider provider = {}, ProxyWifiObserver* pObserver = nullptr)
{
    return MakeWlansvcOperationHandler(std::move(fakeWlansvc), std::move(provider), pObserver);
}

ConnectRequest MakeWpa2PskConnectRequest(const Ssid& ssid)
{
    const std::vector<uint8_t> key{'p', 'i', 'z', 'z', 'a'};
    const auto bodySize = sizeof(proxy_wifi_connect_request) + key.size();
    auto body = std::vector<uint8_t>(bodySize);
    const auto connectRequest = reinterpret_cast<proxy_wifi_connect_request*>(body.data());

    connectRequest->ssid_len = ssid.size();
    std::copy_n(ssid.value().begin(), connectRequest->ssid_len, connectRequest->ssid);
    connectRequest->wpa_versions = 2;
    connectRequest->num_akm_suites = 1;
    connectRequest->akm_suites[0] = WI_EnumValue(AkmSuite::Psk);
    connectRequest->num_pairwise_cipher_suites = 1;
    connectRequest->pairwise_cipher_suites[0] = WI_EnumValue(CipherSuite::Ccmp);
    connectRequest->group_cipher_suite = WI_EnumValue(CipherSuite::Ccmp);
    connectRequest->key_len = wil::safe_cast<uint8_t>(key.size());
    std::ranges::copy(key, connectRequest->key);

    return ConnectRequest{std::move(body)};
}

ConnectRequest MakeOpenConnectRequest(const Ssid& ssid)
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_connect_request));
    const auto connectRequest = reinterpret_cast<proxy_wifi_connect_request*>(body.data());

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
    const auto disconnectRequest = reinterpret_cast<proxy_wifi_disconnect_request*>(body.data());
    disconnectRequest->session_id = sessionId;

    return DisconnectRequest{std::move(body)};
}

// Tests for WlansvcOperationHandler.cpp

TEST_CASE("Process a scan requests", "[wlansvcOpHandler]")
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));

    SECTION("No visible networks")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1});
        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        CHECK(scanResponse->num_bss == 0);
        CHECK(scanResponse->total_size == 9);
        CHECK(scanResponse->scan_complete == 1);
    }

    SECTION("Report supported networks")
    {
        auto fakeWlansvc =
            std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});
        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

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
        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        REQUIRE(scanResponse->num_bss == 1);
        CHECK(scanResponse->total_size == 66);
        CHECK(scanResponse->scan_complete == 1);
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

        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, [&] {
            return std::vector<WifiNetworkInfo>{{static_cast<DOT11_SSID>(ssid), bssid}};
        });

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        REQUIRE(scanResponse->num_bss == 1);
        CHECK(scanResponse->total_size == 67);
        CHECK(scanResponse->scan_complete == 1);
        CHECK(toBssid(bssid) == toBssid(scanResponse->bss[0].bssid));
        // Check the ie are not the original ones, but are for a WPA2PSK network with the same SSID
        gsl::span<uint8_t> ie{
            reinterpret_cast<uint8_t*>(&scanResponse->bss[0]) + scanResponse->bss[0].ie_offset, scanResponse->bss[0].ie_size};
        CHECK(std::search(ie.begin(), ie.end(), ssid.value().begin(), ssid.value().end()) != ie.end());
        CHECK(std::search(ie.begin(), ie.end(), Mock::c_wpa2pskRsnIe.begin(), Mock::c_wpa2pskRsnIe.end()) != ie.end());
    }
}

TEST_CASE("Handle an async scan request", "[wlansvcOpHandler][multiInterface]")
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));

    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});
    // This network won't be cached by the interface until a scan
    fakeWlansvc->AddNetwork(Mock::c_openNetwork);
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    ProxyWifi::OperationHandler::GuestNotificationTypes notif{SignalQualityNotif{42}};
    auto notifSent = 0;
    opHandler->RegisterGuestNotificationCallback([&](auto n) {
        ++notifSent;
        notif = n;
    });

    SECTION("Don't wait for scan completion on a first request")
    {
        // Block the scan completion notification
        fakeWlansvc->BlockNotifications();
        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{body});

        CHECK(scanResponse->num_bss == 1);
        CHECK(scanResponse->scan_complete == 1);
        CHECK(fakeWlansvc->callCount.scan == 1);

        fakeWlansvc->UnblockNotifications();
        fakeWlansvc->WaitForNotifComplete();
    }

    SECTION("Send non-cached results in a notification")
    {
        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        CHECK(scanResponse->num_bss == 1);
        CHECK(scanResponse->scan_complete == 1);
        CHECK(fakeWlansvc->callCount.scan == 1);

        CHECK(notifSent == 1);
        REQUIRE(std::holds_alternative<ScanResponse>(notif));
        CHECK(std::get<ScanResponse>(notif)->num_bss == 2);
        CHECK(std::get<ScanResponse>(notif)->scan_complete == 1);
    }

    SECTION("Wait for results when a scan is already requested")
    {
        // Delay notifications to make sure the second request gets in before the scan completion is notified
        fakeWlansvc->BlockNotifications(10 /* ms */);
        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{body});
        CHECK(fakeWlansvc->callCount.scan == 1);

        auto scanResponse2 = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        CHECK(scanResponse->num_bss == 1);
        CHECK(scanResponse->scan_complete == 1);
        CHECK(fakeWlansvc->callCount.scan == 1);

        // The second request got the scan results and no notification was sent
        CHECK(notifSent == 0);
        CHECK(scanResponse2->num_bss == 2);
        CHECK(scanResponse2->scan_complete == 1);
    }
}

TEST_CASE("Handle scan on multiple interfaces", "[wlansvcOpHandler][multiInterface]")
{
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));

    SECTION("No visible networks")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2});
        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        CHECK(scanResponse->num_bss == 0);
        CHECK(scanResponse->total_size == 9);
        CHECK(scanResponse->scan_complete == 1);
    }
    SECTION("Scanned network are reported for all interfaces")
    {
        auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2});
        fakeWlansvc->AddNetwork(Mock::c_intf1, Mock::c_openNetwork);
        fakeWlansvc->AddNetwork(Mock::c_intf2, Mock::c_wpa2PskNetwork);
        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        REQUIRE(scanResponse->num_bss == 2);
        CHECK(toBssid(scanResponse->bss[0].bssid) == Mock::c_openNetwork.bss.bssid);
        CHECK(toBssid(scanResponse->bss[1].bssid) == Mock::c_wpa2PskNetwork.bss.bssid);
    }

    SECTION("Bss scanned by both interfaces are reported only once")
    {
        auto fakeWlansvc =
            std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2}, std::vector{Mock::c_wpa2PskNetwork});
        fakeWlansvc->AddNetwork(Mock::c_intf1, Mock::c_openNetwork);
        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

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
        std::ranges::copy(Mock::c_wpa2PskNetwork.bss.bssid, bssid);

        auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, [&] {
            return std::vector<WifiNetworkInfo>{{static_cast<DOT11_SSID>(ssid), bssid}};
        });

        auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

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
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);
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
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, [&] {
        return std::vector<WifiNetworkInfo>{{Mock::c_pizzaNetwork.network.dot11Ssid, bssid}};
    });

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
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
    auto disconnectRequest = MakeDisconnectRequest(1);

    // Guest disconnection request on new network result in call to wlansvc
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
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, [&] {
        return std::vector<WifiNetworkInfo>{{static_cast<DOT11_SSID>(ssid), bssid}};
    });

    SECTION("Only disconnect the guest connected interface")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));

        fakeWlansvc->ConnectHost(Mock::c_intf2, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        auto disconnectResponse = opHandler->HandleDisconnectRequest(MakeDisconnectRequest(1));
        CHECK(fakeWlansvc->callCount.disconnect == 1);
        const auto intf1Info = fakeWlansvc->GetCurrentConnection(Mock::c_intf1);
        const auto intf2Info = fakeWlansvc->GetCurrentConnection(Mock::c_intf2);
        CHECK((!intf1Info || intf1Info->isState == wlan_interface_state_disconnected));
        CHECK((intf2Info && intf2Info->isState == wlan_interface_state_connected));
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
        const auto intf1Info = fakeWlansvc->GetCurrentConnection(Mock::c_intf1);
        CHECK((intf1Info && intf1Info->isState == wlan_interface_state_connected));
    }
}

TEST_CASE("Notify the client on connection and disconnection", "[wlansvcOpHandler][clientNotification]")
{
    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});

    enum class Notif
    {
        HostConnect,
        HostDisconnect,
        GuestConnectRequest,
        GuestConnectComplete,
        GuestDisconnectRequest,
        GuestDisconnectComplete
    };
    enum class Type
    {
        None,
        GuestDirected,
        HostMirroring
    };

    struct TestObserver : public ProxyWifiObserver
    {
        void OnHostConnection(const ConnectCompleteArgs&) noexcept override
        {
            notifs.emplace_back(Notif::HostConnect, Type::None);
        }

        void OnHostDisconnection(const DisconnectCompleteArgs&) noexcept override
        {
            notifs.emplace_back(Notif::HostDisconnect, Type::None);
        }

        Authorization AuthorizeGuestConnectionRequest(OperationType t, const ConnectRequestArgs&) noexcept override
        {
            auto type = t == OperationType::GuestDirected ? Type::GuestDirected : Type::HostMirroring;
            notifs.emplace_back(Notif::GuestConnectRequest, type);
            return Authorization::Approve;
        }

        void OnGuestConnectionCompletion(OperationType t, OperationStatus, const ConnectCompleteArgs&) noexcept override
        {
            auto type = t == OperationType::GuestDirected ? Type::GuestDirected : Type::HostMirroring;
            notifs.emplace_back(Notif::GuestConnectComplete, type);
        }

        void OnGuestDisconnectionRequest(OperationType t, const DisconnectRequestArgs&) noexcept override
        {
            auto type = t == OperationType::GuestDirected ? Type::GuestDirected : Type::HostMirroring;
            notifs.emplace_back(Notif::GuestDisconnectRequest, type);
        }

        void OnGuestDisconnectionCompletion(OperationType t, OperationStatus, const DisconnectCompleteArgs&) noexcept override
        {
            auto type = t == OperationType::GuestDirected ? Type::GuestDirected : Type::HostMirroring;
            notifs.emplace_back(Notif::GuestDisconnectComplete, type);
        }

        std::vector<std::pair<Notif, Type>> notifs;
    };

    auto pObserver = std::make_unique<TestObserver>();
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, {}, pObserver.get());
    auto connectRequest = MakeOpenConnectRequest(Mock::c_openNetwork.bss.ssid);
    auto disconnectRequest = MakeDisconnectRequest(1);

    SECTION("Notifications on guest directed operations")
    {
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        opHandler->DrainWorkqueues();
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(
            pObserver->notifs == std::vector<std::pair<Notif, Type>>{
                                     {Notif::GuestConnectRequest, Type::GuestDirected},
                                     {Notif::HostConnect, Type::None},
                                     {Notif::GuestConnectComplete, Type::GuestDirected}});

        pObserver->notifs.clear();
        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        opHandler->DrainWorkqueues();
        CHECK(
            pObserver->notifs == std::vector<std::pair<Notif, Type>>{
                                     {Notif::GuestDisconnectRequest, Type::GuestDirected},
                                     {Notif::HostDisconnect, Type::None},
                                     {Notif::GuestDisconnectComplete, Type::GuestDirected}});
    }

    SECTION("Notifications on host initiated operations")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();
        CHECK(pObserver->notifs == std::vector<std::pair<Notif, Type>>{{Notif::HostConnect, Type::None}});

        pObserver->notifs.clear();

        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        fakeWlansvc->DisconnectHost(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        CHECK(pObserver->notifs == std::vector<std::pair<Notif, Type>>{{Notif::HostDisconnect, Type::None}});
    }

    SECTION("Notifications on mirroring operations")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_openNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        opHandler->DrainWorkqueues();
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(fakeWlansvc->callCount.connect == 0);
        CHECK(
            pObserver->notifs == std::vector<std::pair<Notif, Type>>{
                                     {Notif::HostConnect, Type::None},
                                     {Notif::GuestConnectRequest, Type::HostMirroring},
                                     {Notif::GuestConnectComplete, Type::HostMirroring}});

        pObserver->notifs.clear();

        auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
        opHandler->DrainWorkqueues();
        CHECK(fakeWlansvc->callCount.disconnect == 0);
        CHECK(
            pObserver->notifs ==
            std::vector<std::pair<Notif, Type>>{
                {Notif::GuestDisconnectRequest, Type::HostMirroring}, {Notif::GuestDisconnectComplete, Type::HostMirroring}});

        pObserver->notifs.clear();

        fakeWlansvc->DisconnectHost(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

        CHECK(pObserver->notifs == std::vector<std::pair<Notif, Type>>{{Notif::HostDisconnect, Type::None}});
    }
}

TEST_CASE("The client can approve or deny guest connection requests", "[wlansvcOpHandler][clientNotification]")
{
    struct TestObserver : public ProxyWifiObserver
    {
        Authorization AuthorizeGuestConnectionRequest(OperationType, const ConnectRequestArgs&) noexcept override
        {
            return authorizeToConnect;
        }

        void OnGuestConnectionCompletion(OperationType, OperationStatus status, const ConnectCompleteArgs&) noexcept override
        {
            lastOperationStatus = status;
        }

        Authorization authorizeToConnect;
        OperationStatus lastOperationStatus = OperationStatus::Succeeded;
    };

    auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});

    auto pObserver = std::make_unique<TestObserver>();
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, {}, pObserver.get());
    auto connectRequest = MakeOpenConnectRequest(Mock::c_openNetwork.bss.ssid);
    auto disconnectRequest = MakeDisconnectRequest(1);

    SECTION("The client can approve a guest directed connection request")
    {
        pObserver->authorizeToConnect = ProxyWifiObserver::Authorization::Approve;
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        opHandler->DrainClientNotifications();
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(pObserver->lastOperationStatus == OperationStatus::Succeeded);
    }

    SECTION("The client can deny a guest directed connection request")
    {
        pObserver->authorizeToConnect = ProxyWifiObserver::Authorization::Deny;
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        opHandler->DrainClientNotifications();
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::UnspecifiedFailure));
        CHECK(pObserver->lastOperationStatus == OperationStatus::Denied);
    }

    SECTION("The client can approve a host mirroring connection request")
    {
        pObserver->authorizeToConnect = ProxyWifiObserver::Authorization::Approve;

        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_openNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainClientNotifications();

        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        opHandler->DrainClientNotifications();
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));
        CHECK(pObserver->lastOperationStatus == OperationStatus::Succeeded);
    }

    SECTION("The client can deny a host mirroring connection request")
    {
        pObserver->authorizeToConnect = ProxyWifiObserver::Authorization::Deny;

        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_openNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainClientNotifications();

        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        opHandler->DrainClientNotifications();
        CHECK(connectResponse->result_code == WI_EnumValue(WlanStatus::UnspecifiedFailure));
        CHECK(pObserver->lastOperationStatus == OperationStatus::Denied);
    }
}

TEST_CASE("Notify client for guest scans", "[wlansvcOpHandler][clientNotification]")
{
    const auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});

    enum class Notif
    {
        ScanRequest,
        ScanComplete
    };

    struct TestObserver : public ProxyWifiObserver
    {
        void OnGuestScanRequest() noexcept override
        {
            notifs.push_back(Notif::ScanRequest);
        }
        void OnGuestScanCompletion(OperationStatus) noexcept override
        {
            notifs.push_back(Notif::ScanComplete);
        }
        std::vector<Notif> notifs;
    };

    const auto pObserver = std::make_unique<TestObserver>();
    const auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, {}, pObserver.get());
    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));
    auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
    fakeWlansvc->WaitForNotifComplete();
    opHandler->DrainWorkqueues();

    CHECK(pObserver->notifs == std::vector{Notif::ScanRequest, Notif::ScanComplete});
}

TEST_CASE("Provide the authentication algorithm on host connections", "[wlansvcOpHandler][clientNotification]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(
        std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork, Mock::c_enterpriseNetwork});

    enum class EventSource
    {
        Host,
        Guest
    };

    struct TestObserver : public ProxyWifiObserver
    {
        void OnHostConnection(const ConnectCompleteArgs& connectInfo) noexcept override
        {
            notifParams.emplace_back(EventSource::Host, connectInfo.authAlgo);
        }

        void OnGuestConnectionCompletion(OperationType, OperationStatus, const ConnectCompleteArgs& connectInfo) noexcept override
        {
            notifParams.emplace_back(EventSource::Guest, connectInfo.authAlgo);
        }

        std::vector<std::pair<EventSource, DOT11_AUTH_ALGORITHM>> notifParams;
    };

    auto pObserver = std::make_unique<TestObserver>();
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, {}, pObserver.get());

    SECTION("Correct auth algo for host wpa2psk connection")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();
        REQUIRE(pObserver->notifParams.size() == 1);
        CHECK(pObserver->notifParams[0].first == EventSource::Host);
        CHECK(pObserver->notifParams[0].second == DOT11_AUTH_ALGO_RSNA_PSK);
    }

    SECTION("Correct auth algo for host open connection")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_openNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();
        REQUIRE(pObserver->notifParams.size() == 1);
        CHECK(pObserver->notifParams[0].first == EventSource::Host);
        CHECK(pObserver->notifParams[0].second == DOT11_AUTH_ALGO_80211_OPEN);
    }

    SECTION("Auth algo is adapted to what the guest sees")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_enterpriseNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();
        REQUIRE(pObserver->notifParams.size() == 1);
        CHECK(pObserver->notifParams[0].first == EventSource::Host);
        CHECK(pObserver->notifParams[0].second == DOT11_AUTH_ALGO_RSNA_PSK);
    }

    SECTION("Correct auth algo for guest connection")
    {
        auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        REQUIRE(pObserver->notifParams.size() == 2);
        CHECK(pObserver->notifParams[0].first == EventSource::Host);
        CHECK(pObserver->notifParams[0].second == DOT11_AUTH_ALGO_RSNA_PSK);
        CHECK(pObserver->notifParams[1].first == EventSource::Guest);
        CHECK(pObserver->notifParams[1].second == DOT11_AUTH_ALGO_RSNA_PSK);
    }
}

TEST_CASE("Notify client for initially connected networks", "[wlansvcOpHandler][clientNotification]")
{
    const auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});

    struct TestObserver : public ProxyWifiObserver
    {
        void OnHostConnection(const ConnectCompleteArgs&) noexcept override
        {
            hostConnect++;
        }
        int hostConnect = 0;
    };

    const auto pObserver = std::make_unique<TestObserver>();
    fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
    fakeWlansvc->WaitForNotifComplete();

    const auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc, {}, pObserver.get());
    opHandler->DrainWorkqueues();

    CHECK(pObserver->hostConnect == 1);
}

TEST_CASE("Initial notifications cannot deadlock a cient", "[wlansvcOpHandler][clientNotification]")
{
    const auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});

    fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
    fakeWlansvc->WaitForNotifComplete();

    struct TestObserver : public ProxyWifiObserver
    {
        void OnHostConnection(const ConnectCompleteArgs&) noexcept override
        {
            for (auto i = 0; i < 10; ++i)
            {
                auto lock = clientLock.try_lock_exclusive();
                if (lock)
                {
                    noDeadlock = true;
                    return;
                }
                std::this_thread::sleep_for(10ms);
            }
        }
        wil::srwlock clientLock;
        bool noDeadlock = false;
    };

    const auto pObserver = std::make_unique<TestObserver>();
    const auto opHandler = [&]() {
        auto lock = pObserver->clientLock.lock_exclusive();
        return MakeUnitTestOperationHandler(fakeWlansvc, {}, pObserver.get());
    }();

    opHandler->DrainWorkqueues();
    CHECK(pObserver->noDeadlock);
}

TEST_CASE("Handle graciously non-expected wlansvc notifications", "[wlansvcOpHandler]")
{
    const auto fakeWlansvc =
        std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork, Mock::c_openNetwork});
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    SECTION("Do not crash on spontaneous scan complete notification")
    {
        fakeWlansvc->Scan(Mock::c_intf1);
        fakeWlansvc->WaitForNotifComplete();
    }

    SECTION("Do not crash on spontaneous connection complete notification")
    {
        fakeWlansvc->ConnectHost(Mock::c_intf1, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();
    }
}

TEST_CASE("Don't notify guest on host disconnection", "[wlansvcOpHandler]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

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
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    unsigned long signalQuality = 80;
    int8_t rssi = -60; // (rssi + 100) * 2 = signalQuality
    auto callCount = 0;
    ProxyWifi::OperationHandler::GuestNotificationTypes notif{SignalQualityNotif{42}};

    opHandler->RegisterGuestNotificationCallback([&](auto n) {
        ++callCount;
        notif = n;
    });

    SECTION("Ignore notification when disconnected")
    {
        fakeWlansvc->SetSignalQuality(Mock::c_intf1, signalQuality);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();
        CHECK(callCount == 0);
    }

    SECTION("Forward notification when connected")
    {
        const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
        REQUIRE(connectResponse->result_code == WI_EnumValue(WlanStatus::Success));

        fakeWlansvc->SetSignalQuality(Mock::c_intf1, signalQuality);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();
        CHECK(callCount == 1);
        REQUIRE(std::holds_alternative<SignalQualityNotif>(notif));
        CHECK(std::get<SignalQualityNotif>(notif)->signal == rssi);
    }
}

TEST_CASE("Ignore notification from other interfaces", "[wlansvcOpHandler][multiInterface]")
{
    auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1, Mock::c_intf2}, std::vector{Mock::c_wpa2PskNetwork});
    auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    unsigned long signalQuality = 80;
    int8_t rssi = -60; // (rssi + 100) * 2 = signalQuality
    auto callCount = 0;
    ProxyWifi::OperationHandler::GuestNotificationTypes notif{SignalQualityNotif{42}};

    opHandler->RegisterGuestNotificationCallback([&](auto n) {
        ++callCount;
        notif = n;
    });

    SECTION("Ignore notification on the non-connected interface")
    {
        const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_wpa2PskNetwork.bss.ssid);
        auto connectResponse = opHandler->HandleConnectRequest(connectRequest);

        fakeWlansvc->ConnectHost(Mock::c_intf2, Mock::c_wpa2PskNetwork.bss.ssid);
        fakeWlansvc->WaitForNotifComplete();

        fakeWlansvc->SetSignalQuality(Mock::c_intf2, signalQuality);
        fakeWlansvc->WaitForNotifComplete();
        opHandler->DrainWorkqueues();

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
        opHandler->DrainWorkqueues();
        CHECK(callCount == 1);
        REQUIRE(std::holds_alternative<SignalQualityNotif>(notif));
        CHECK(std::get<SignalQualityNotif>(notif)->signal == rssi);
    }
}

TEST_CASE("Notifications for fake networks use FakeInterfaceGuid", "[wlansvcOpHandler][clientNotification]")
{
    const auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>();

    struct TestObserver : public ProxyWifiObserver
    {
        void OnGuestDisconnectionCompletion(OperationType, OperationStatus, const DisconnectCompleteArgs& disconnectInfo) noexcept override
        {
            guid = disconnectInfo.interfaceGuid;
        }
        void OnGuestConnectionCompletion(OperationType, OperationStatus, const ConnectCompleteArgs& connectInfo) noexcept override
        {
            guid = connectInfo.interfaceGuid;
        }
        GUID guid{};
    };

    const auto pObserver = std::make_unique<TestObserver>();
    const auto opHandler = MakeUnitTestOperationHandler(
        fakeWlansvc,
        [&] {
            DOT11_MAC_ADDRESS bssid{0, 0, 0, 0, 0, 1};
            return std::vector<WifiNetworkInfo>{{Mock::c_pizzaNetwork.network.dot11Ssid, bssid}};
        },
        pObserver.get());

    const auto connectRequest = MakeWpa2PskConnectRequest(Mock::c_pizzaNetwork.bss.ssid);
    auto connectResponse = opHandler->HandleConnectRequest(connectRequest);
    CHECK(pObserver->guid == FakeInterfaceGuid);

    const auto disconnectRequest = MakeDisconnectRequest(1);
    auto disconnectResponse = opHandler->HandleDisconnectRequest(disconnectRequest);
    CHECK(pObserver->guid == FakeInterfaceGuid);
}

TEST_CASE("Handle interface arrival", "[wlansvcOpHandler][multiInterface]")
{
    const auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>();
    const auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    fakeWlansvc->AddInterface(Mock::c_intf2);
    fakeWlansvc->AddNetwork(Mock::c_intf2, Mock::c_wpa2PskNetwork);
    fakeWlansvc->WaitForNotifComplete();

    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));
    auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
    fakeWlansvc->WaitForNotifComplete();
    opHandler->DrainWorkqueues();

    // Indirectly check that the interface has been added and is in use
    CHECK(scanResponse->num_bss == 1);
}

TEST_CASE("Handle interface departure", "[wlansvcOpHandler][multiInterface]")
{
    const auto fakeWlansvc = std::make_shared<Mock::WlanSvcFake>(std::vector{Mock::c_intf1}, std::vector{Mock::c_wpa2PskNetwork});
    const auto opHandler = MakeUnitTestOperationHandler(fakeWlansvc);

    fakeWlansvc->RemoveInterface(Mock::c_intf1);
    fakeWlansvc->WaitForNotifComplete();

    auto body = std::vector<uint8_t>(sizeof(proxy_wifi_scan_request));
    auto scanResponse = opHandler->HandleScanRequest(ScanRequest{std::move(body)});
    fakeWlansvc->WaitForNotifComplete();
    opHandler->DrainWorkqueues();

    // Indirectly check that the interface is no longer present
    CHECK(scanResponse->num_bss == 0);
}