// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include "OperationHandler.hpp"
#include "RealWlanInterface.hpp"
#include "WlanSvcWrapper.hpp"

#include <algorithm>
#include <memory>
#include <vector>

namespace ProxyWifi {

class WlansvcOperationHandler : public OperationHandler
{
public:
    WlansvcOperationHandler(ProxyWifiObserver* pObserver, std::vector<std::unique_ptr<IWlanInterface>> wlanInterfaces, std::shared_ptr<Wlansvc::WlanApiWrapper>& wlansvc)
        : OperationHandler{pObserver, std::move(wlanInterfaces)}, m_wlansvc{wlansvc}
    {
        if (!m_wlansvc)
        {
            return;
        }

        m_wlansvc->Subscribe(GUID{}, [this](const auto& n) {
            if (n.NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM)
            {
                switch (n.NotificationCode)
                {
                case wlan_notification_acm_interface_arrival:
                {
                    // Check the notification is for a primary interface
                    // (secondary interfaces arrival are notified, but not returned by EnumerateInterface)
                    auto intf = m_wlansvc->EnumerateInterfaces();
                    auto foundIt = std::find(intf.begin(), intf.end(), n.InterfaceGuid);
                    if (foundIt != intf.end())
                    {
                        AddInterface([wlansvc = m_wlansvc, guid = n.InterfaceGuid] {
                                return std::make_unique<RealWlanInterface>(wlansvc, guid);
                        });
                    }
                    break;
                }
                case wlan_notification_acm_interface_removal:
                    RemoveInterface(n.InterfaceGuid);
                    break;
                }
            }
        });
    }

    virtual ~WlansvcOperationHandler()
    {
        if (m_wlansvc)
        {
            m_wlansvc->Unsubscribe(GUID{});
        }
    }

private:
    std::shared_ptr<Wlansvc::WlanApiWrapper> m_wlansvc;
};

} // namespace ProxyWifi