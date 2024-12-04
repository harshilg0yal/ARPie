#include <iostream>
#include <unordered_map>
#include "PcapLiveDeviceList.h"

std::unordered_map<int,pcpp::PcapLiveDevice*> listInterface() {
    auto interfaces = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    int interfaceCount = 1;

    std::cout << "Interfaces found:" << std::endl;
    std::unordered_map<int,pcpp::PcapLiveDevice*> interface_map;

    for (auto interface : interfaces) {
        std::cout << "----------------------------------------" << std::endl;
        interface_map[interfaceCount]=interface;
        std::cout << interfaceCount++ << ". Interface Name: " << interface->getName() << std::endl;

        // Description
        if (!interface->getDesc().empty()) {
            std::cout << "   Description       : " << interface->getDesc() << std::endl;
        } else {
            std::cout << "   Description       : (None)" << std::endl;
        }

        // Default Gateway
        auto defaultGateway = interface->getDefaultGateway();
        if (defaultGateway!=pcpp::IPv4Address::Zero) {
            std::cout << "   Default Gateway   : " << interface->getDefaultGateway().toString() << std::endl;
        } else {
            std::cout << "   Default Gateway   : (None)" << std::endl;
        }

        // MAC Address
        auto macAddress=interface->getMacAddress();
        if (macAddress != pcpp::MacAddress::Zero) {
            std::cout << "   MAC Address       : " << interface->getMacAddress().toString() << std::endl;
        } else {
            std::cout << "   MAC Address       : (None)" << std::endl;
        }

        // IPv4 Addresses
        auto ipv4Addresses = interface->getIPAddresses();
        if (!ipv4Addresses.empty()) {
            std::cout << "   IPv4 Addresses    : ";
            for (const auto& address : ipv4Addresses) {
                if (address.isIPv4()) {
                    std::cout << address.toString() << " ";
                }
            }
            std::cout << std::endl;
        } else {
            std::cout << "   IPv4 Addresses    : None" << std::endl;
        }

        // Loopback Check
        std::cout << "   Loopback Device   : " << (interface->getLoopback() ? "Yes" : "No") << std::endl;

        // MTU
        if (interface->getMtu() > 0) {
            std::cout << "   MTU               : " << interface->getMtu() << std::endl;
        } else {
            std::cout << "   MTU               : (Not Available)" << std::endl;
        }
    }
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Total Interfaces Found: " << interfaceCount-1 << std::endl;

    return interface_map;
}
