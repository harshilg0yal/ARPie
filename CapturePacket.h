#include <iostream>
#include <algorithm>
#include "cstdlib"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

struct PacketStats {
    int ethPacketCount = 0;
    int ipv4PacketCount = 0;
    int ipv6PacketCount = 0;
    int tcpPacketCount = 0;
    int udpPacketCount = 0;
    int dnsPacketCount = 0;
    int httpPacketCount = 0;
    int sslPacketCount = 0;

    void clear() {
        ethPacketCount = ipv4PacketCount = ipv6PacketCount = tcpPacketCount = udpPacketCount = dnsPacketCount = httpPacketCount = sslPacketCount = 0;
    }

    void ConsumePacket(pcpp::Packet &packet) {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    void printToConsole() const {
        std::cout
                << "Ethernet packet count: " << ethPacketCount << std::endl
                << "IPv4 packet count:     " << ipv4PacketCount << std::endl
                << "IPv6 packet count:     " << ipv6PacketCount << std::endl
                << "TCP packet count:      " << tcpPacketCount << std::endl
                << "UDP packet count:      " << udpPacketCount << std::endl
                << "DNS packet count:      " << dnsPacketCount << std::endl
                << "HTTP packet count:     " << httpPacketCount << std::endl
                << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *interface, void *cookie) {
    auto *stats = static_cast <PacketStats *>(cookie);
    pcpp::Packet parsedPacket(packet);
    stats->ConsumePacket(parsedPacket);
}

static bool onPacketArrivesBlockingMode(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *interface, void *cookie) {
    auto *stats = static_cast<PacketStats *>(cookie);
    pcpp::Packet parsedPacket(packet);
    stats->ConsumePacket(parsedPacket);
    return false;
}

void CapturePackets(pcpp::PcapLiveDevice* interface) {

    if(interface == nullptr)
    {
        std::cerr<<"Invalid Interface provided, Please re-run ARPie"<<std::endl;
        return;
    }
    
    std::cout
            << "Interface info:" << std::endl
            << "   Interface name:        " << interface->getName() << std::endl // get interface name
            << "   Interface description: " << interface->getDesc() << std::endl // get interface description
            << "   MAC address:           " << interface->getMacAddress() << std::endl // get interface MAC address
            << "   Default gateway:       " << interface->getDefaultGateway() << std::endl // get default gateway
            << "   Interface MTU:         " << interface->getMtu() << std::endl; // get interface MTU

    if (!interface->getDnsServers().empty()) {
        std::cout << "   DNS server:            " << interface->getDnsServers().front() << std::endl;
    }

    if (!interface->open()) {
        std::cerr << "Cannot open device" << std::endl;
        return;
    }

    PacketStats stats;
    std::string opt1("1. Asynchronous packet capture using callback function");
    std::string opt2("2. Asynchronous Packet capture using a packet list (Vector)");
    std::string opt3("3. Synchronous(Blocking) Packet Capture");

    std::string question("Please select the type of packet capture from the following options :");

    auto askQuestion = [question, opt1, opt2, opt3]() {
        std::cout << question << std::endl;
        std::cout << opt1 << std::endl
                  << opt2 << std::endl
                  << opt3 << std::endl;
        int op = 0;
        std::cout << "Please enter the option no. :";
        std::cin >> op;
        return op;
    };

    int opt = askQuestion();

    auto checkOption = [opt]() {
        if (opt == 1 || opt == 2 || opt == 3) {
            return opt;
        } else {
            std::cout << "Wrong options selected. Please select a valid option i.e. 1, 2 or 3" << std::endl;
            return -1;
        }
    };

    while (true) {
        int flag = checkOption();
        if (flag != -1) break;
        else opt = askQuestion();
    }

    //Asynchronous packet capture using callback function
    auto startAsyncCapture = [&interface, &stats]() {
        std::cout << std::endl << "Starting async capture..." << std::endl;
        interface->startCapture(onPacketArrives, &stats);
        pcpp::multiPlatformSleep(10);
        interface->stopCapture();
        std::cout << "Results: " << std::endl;
        stats.printToConsole();
        stats.clear();
    };

    //Asynchronous Packet capture using a packet list (Vector)
    auto startAsyncCapturePacketList = [&interface, &stats]() {
        std::cout << std::endl << "Starting capture with packet vector..." << std::endl;
        pcpp::RawPacketVector packetVec;
        interface->startCapture(packetVec);
        pcpp::multiPlatformSleep(10);
        for (const auto &packet: packetVec) {
            pcpp::Packet parsedPacket(packet);
            stats.ConsumePacket(parsedPacket);
        }
        std::cout << "Results: " << std::endl;
        stats.printToConsole();
        interface->stopCapture();
    };

    //Synchronous Packet Capture
    auto startSynchronousCapture = [&interface, &stats]() {
        std::cout << std::endl << "Starting capture in blocking mode..." << std::endl;
        stats.clear();

        interface->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);

        std::cout << "Results: " << std::endl;
        stats.printToConsole();
    };

    if (opt == 1) {
        startAsyncCapture();
    } else if (opt == 2) {
        startAsyncCapturePacketList();
    } else {
        startSynchronousCapture();
    }


}
