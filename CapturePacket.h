#include <iostream>
#include <algorithm>
#include "cstdlib"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

struct PacketStats{
    int ethPacketCount = 0;
    int ipv4PacketCount = 0;
    int ipv6PacketCount = 0;
    int tcpPacketCount = 0;
    int udpPacketCount = 0;
    int dnsPacketCount = 0;
    int httpPacketCount = 0;
    int sslPacketCount = 0;

    void clear()
    {
        ethPacketCount=ipv4PacketCount=ipv6PacketCount=tcpPacketCount=udpPacketCount=dnsPacketCount=httpPacketCount=sslPacketCount=0;
    }
    void ConsumePacket(pcpp::Packet& packet)
    {
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
    void printToConsole() const
    {
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
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    auto* stats = static_cast <PacketStats*>(cookie);
    pcpp::Packet parsedPacket (packet);
    stats->ConsumePacket(parsedPacket);
}
static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    auto *stats = static_cast<PacketStats*>(cookie);
    pcpp::Packet parsedPacket(packet);
    stats->ConsumePacket(parsedPacket);
    return false;
}
void CapturePackets()
{
    std::string interfaceIPAddr="192.168.1.9";
    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);

    if(dev == nullptr) {
        std::cerr << "Cannot find interface with " << interfaceIPAddr << std::endl;
        return;
    }
    std::cout
            << "Interface info:" << std::endl
            << "   Interface name:        " << dev->getName() << std::endl // get interface name
            << "   Interface description: " << dev->getDesc() << std::endl // get interface description
            << "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
            << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
            << "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU

    if (!dev->getDnsServers().empty())
    {
        std::cout << "   DNS server:            " << dev->getDnsServers().front() << std::endl;
    }

    if(!dev->open())
    {
        std::cerr<<"Cannot open device"<<std::endl;
        return;
    }

    PacketStats stats;
    //Asynchronous packet capture using callback function
    std::cout<<std::endl << "Starting async capture..." << std::endl;
    dev->startCapture(onPacketArrives, &stats);
    pcpp::multiPlatformSleep(10);
    dev->stopCapture();

    std::cout<<"Results: " << std::endl;
    stats.printToConsole();
    stats.clear();

    //Asynchronous Packet capture using a packet list (Vector)
    std::cout << std::endl << "Starting capture with packet vector..." << std::endl;
    pcpp::RawPacketVector packetVec;
    dev->startCapture(packetVec);
    pcpp::multiPlatformSleep(10);
    for(const auto& packet: packetVec)
    {
        pcpp::Packet parsedPacket(packet);
        stats.ConsumePacket(parsedPacket);
    }
    std::cout<<"Results: " << std::endl;
    stats.printToConsole();
    dev->stopCapture();

    //Synchronous Packet Capture
    std::cout<<std::endl << "Starting capture in blocking mode..."<<std::endl;
    stats.clear();

    dev->startCaptureBlockingMode(onPacketArrivesBlockingMode,&stats,10);

    std::cout<<"Results: "<<std::endl;
    stats.printToConsole();

}
