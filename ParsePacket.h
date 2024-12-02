#include <iostream>
#include <memory>
#include "cstdlib"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::TCP:
            return "TCP";
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";
        default:
            return "Unknown";
    }
}
std::string printTCPFlags(pcpp::TcpLayer* tcpLayer)
{
    std::string result;

    auto* tcpHeader = tcpLayer -> getTcpHeader();
    if (tcpHeader->synFlag) result += "SYN ";
    if (tcpHeader->ackFlag) result += "ACK ";
    if (tcpHeader->pshFlag) result += "PSH ";
    if (tcpHeader->cwrFlag) result += "CWR ";
    if (tcpHeader->urgFlag) result += "URG ";
    if (tcpHeader->eceFlag) result += "ECE ";
    if (tcpHeader->rstFlag) result += "RST ";
    if (tcpHeader->finFlag) result += "FIN ";
    return result;
}
std::string printTcpOptionType(pcpp::TcpOptionType optionType)
{
    switch(optionType)
    {
        case pcpp::PCPP_TCPOPT_NOP:
            return "NOP";
        case pcpp::PCPP_TCPOPT_TIMESTAMP:
            return "Timestamp";
        default:
            return "Other";
    }
}
std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod )
{
    switch (httpMethod)
    {
        case pcpp::HttpRequestLayer::HttpGET:
            return "GET";
        case pcpp::HttpRequestLayer::HttpPOST:
            return "POST";
        default:
            return "Other";
    }
}
void GetLayerDetails(const pcpp::Packet& parsedPacket)
{
    for(auto* currLayer = parsedPacket.getFirstLayer();currLayer != nullptr ; currLayer=currLayer->getNextLayer())
    {
        std::cout
                << "Layer type: " << getProtocolTypeAsString(currLayer->getProtocol()) << "; " // get layer type
                << "Total data: " << currLayer->getDataLen() << " [bytes]; " // get total length of the layer
                << "Layer data: " << currLayer->getHeaderLen() << " [bytes]; " // get the header length of the layer
                << "Layer payload: " << currLayer->getLayerPayloadSize() << " [bytes]"<<std::endl;
    }
}
void ParseEthLayer(const pcpp::Packet& parsedPacket)
{
    auto* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

    if(ethernetLayer == nullptr)
    {
        std::cerr << "Something went wrong, couldn't find Ethernet Layer"<<std::endl;
        return;
    }
    //Parsing Ethernet
    std::cout << std::endl
              <<"Source MAC address: "<< ethernetLayer->getSourceMac()<<std::endl
              <<"Destination MAC  address"<<ethernetLayer->getDestMac()<<std::endl
              <<"Ether type = 0x"<<std::hex
              << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType)
              <<std::endl;
}
void ParseIPv4Layer(const pcpp::Packet& parsedPacket)
{
    //Parsing IPv4

    auto * ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    if (ipLayer == nullptr)
    {
        std::cerr << "Something went wrong, couldn't find Ethernet Layer"<<std::endl;
        return;
    }

    std::cout<<std::endl
             << "Source IP address: " << ipLayer->getSrcIPv4Address()<<std::endl
             << "Destination MAC address: " << ipLayer->getDstIPv4Address()<<std::endl
             << "IP ID: 0x"<<std::hex<<pcpp::netToHost16(ipLayer->getIPv4Header()->ipDst)<<std::endl
             <<"TTL: "<<std::dec << (int)ipLayer->getIPv4Header()->timeToLive<<std::endl;

}
void ParseTCPLayer(const pcpp::Packet& parsedPacket)
{
    auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

    if(tcpLayer == nullptr)
    {
        std::cerr << "Something went wrong, couldn't find TCP Layer"<<std::endl;
        return;
    }

    std::cout<<std::endl
    <<"Source TCP Port" << tcpLayer->getSrcPort()<<std::endl
    <<"Destination TCP Port" << tcpLayer->getDstPort()<<std::endl
    <<"Window Size" << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize)<<std::endl
    <<"TCP Flags" << printTCPFlags(tcpLayer)<<std::endl<< "TCP options: ";
    for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
    {
        std::cout << printTcpOptionType(tcpOption.getTcpOptionType()) << " ";
    }
    std::cout << std::endl;

}
void ParseHTTPLayer(const pcpp::Packet& parsedPacket){
    auto * httpLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();

    if(httpLayer == nullptr)
    {
        std::cerr<<"Something went wrong, couldn't find HTTP request Layer "<<std::endl;
        return;
    }

    std::cout<<std::endl
    <<"HTTP Method: "<< printHttpMethod(httpLayer->getFirstLine()->getMethod())<<std::endl
    <<"HTTP URI: "<<httpLayer->getFirstLine()->getUri()<<std::endl;

    std::cout
            << "HTTP host: " << httpLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << std::endl
            << "HTTP user-agent: " << httpLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() << std::endl
            << "HTTP cookie: " << httpLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() << std::endl;

    // print the full URL of this request
    std::cout << "HTTP full URL: " << httpLayer->getUrl() << std::endl;
}
void ParsePacket(const std::string& FileName)
{
    //Created a smart pointer
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(FileName));

    if(reader == nullptr)
    {
        std::cerr << "Unable to determine reader for the file type"<<std::endl;
        return;
    }

    if(!reader->open())
    {
        std::cerr<<"Unable to open "<<FileName<<" for reading"<<std::endl;
        return;
    }

    pcpp::RawPacket rawPacket;

    if(!reader->getNextPacket(rawPacket))
    {
        std::cerr << "Couldn't read the first packet in the file"<<std::endl;
        return;
    }

    reader->close();

    pcpp::Packet parsedPacket (&rawPacket);
    GetLayerDetails(parsedPacket);
    ParseEthLayer(parsedPacket);
    ParseIPv4Layer(parsedPacket);
    ParseTCPLayer(parsedPacket);
    ParseHTTPLayer(parsedPacket);
}