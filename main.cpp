#include "ListInterfaces.h"
#include "CapturePacket.h"

int main(int argc, char* argv[])
{
    int option=0;
    auto interfaces=listInterface();
    std::cout<<"Please enter the Interface No. for which you want to sniff packets: ";
    std::cin>>option;
    std::cout<<std::endl;
    auto interface = interfaces[option];
    CapturePackets(interface);
}