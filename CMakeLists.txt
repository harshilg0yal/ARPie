cmake_minimum_required(VERSION 3.0)
project(ARPie)

# Set the C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include Pcap++ headers (adjust this path to where Pcap++ headers are located)
include_directories("C:/Program Files (x86)/PcapPlusPlus/include/pcapplusplus")

# Include Npcap SDK headers
include_directories("C:/Libraries/npcap-sdk-1.13/include")

# Link directories for Pcap++ and Npcap SDK libraries
link_directories("C:/Program Files (x86)/pcapplusplus/lib")
link_directories("C:/Libraries/npcap-sdk-1.13/lib")

# Define compile definitions
add_definitions(-D_GLIBCXX_USE_CXX11_ABI=1)

# Add the executable
add_executable(${PROJECT_NAME}
        ParsePacket.h 
        CapturePacket.h
        ListInterfaces.h
        main.cpp
        floodie.h
        ARPieFlooderMain.cpp)

# Link the necessary libraries (make sure to link to the correct libraries in Npcap SDK and Pcap++)
target_link_libraries(${PROJECT_NAME} Pcap++ Packet++ Common++ pcap npcap)
