cmake_minimum_required(VERSION 3.0)
project(ARPie)

# Set the C++ standard to C++11
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(/usr/local/include/pcapplusplus)

# Link directories
link_directories(/usr/local/lib)

# Define compile definitions
add_definitions(-D_GLIBCXX_USE_CXX11_ABI=1)
add_executable(${PROJECT_NAME}
        floodie.h
        main.cpp)

# Link the necessary libraries
target_link_libraries(${PROJECT_NAME} Pcap++ Packet++ Common++ pcap)