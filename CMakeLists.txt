cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Threading support
find_package(Threads REQUIRED)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Target 1: Basic Packet Parser / Summary Analyzer
set(SOURCES_ANALYZER
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)
add_executable(packet_analyzer ${SOURCES_ANALYZER})

# Target 2: High-Performance Multi-Threaded DPI Engine (Load Balancers + Fast Paths)
set(SOURCES_DPI_MT
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
add_executable(dpi_engine ${SOURCES_DPI_MT})
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# Compiler options
if(MSVC)
    target_compile_options(packet_analyzer PRIVATE /W4 /EHsc /utf-8)
    target_compile_options(dpi_engine PRIVATE /W4 /EHsc /utf-8)
else()
    target_compile_options(packet_analyzer PRIVATE -Wall -Wextra -O2)
    target_compile_options(dpi_engine PRIVATE -Wall -Wextra -O2)
endif()
