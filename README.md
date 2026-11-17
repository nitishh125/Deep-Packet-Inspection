# Deep Packet Inspection (DPI) Engine & Packet Analyzer

[![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?logo=windows)](https://microsoft.com)
[![Python](https://img.shields.io/badge/Python-3.7%2B-brightgreen?logo=python)](https://python.org)
[![C++](https://img.shields.io/badge/C%2B%2B-17%20Standard-blue?logo=c%2B%2B)](https://isocpp.org)
[![Wireshark](https://img.shields.io/badge/Format-Wireshark%20PCAP-teal?logo=wireshark)](https://wireshark.org)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

A high-performance **Layer 7 Deep Packet Inspection (DPI)** and packet analysis system tailored for Windows. It inspects network packet captures (`.pcap`), identifies applications within encrypted HTTPS connections using **TLS Server Name Indication (SNI) extraction**, enforces multi-level blocking rules (by Application, Domain, IP, or Port), and exports filtered, Wireshark-compatible packet captures.

---

## 📑 Table of Contents

- [Overview & Capabilities](#-overview--capabilities)
- [How Layer 7 DPI Works](#-how-layer-7-dpi-works)
- [Project Architecture](#-project-architecture)
- [Quick Start on Windows (Step-by-Step)](#-quick-start-on-windows-step-by-step)
- [Usage Examples & Commands](#-usage-examples--commands)
  - [1. Basic Packet Analysis](#1-basic-packet-analysis)
  - [2. Blocking Applications](#2-blocking-applications)
  - [3. Blocking Domains & Hostnames](#3-blocking-domains--hostnames)
  - [4. Blocking Client IP Addresses](#4-blocking-client-ip-addresses)
  - [5. Combining Multiple Rules](#5-combining-multiple-rules)
  - [6. Using a Rules Configuration File](#6-using-a-rules-configuration-file)
  - [7. Generating Fresh Test Captures](#7-generating-fresh-test-captures)
- [Supported Applications](#-supported-applications)
- [C++ Compilation on Windows (Optional)](#-c-compilation-on-windows-optional)
- [Project Directory Structure](#-project-directory-structure)
- [Verifying in Wireshark](#-verifying-in-wireshark)
- [Troubleshooting & FAQ](#-troubleshooting--faq)

---

## 🚀 Overview & Capabilities

Traditional firewalls only inspect Layer 3 and Layer 4 headers (IP addresses and TCP/UDP ports). However, modern web applications all share port `443` (HTTPS) and obscure individual traffic inside encrypted TLS sessions. 

This **DPI Engine** bridges that gap by implementing deep inspection:
- **Layer 7 Application Identification**: Identifies the destination application (e.g. YouTube, Netflix, TikTok, Discord) even over encrypted HTTPS by extracting the plaintext **Server Name Indication (SNI)** in the initial TLS Client Hello handshake.
- **HTTP & DNS Extraction**: Parses Host headers in plain HTTP requests and resolves query domains in UDP DNS queries (Port 53).
- **Stateful 5-Tuple Connection Tracking**: Tracks active sessions bidirectionally across `(Source IP, Destination IP, Source Port, Destination Port, Protocol)`. When a flow is blocked, all subsequent traffic in both directions is dropped.
- **Multi-Level Firewall Filtering**:
  - **By Application**: Block entire platforms (e.g., YouTube, Facebook, Spotify).
  - **By Domain**: Block wildcard patterns (e.g., `*.tiktok.com`, `ads.*`, `facebook`).
  - **By IP Address**: Drop packets originating from or destined to specific hosts.
  - **By Port**: Drop packets targeting specified network ports.
- **Clean PCAP Export**: Writes an industry-standard, Wireshark-compatible `.pcap` containing only forwarded (allowed) packets.
- **Dual Engine Options**:
  1. **Native Python Engine (`dpi_engine.py`)**: Zero external dependencies, works out of the box on Windows with standard Python 3.
  2. **Multi-Threaded C++17 Engine (`src/dpi_mt.cpp`)**: High-throughput pipeline utilizing Load Balancers and Fast Path worker threads.

---

## 🧠 How Layer 7 DPI Works

### The TLS SNI Extraction Technique

When an HTTPS connection is established, the client initiates a **TLS Handshake** before encryption keys are negotiated. The very first packet sent by the client is the **Client Hello**. 

Within this Client Hello is a TLS extension called **Server Name Indication (SNI)**, which specifies the hostname the client wants to connect to (e.g., `www.youtube.com`). **This field is sent in cleartext**:

```
[Ethernet Header] (14 bytes)
  └── [IPv4 Header] (20 bytes: Src IP, Dst IP, Protocol=6)
        └── [TCP Header] (20 bytes: Src Port, Dst Port=443)
              └── [TLS Record Header] (5 bytes: Type 0x16 = Handshake)
                    └── [Handshake: Client Hello] (Type 0x01)
                          └── [Extensions Section]
                                └── [Extension: 0x0000 (SNI)]
                                      └── "www.youtube.com" (Plaintext!)
```

The DPI Engine parses each layer:
1. Validates the PCAP global and per-packet headers (handling big-endian and little-endian captures).
2. Strips Ethernet headers (including 802.1Q VLAN tags).
3. Parses IPv4 headers to isolate protocol and endpoints.
4. Identifies TCP/UDP transport payloads.
5. On port 443, walks the TLS Handshake byte structure to locate extension `0x0000`, decoding the target hostname.
6. Maps the hostname to an application signature table.
7. Evaluates active blocking rules. If a rule triggers, marks the 5-tuple flow as **BLOCKED** and drops the packet. Allowed packets are immediately written to the output file.

---

## 🏛 Project Architecture

```
                       ┌─────────────────────────┐
                       │     Input PCAP File     │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   PCAP Reader & Parser  │ (Endianness & Layer 2-4)
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  5-Tuple Flow Tracker   │ (Bidirectional Sessions)
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   Layer 7 DPI Engine    │
                       │ ┌─────────────────────┐ │
                       │ │ TLS SNI Extractor   │ │ (Port 443)
                       │ ├─────────────────────┤ │
                       │ │ HTTP Host Parser    │ │ (Port 80)
                       │ ├─────────────────────┤ │
                       │ │ DNS Query Parser    │ │ (Port 53)
                       │ └─────────────────────┘ │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   Rule Manager Engine   │
                       │ (App, Domain, IP, Port) │
                       └─────┬─────────────┬─────┘
                             │             │
                    MATCHED  │             │ PERMITTED
                             ▼             ▼
                      [DROP PACKET]  [FORWARD PACKET]
                                           │
                                           ▼
                             ┌───────────────────────────┐
                             │    Filtered Output PCAP   │
                             └───────────────────────────┘
```

---

## ⚡ Quick Start on Windows (Step-by-Step)

You can run the engine on Windows immediately with Python 3—no compiler installation or visual studio required!

### Step 1: Open Terminal in the Project Directory

Open **PowerShell** or **Command Prompt** (cmd) and navigate to the `Packet analyzer` folder:

```powershell
cd "E:\repos\Deep Packet Inspection\Packet analyzer"
```

### Step 2: Run a Basic Analysis

Analyze the provided sample capture (`test_dpi.pcap`) and write filtered results to `output.pcap`:

Using the Windows batch shortcut:
```cmd
.\dpi.bat test_dpi.pcap output.pcap
```

Or using PowerShell launcher:
```powershell
.\dpi.ps1 test_dpi.pcap output.pcap
```

Or calling Python directly:
```powershell
python dpi_engine.py test_dpi.pcap output.pcap
```

### Step 3: Run with Application Blocking

Block YouTube and Netflix traffic:

```powershell
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-app Netflix
```

### Step 4: Review the Console Report

The engine prints real-time alerts for blocked connections followed by an analytical breakdown:

```text
╔══════════════════════════════════════════════════════════════╗
║                PACKET ANALYZER & DPI ENGINE                  ║
║             Layer 7 Deep Packet Inspection System            ║
╠══════════════════════════════════════════════════════════════╣
║ Input File:     test_dpi.pcap                                ║
║ Output File:    output.pcap                                  ║
╚══════════════════════════════════════════════════════════════╝
[*] Blocked Applications : netflix, youtube

[Engine] Analyzing packet capture stream...
  [BLOCKED] 192.168.1.100:58867 -> 142.250.185.110:443 | App: YouTube (www.youtube.com) | Reason: Application 'YouTube'
  [BLOCKED] 192.168.1.100:50684 -> 23.52.167.61:443 | App: Netflix (www.netflix.com) | Reason: Application 'Netflix'

╔══════════════════════════════════════════════════════════════╗
║                     PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets Analyzed:            77                        ║
║ Packets Forwarded:                 75                        ║
║ Packets Dropped (Blocked):          2                        ║
║ Total Connections (Flows):         27                        ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                 55   71.4%  ##############             ║
║ DNS                    4    5.2%  #                          ║
║ HTTP                   2    2.6%                             ║
║ Google                 1    1.3%                             ║
║ Facebook               1    1.3%                             ║
║ Discord                1    1.3%                             ║
║ ...                                                          ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🛠 Usage Examples & Commands

### 1. Basic Packet Analysis
Analyze traffic distribution without blocking any packets:
```powershell
python dpi_engine.py test_dpi.pcap output.pcap
```

### 2. Blocking Applications
Block traffic for specific platforms by name (case-insensitive):
```powershell
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube
python dpi_engine.py test_dpi.pcap output.pcap --block-app TikTok --block-app Discord
```

### 3. Blocking Domains & Hostnames
Block specific domains or wildcard patterns:
```powershell
# Block any domain containing "facebook"
python dpi_engine.py test_dpi.pcap output.pcap --block-domain facebook

# Block using wildcard pattern
python dpi_engine.py test_dpi.pcap output.pcap --block-domain "*.spotify.com"
```

### 4. Blocking Client IP Addresses
Drop all packets coming from or going to a specific IP:
```powershell
python dpi_engine.py test_dpi.pcap output.pcap --block-ip 192.168.1.50
```

### 5. Combining Multiple Rules
Combine application, domain, IP, and port rules into a single command:
```powershell
python dpi_engine.py test_dpi.pcap output.pcap `
    --block-app YouTube `
    --block-app TikTok `
    --block-domain facebook `
    --block-ip 192.168.1.50
```

### 6. Using a Rules Configuration File
Store rules in a text file (such as `rules.example.txt`):

```ini
# rules.example.txt
[BLOCKED_APPS]
YouTube
TikTok
Netflix

[BLOCKED_DOMAINS]
facebook
spotify

[BLOCKED_IPS]
192.168.1.50
```

Execute with the `--rules` flag:
```powershell
python dpi_engine.py test_dpi.pcap output.pcap --rules rules.example.txt
```

### 7. Generating Fresh Test Captures
Regenerate a sample PCAP file containing TLS Client Hello handshakes, HTTP requests, DNS queries, and blocked IP test traffic:
```powershell
python generate_test_pcap.py
```
This produces a fresh `test_dpi.pcap` with 77 realistic packets.

---

## 📱 Supported Applications

The DPI engine includes built-in Layer 7 signature detection for:

| Application | Detection Signatures |
| :--- | :--- |
| **YouTube** | `youtube`, `ytimg`, `youtu.be`, `yt3.ggpht`, `googlevideo.com` |
| **Google** | `google`, `gstatic`, `googleapis`, `ggpht`, `1e100.net` |
| **Facebook** | `facebook`, `fbcdn`, `fb.com`, `meta.com`, `messenger.com` |
| **Instagram** | `instagram`, `cdninstagram` |
| **WhatsApp** | `whatsapp`, `wa.me` |
| **Twitter / X** | `twitter`, `twimg`, `x.com`, `t.co` |
| **Netflix** | `netflix`, `nflxvideo`, `nflximg`, `nflxext.com` |
| **Amazon** | `amazon`, `amazonaws`, `cloudfront`, `aws` |
| **Microsoft** | `microsoft`, `office`, `azure`, `live.com`, `outlook`, `bing` |
| **Apple** | `apple`, `icloud`, `mzstatic`, `itunes`, `aaplimg.com` |
| **TikTok** | `tiktok`, `tiktokcdn`, `musical.ly`, `bytedance` |
| **Spotify** | `spotify`, `scdn.co`, `spoti.fi` |
| **Telegram** | `telegram`, `t.me` |
| **Discord** | `discord`, `discordapp`, `discord.gg` |
| **Zoom** | `zoom`, `zoom.us` |
| **GitHub** | `github`, `githubusercontent`, `github.io` |
| **Cloudflare** | `cloudflare`, `cf-`, `cloudflare.net` |
| **Reddit** | `reddit`, `redditmedia`, `redd.it` |
| **Twitch** | `twitch`, `ttvnw.net`, `jtvnw.net` |
| **Steam** | `steampowered`, `steamcommunity`, `steamstatic` |

*Custom signatures can be added in `dpi_engine.py` under `APP_SIGNATURES` or in C++ under `include/types.h`.*

---

## 💻 C++ Compilation on Windows (Optional)

If you have a C++17 compiler (Visual Studio, MinGW, or CMake) and want to build the multi-threaded native C++ engine:

### Option A: Automatic Build Script
Run the automated detection script:
```cmd
build_windows.bat
```

### Option B: Visual Studio (MSVC)
Open **Developer Command Prompt for VS 2022**:
```cmd
cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe src\dpi_mt.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp
```

### Option C: MinGW-w64 (g++)
```cmd
g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

### Option D: CMake
```cmd
cmake -B build
cmake --build build --config Release
```

Once built, execute with:
```cmd
dpi_engine.exe test_dpi.pcap output.pcap --block-app YouTube
```

---

## 📂 Project Directory Structure

```text
Packet analyzer/
│
├── dpi_engine.py            # Native Windows Layer 7 DPI Engine (Python 3)
├── dpi.bat                  # Windows Command Prompt launcher
├── dpi.ps1                  # Windows PowerShell launcher
├── build_windows.bat        # Automated C++ compiler detection & build script
├── CMakeLists.txt           # Cross-platform CMake configuration
│
├── rules.example.txt        # Sample configuration file for blocking rules
├── generate_test_pcap.py    # Generates realistic PCAP files with SNI, HTTP, DNS
├── test_dpi.pcap            # Test packet capture dataset
├── output.pcap              # Generated filtered output capture
│
├── README.md                # Detailed project documentation
├── WINDOWS_SETUP.md         # Windows compiler & environment setup guide
│
├── include/                 # C++ Header files
│   ├── connection_tracker.h # Flow state & connection management
│   ├── dpi_engine.h         # Modular DPI engine interfaces
│   ├── fast_path.h          # Worker thread packet processing
│   ├── load_balancer.h      # 5-tuple hash distribution
│   ├── packet_parser.h      # Layer 2-4 headers (Ethernet, IP, TCP, UDP)
│   ├── pcap_reader.h        # Binary PCAP stream reader
│   ├── platform.h           # Portable byte-order / endianness routines
│   ├── rule_manager.h       # Rule storage & evaluation
│   ├── sni_extractor.h      # TLS Client Hello SNI parser
│   ├── thread_safe_queue.h  # Lock-based inter-thread communication queue
│   └── types.h              # Data structures & application definitions
│
└── src/                     # C++ Source implementations
    ├── connection_tracker.cpp
    ├── dpi_engine.cpp
    ├── dpi_mt.cpp           # Complete standalone multi-threaded engine
    ├── fast_path.cpp
    ├── load_balancer.cpp
    ├── main.cpp             # Packet summary inspector
    ├── main_dpi.cpp         # Modular pipeline entry point
    ├── main_simple.cpp
    ├── main_working.cpp
    ├── packet_parser.cpp
    ├── pcap_reader.cpp
    ├── rule_manager.cpp
    ├── sni_extractor.cpp
    └── types.cpp
```

---

## 🔍 Verifying in Wireshark

To confirm that the DPI Engine correctly blocked and dropped unauthorized traffic:

1. Open **Wireshark**.
2. Open `test_dpi.pcap` (the original capture) in Wireshark:
   - Notice packets destined for YouTube (`142.250.185.110`) or containing `ssl.handshake.extensions_server_name == "www.youtube.com"`.
3. Open `output.pcap` (the filtered capture) in a second Wireshark window:
   - Apply filter: `ssl.handshake.extensions_server_name contains "youtube"`
   - Result: **0 packets found!** All YouTube packets and associated TCP streams were cleanly dropped.
4. Verify packet count: Notice the total packet count decreased by the exact number of dropped packets reported in the summary table.

---

## ❓ Troubleshooting & FAQ

### Q: Do I need to install WinPcap or Npcap?
**No.** This DPI engine reads and writes standard `.pcap` capture files directly at the binary level using pure portable code. It does not require Npcap, WinPcap, or driver installations.

### Q: Why not use a raw socket on Windows?
Windows restricts raw socket packet capture and injection (promiscuous mode) for unprivileged users and blocks raw TCP traffic. Analyzing `.pcap` files provides 100% deterministic, reproducible, and safe packet inspection without requiring elevated kernel drivers.

### Q: Does it inspect traffic if the user uses a VPN?
If the user's traffic is encapsulated inside a VPN tunnel (e.g. WireGuard, OpenVPN, or IPsec), the outer packet is encrypted UDP. To inspect VPN traffic, the DPI engine must be placed at the VPN egress gateway or on the decrypted tunnel interface.

### Q: What if an application doesn't send an SNI extension?
For non-SNI HTTPS traffic, the engine falls back to port classification (`HTTPS`) or IP classification. For plain HTTP, it extracts the `Host:` header; for DNS, it extracts the question query name.

---

## 📄 License
This project is licensed under the MIT License.
