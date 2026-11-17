#!/usr/bin/env python3
"""
Deep Packet Inspection (DPI) & Packet Analyzer Engine
Layer 7 Protocol Analysis, Application Identification & Traffic Filtering
Cross-Platform Native Python Implementation (Windows, macOS, Linux)
"""

import sys
import os
import struct
import socket
import argparse
from collections import defaultdict

# ============================================================================
# Application Signatures Database
# ============================================================================
APP_SIGNATURES = [
    ("YouTube",    ["youtube", "ytimg", "youtu.be", "yt3.ggpht", "googlevideo.com"]),
    ("Google",     ["google", "gstatic", "googleapis", "ggpht", "gvt1", "1e100.net"]),
    ("Facebook",   ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com", "messenger.com"]),
    ("Instagram",  ["instagram", "cdninstagram"]),
    ("WhatsApp",   ["whatsapp", "wa.me"]),
    ("Twitter/X",  ["twitter", "twimg", "x.com", "t.co"]),
    ("Netflix",    ["netflix", "nflxvideo", "nflximg", "nflxext.com"]),
    ("Amazon",     ["amazon", "amazonaws", "cloudfront", "aws"]),
    ("Microsoft",  ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing", "windows"]),
    ("Apple",      ["apple", "icloud", "mzstatic", "itunes", "aaplimg.com"]),
    ("Telegram",   ["telegram", "t.me"]),
    ("TikTok",     ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]),
    ("Spotify",    ["spotify", "scdn.co", "spoti.fi"]),
    ("Zoom",       ["zoom", "zoom.us"]),
    ("Discord",    ["discord", "discordapp", "discord.gg", "discord.media"]),
    ("GitHub",     ["github", "githubusercontent", "github.io"]),
    ("Cloudflare", ["cloudflare", "cf-", "cloudflare.net"]),
    ("Reddit",     ["reddit", "redditmedia", "redd.it"]),
    ("Twitch",     ["twitch", "ttvnw.net", "jtvnw.net"]),
    ("Steam",      ["steampowered", "steamcommunity", "steamstatic"]),
]

def domain_matches(sni: str, pattern: str) -> bool:
    """Check if SNI or domain matches pattern, supporting wildcards."""
    pattern = pattern.strip().lower()
    sni = sni.strip().lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return sni == suffix or sni.endswith("." + suffix)
    if "." in pattern:
        return sni == pattern or sni.endswith("." + pattern)
    return pattern in sni

def sni_to_app(sni: str) -> str:
    """Identify application type from extracted SNI / hostname."""
    if not sni:
        return "Unknown"
    lower_sni = sni.lower()
    for app_name, patterns in APP_SIGNATURES:
        for p in patterns:
            if domain_matches(lower_sni, p):
                return app_name
    return "HTTPS"


# ============================================================================
# Protocol Extractors (Layer 7 DPI)
# ============================================================================
def extract_tls_sni(payload: bytes) -> str | None:
    """
    Extract Server Name Indication (SNI) from TLS Client Hello handshake.
    The Client Hello is transmitted unencrypted before the TLS session key exchange.
    """
    try:
        # Minimum TLS record header (5 bytes) + Handshake header (4 bytes)
        if len(payload) < 9:
            return None

        # Content Type: 0x16 = Handshake
        if payload[0] != 0x16:
            return None

        # TLS Version check (SSL 3.0 to TLS 1.3: 0x0300 to 0x0304)
        version = struct.unpack(">H", payload[1:3])[0]
        if not (0x0300 <= version <= 0x0304):
            return None

        # Record length
        record_len = struct.unpack(">H", payload[3:5])[0]
        max_len = min(len(payload) - 5, record_len)
        if max_len < 4:
            return None

        # Handshake Type: 0x01 = Client Hello
        if payload[5] != 0x01:
            return None

        offset = 5  # Handshake header starts
        # Skip: Handshake type (1 byte) + Length (3 bytes) + Client Version (2 bytes) + Random (32 bytes)
        offset += 1 + 3 + 2 + 32
        if offset >= len(payload):
            return None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(payload):
            return None

        # Cipher Suites
        cipher_len = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2 + cipher_len
        if offset >= len(payload):
            return None

        # Compression Methods
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload):
            return None

        # Extensions Total Length
        ext_total_len = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2
        ext_end = min(offset + ext_total_len, len(payload))

        # Iterate through Extensions
        while offset + 4 <= ext_end:
            ext_type = struct.unpack(">H", payload[offset:offset+2])[0]
            ext_len = struct.unpack(">H", payload[offset+2:offset+4])[0]
            offset += 4

            if ext_type == 0x0000:  # Server Name Indication (SNI)
                sni_data = payload[offset:offset+ext_len]
                if len(sni_data) >= 5:
                    # list_length (2 bytes) + name_type (1 byte, 0x00=host_name) + name_len (2 bytes)
                    name_type = sni_data[2]
                    if name_type == 0x00:
                        name_len = struct.unpack(">H", sni_data[3:5])[0]
                        sni_bytes = sni_data[5:5+name_len]
                        return sni_bytes.decode("utf-8", errors="ignore")
                return None

            offset += ext_len
    except Exception:
        pass
    return None


def extract_http_host(payload: bytes) -> str | None:
    """Extract Host header value from plain HTTP requests."""
    try:
        header_text = payload[:1024].decode("latin-1", errors="ignore")
        first_line = header_text.split("\r\n", 1)[0]
        http_methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ")
        if not any(first_line.startswith(m) for m in http_methods):
            return None

        for line in header_text.split("\r\n"):
            if line.lower().startswith("host:"):
                host_val = line.split(":", 1)[1].strip()
                return host_val.split(":")[0]  # Strip port if present
    except Exception:
        pass
    return None


def extract_dns_query(payload: bytes) -> str | None:
    """Extract queried domain name from DNS request payload (UDP port 53)."""
    try:
        if len(payload) < 12:
            return None
        # DNS header: ID(2), Flags(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        qdcount = struct.unpack(">H", payload[4:6])[0]
        if qdcount == 0:
            return None

        offset = 12
        domain_parts = []
        while offset < len(payload):
            length = payload[offset]
            offset += 1
            if length == 0:
                break
            if length > 63 or offset + length > len(payload):
                return None
            part = payload[offset:offset+length].decode("latin-1", errors="ignore")
            domain_parts.append(part)
            offset += length

        if domain_parts:
            return ".".join(domain_parts)
    except Exception:
        pass
    return None


# ============================================================================
# Deep Packet Inspection & Filtering Engine
# ============================================================================
class DPIEngine:
    def __init__(self, block_ips=None, block_apps=None, block_domains=None, block_ports=None, verbose=False):
        self.block_ips = set(block_ips or [])
        self.block_apps = set(a.strip().lower() for a in (block_apps or []))
        self.block_domains = [d.strip().lower() for d in (block_domains or [])]
        self.block_ports = set(int(p) for p in (block_ports or []))
        self.verbose = verbose

        # Connection flow table: maps 5-tuple -> FlowInfo dict
        self.flows = {}
        self.app_stats = defaultdict(int)
        self.total_packets = 0
        self.forwarded = 0
        self.dropped = 0
        self.dns_queries = {}

    def load_rules_file(self, filepath: str):
        """Load blocking rules from configuration file."""
        if not os.path.exists(filepath):
            print(f"[Warning] Rules file not found: {filepath}")
            return

        current_section = None
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("[") and line.endswith("]"):
                    current_section = line.upper()
                    continue

                if current_section == "[BLOCKED_IPS]":
                    self.block_ips.add(line)
                elif current_section == "[BLOCKED_APPS]":
                    self.block_apps.add(line.lower())
                elif current_section == "[BLOCKED_DOMAINS]":
                    self.block_domains.append(line.lower())
                elif current_section == "[BLOCKED_PORTS]":
                    try:
                        self.block_ports.add(int(line))
                    except ValueError:
                        pass
                else:
                    # Fallback key-value parsing: block-app <app>, block-ip <ip>, etc.
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, val = parts[0].lower(), parts[1].strip()
                        if key in ("block-app", "block_app", "app"):
                            self.block_apps.add(val.lower())
                        elif key in ("block-ip", "block_ip", "ip"):
                            self.block_ips.add(val)
                        elif key in ("block-domain", "block_domain", "domain"):
                            self.block_domains.append(val.lower())
                        elif key in ("block-port", "block_port", "port"):
                            try:
                                self.block_ports.add(int(val))
                            except ValueError:
                                pass

    def should_block(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, app_type: str, domain: str):
        """Evaluate blocking rules against packet properties. Returns (bool, reason_string)."""
        # IP blocking (source or destination match)
        if src_ip in self.block_ips:
            return True, f"IP {src_ip}"
        if dst_ip in self.block_ips:
            return True, f"IP {dst_ip}"

        # Port blocking
        if dst_port in self.block_ports:
            return True, f"Port {dst_port}"
        if src_port in self.block_ports:
            return True, f"Port {src_port}"

        # Application blocking
        if app_type.lower() in self.block_apps:
            return True, f"Application '{app_type}'"

        # Domain / SNI blocking
        if domain:
            lower_dom = domain.lower()
            for pattern in self.block_domains:
                if domain_matches(lower_dom, pattern):
                    return True, f"Domain pattern '{pattern}'"

        return False, ""

    def process(self, input_pcap: str, output_pcap: str = None) -> bool:
        """Process input PCAP, classify packets, enforce rules, and write filtered PCAP."""
        if not os.path.exists(input_pcap):
            print(f"[Error] Input PCAP file does not exist: {input_pcap}")
            return False

        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                PACKET ANALYZER & DPI ENGINE                  ║")
        print("║             Layer 7 Deep Packet Inspection System            ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Input File:     {input_pcap:<44} ║")
        out_display = output_pcap if output_pcap else "(Analysis only - no export)"
        print(f"║ Output File:    {out_display:<44} ║")
        print("╚══════════════════════════════════════════════════════════════╝")

        # Active rules display
        if self.block_apps:
            print(f"[*] Blocked Applications : {', '.join(sorted(self.block_apps))}")
        if self.block_domains:
            print(f"[*] Blocked Domains      : {', '.join(sorted(self.block_domains))}")
        if self.block_ips:
            print(f"[*] Blocked IPs          : {', '.join(sorted(self.block_ips))}")
        if self.block_ports:
            print(f"[*] Blocked Ports        : {', '.join(str(p) for p in sorted(self.block_ports))}")

        print("\n[Engine] Analyzing packet capture stream...")

        fout = None
        try:
            fin = open(input_pcap, "rb")
            if output_pcap:
                fout = open(output_pcap, "wb")
        except Exception as e:
            print(f"[Error] Failed to open file: {e}")
            return False

        try:
            # Read 24-byte PCAP global header
            global_hdr = fin.read(24)
            if len(global_hdr) < 24:
                print("[Error] Invalid or truncated PCAP header.")
                return False

            magic = struct.unpack("<I", global_hdr[:4])[0]
            swapped = False
            if magic in (0xa1b2c3d4, 0xa1b23c4d):
                swapped = False
            elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
                swapped = True
            else:
                print(f"[Error] Unrecognized PCAP magic number: {hex(magic)}")
                return False

            if fout:
                fout.write(global_hdr)

            # Packet processing loop
            while True:
                pkt_hdr_data = fin.read(16)
                if len(pkt_hdr_data) < 16:
                    break

                if swapped:
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(">IIII", pkt_hdr_data)
                else:
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr_data)

                packet_bytes = fin.read(incl_len)
                if len(packet_bytes) < incl_len:
                    break

                self.total_packets += 1

                # Layer 2: Ethernet Header (14 bytes)
                if len(packet_bytes) < 14:
                    continue

                ethertype = struct.unpack(">H", packet_bytes[12:14])[0]
                ip_offset = 14

                # 802.1Q VLAN support
                if ethertype == 0x8100:
                    ethertype = struct.unpack(">H", packet_bytes[16:18])[0]
                    ip_offset = 18

                # Non-IPv4 packets (ARP, IPv6, etc.)
                if ethertype != 0x0800:
                    self.forwarded += 1
                    self.app_stats["Non-IPv4"] += 1
                    if fout:
                        fout.write(pkt_hdr_data)
                        fout.write(packet_bytes)
                    continue

                # Layer 3: IPv4 Header (minimum 20 bytes)
                if len(packet_bytes) < ip_offset + 20:
                    continue

                ip_hdr = packet_bytes[ip_offset:ip_offset+20]
                ihl = (ip_hdr[0] & 0x0F) * 4
                protocol = ip_hdr[9]
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])

                # Layer 4: Transport Layer (TCP / UDP)
                trans_offset = ip_offset + ihl
                src_port = 0
                dst_port = 0
                payload = b""

                if protocol == 6:  # TCP
                    if len(packet_bytes) >= trans_offset + 20:
                        src_port, dst_port = struct.unpack(">HH", packet_bytes[trans_offset:trans_offset+4])
                        tcp_hdr_len = ((packet_bytes[trans_offset+12] >> 4) & 0x0F) * 4
                        payload = packet_bytes[trans_offset+tcp_hdr_len:]
                elif protocol == 17:  # UDP
                    if len(packet_bytes) >= trans_offset + 8:
                        src_port, dst_port = struct.unpack(">HH", packet_bytes[trans_offset:trans_offset+4])
                        payload = packet_bytes[trans_offset+8:]

                # 5-Tuple Connection Identification (Bidirectional Flow Tracking)
                fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                rev_key = (dst_ip, src_ip, dst_port, src_port, protocol)

                flow = self.flows.get(fwd_key) or self.flows.get(rev_key)
                if flow is None:
                    flow = {
                        "app_type": "Unknown",
                        "domain": "",
                        "packets": 0,
                        "bytes": 0,
                        "blocked": False,
                        "block_reason": "",
                        "tuple": fwd_key,
                    }
                    self.flows[fwd_key] = flow
                    self.flows[rev_key] = flow

                flow["packets"] += 1
                flow["bytes"] += len(packet_bytes)

                # Layer 7 Deep Packet Inspection: Extract SNI / Host / DNS
                if not flow["domain"]:
                    # HTTPS (Port 443) -> TLS SNI extraction
                    if protocol == 6 and (dst_port == 443 or src_port == 443) and payload:
                        sni = extract_tls_sni(payload)
                        if sni:
                            flow["domain"] = sni
                            flow["app_type"] = sni_to_app(sni)

                    # HTTP (Port 80) -> Host header extraction
                    elif protocol == 6 and (dst_port == 80 or src_port == 80) and payload:
                        host = extract_http_host(payload)
                        if host:
                            flow["domain"] = host
                            flow["app_type"] = sni_to_app(host)

                    # DNS (Port 53) -> DNS Query domain extraction
                    elif protocol == 17 and (dst_port == 53 or src_port == 53) and payload:
                        dns_q = extract_dns_query(payload)
                        if dns_q:
                            flow["domain"] = dns_q
                            flow["app_type"] = "DNS"

                # Port-based heuristics fallback
                if flow["app_type"] == "Unknown":
                    if dst_port == 443 or src_port == 443:
                        flow["app_type"] = "HTTPS"
                    elif dst_port == 80 or src_port == 80:
                        flow["app_type"] = "HTTP"
                    elif dst_port == 53 or src_port == 53:
                        flow["app_type"] = "DNS"

                # Rule enforcement check
                if not flow["blocked"]:
                    blocked, reason = self.should_block(
                        src_ip, dst_ip, src_port, dst_port, flow["app_type"], flow["domain"]
                    )
                    if blocked:
                        flow["blocked"] = True
                        flow["block_reason"] = reason
                        domain_tag = f" ({flow['domain']})" if flow["domain"] else ""
                        print(f"  [BLOCKED] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | App: {flow['app_type']}{domain_tag} | Reason: {reason}")
                elif self.verbose and flow["blocked"]:
                    print(f"  [DROP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flow already blocked ({flow['block_reason']})")

                self.app_stats[flow["app_type"]] += 1

                # Packet disposition: Drop or Forward
                if flow["blocked"]:
                    self.dropped += 1
                else:
                    self.forwarded += 1
                    if fout:
                        fout.write(pkt_hdr_data)
                        fout.write(packet_bytes)

        finally:
            fin.close()
            if fout:
                fout.close()

        self.print_report(output_pcap)
        return True

    def print_report(self, output_pcap: str = None):
        """Print comprehensive analytics report."""
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                     PROCESSING REPORT                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets Analyzed:    {self.total_packets:>10}                        ║")
        print(f"║ Packets Forwarded:         {self.forwarded:>10}                        ║")
        print(f"║ Packets Dropped (Blocked): {self.dropped:>10}                        ║")
        # Deduplicate flows (each flow is stored under both forward and reverse keys)
        unique_flows = set(id(f) for f in self.flows.values())
        print(f"║ Total Connections (Flows): {len(unique_flows):>10}                        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                    APPLICATION BREAKDOWN                     ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        sorted_apps = sorted(self.app_stats.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / self.total_packets) if self.total_packets else 0
            bar = "#" * int(pct / 5)
            print(f"║ {app:<15} {count:>8}  {pct:>5.1f}%  {bar:<18} ║")

        print("╚══════════════════════════════════════════════════════════════╝")

        # List identified applications and domains
        flow_objs = {id(f): f for f in self.flows.values()}.values()
        detected_domains = {}
        for f in flow_objs:
            if f["domain"]:
                status = " [BLOCKED]" if f["blocked"] else ""
                detected_domains[f["domain"]] = f"{f['app_type']}{status}"

        if detected_domains:
            print("\n[Identified Applications & Domains]")
            for domain, info in sorted(detected_domains.items()):
                print(f"  • {domain:<35} -> {info}")

        if output_pcap:
            print(f"\n[+] Cleaned/Filtered PCAP written to: {output_pcap}")
            print(f"    (Open in Wireshark to verify blocked packets were filtered out)\n")


# ============================================================================
# CLI Entry Point
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Packet Analyzer & DPI Engine - Layer 7 Deep Packet Inspection & Filtering",
        usage="python dpi_engine.py <input.pcap> [output.pcap] [options]"
    )
    parser.add_argument("input", help="Path to input .pcap file")
    parser.add_argument("output", nargs="?", default="output.pcap", help="Path to output .pcap file (default: output.pcap)")
    parser.add_argument("--block-app", action="append", default=[], help="Block application by name (e.g., YouTube, TikTok, Netflix)")
    parser.add_argument("--block-ip", action="append", default=[], help="Block source/dest IP address (e.g., 192.168.1.50)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain substring or pattern (e.g., facebook, *.zoom.us)")
    parser.add_argument("--block-port", action="append", default=[], help="Block destination/source port (e.g., 8080)")
    parser.add_argument("--rules", default="", help="Path to blocking rules configuration file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed per-packet logs")

    args = parser.parse_args()

    engine = DPIEngine(
        block_ips=args.block_ip,
        block_apps=args.block_app,
        block_domains=args.block_domain,
        block_ports=args.block_port,
        verbose=args.verbose,
    )

    if args.rules:
        engine.load_rules_file(args.rules)

    success = engine.process(args.input, args.output)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
