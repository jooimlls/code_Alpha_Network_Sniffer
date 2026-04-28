import argparse
import sys

try:
    from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Raw, sniff
except ImportError:
    sys.exit("scapy is not installed. Run: pip install scapy")


# --------------------- Helpers ------------------------------

def get_payload(packet) -> str:
    """Return a safe ASCII preview of the raw payload (first 60 bytes)."""
    if packet.haslayer(Raw):
        raw = packet[Raw].load[:60]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    return "(no payload)"


# ------------------- Packet handler -----------------------

def process_packet(packet):
    print("\n" + "=" * 55)

    # ------------------ ARP ─---------------------
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op  = "Request" if arp.op == 1 else "Reply"
        print(f"  Protocol       : ARP ({op})")
        print(f"  Sender IP/MAC  : {arp.psrc}  /  {arp.hwsrc}")
        print(f"  Target IP/MAC  : {arp.pdst}  /  {arp.hwdst}")
        return

    # ------------------IP-based packets ------------------------
    if not packet.haslayer(IP):
        print("  Protocol       : Non-IP frame (skipped)")
        return

    ip = packet[IP]
    print(f"  Source IP      : {ip.src}")
    print(f"  Destination IP : {ip.dst}")
    print(f"  Packet size    : {len(packet)} bytes")

    # ---------------------- ICMP -----------------------
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        type_names = {
            0: "Echo Reply", 8: "Echo Request",
            3: "Destination Unreachable", 11: "Time Exceeded",
        }
        itype = type_names.get(icmp.type, f"Type {icmp.type}")
        print(f"  Protocol       : ICMP  —  {itype}")
        return

    # -------------------- TCP -------------------
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flag_map = {"S": "SYN", "A": "ACK", "F": "FIN",
                    "R": "RST", "P": "PSH", "U": "URG"}
        flags = " | ".join(v for k, v in flag_map.items() if k in str(tcp.flags))

        if packet.haslayer(DNS):
            proto = "DNS over TCP"
        elif tcp.dport == 80 or tcp.sport == 80:
            proto = "HTTP (TCP 80)"
        elif tcp.dport == 443 or tcp.sport == 443:
            proto = "HTTPS (TCP 443)"
        else:
            proto = "TCP"

        print(f"  Protocol       : {proto}")
        print(f"  Src Port       : {tcp.sport}")
        print(f"  Dst Port       : {tcp.dport}")
        print(f"  TCP Flags      : {flags}")
        print(f"  Payload        : {get_payload(packet)}")
        return

    # -----------UDP / DNS --------------------------
    if packet.haslayer(UDP):
        udp = packet[UDP]

        if packet.haslayer(DNS):
            dns = packet[DNS]
            print(f"  Protocol       : DNS (UDP 53)")
            print(f"  Src Port       : {udp.sport}")
            print(f"  Dst Port       : {udp.dport}")
            if dns.qr == 0 and packet.haslayer(DNSQR):  
                name = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                print(f"  DNS Query      : {name}")
            elif dns.qr == 1 and packet.haslayer(DNSRR):  
                rr = packet[DNSRR]
                name   = rr.rrname.decode(errors="replace").rstrip(".")
                rdata  = rr.rdata if isinstance(rr.rdata, str) else str(rr.rdata)
                print(f"  DNS Response   : {name} -> {rdata}")
        else:
            print(f"  Protocol       : UDP")
            print(f"  Src Port       : {udp.sport}")
            print(f"  Dst Port       : {udp.dport}")
            print(f"  Payload        : {get_payload(packet)}")
        return

    # ── Unknown IP protocol ───────────────────────────────────────
    print(f"  Protocol       : Other (proto={ip.proto})")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("-i", "--iface",  default=None, help="Network interface")
    parser.add_argument("-c", "--count",  type=int, default=10,
                        help="Number of packets to capture (default: 10)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter e.g. "tcp port 80"')
    args = parser.parse_args()

    iface_label = args.iface or "auto"
    filt_label  = args.filter or "none"

    print("=" * 55)
    print("  Packet Sniffer")
    print(f"  Interface : {iface_label}")
    print(f"  Filter    : {filt_label}")
    print(f"  Count     : {args.count}")
    print("=" * 55)
    print("  Capturing... Press Ctrl+C to stop early.\n")

    sniff_kwargs = dict(
        prn=process_packet,
        store=False,
        count=args.count,
    )
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        sys.exit("\nPermission denied — run with sudo.\n")
    except KeyboardInterrupt:
        pass

    print("\n" + "=" * 55)
    print("  Capture complete.")
    print("=" * 55)


if __name__ == "__main__":
    main()