import argparse
import sys

try:
    from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Raw, sniff
    from scapy.error import Scapy_Exception
except ImportError:
    sys.exit("scapy is not installed. Run: pip install scapy")


SEPARATOR = "=" * 55
PAYLOAD_PREVIEW_BYTES = 60


def get_payload(packet) -> str:
    """Return a safe ASCII preview of the raw payload."""
    if packet.haslayer(Raw):
        raw = packet[Raw].load[:PAYLOAD_PREVIEW_BYTES]
        return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in raw)
    return "(no payload)"


def decode_dns_name(value) -> str:
    """Decode DNS fields returned by Scapy without crashing on odd bytes."""
    if isinstance(value, bytes):
        return value.decode(errors="replace").rstrip(".")
    return str(value).rstrip(".")


def format_tcp_flags(flags) -> str:
    flag_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    readable_flags = [name for flag, name in flag_map.items() if flag in str(flags)]
    return " | ".join(readable_flags) if readable_flags else "(none)"


def guess_tcp_protocol(packet, tcp) -> str:
    if packet.haslayer(DNS):
        return "DNS over TCP"
    if 80 in (tcp.sport, tcp.dport):
        return "HTTP (TCP 80)"
    if 443 in (tcp.sport, tcp.dport):
        return "HTTPS (TCP 443)"
    if 22 in (tcp.sport, tcp.dport):
        return "SSH (TCP 22)"
    return "TCP"


def print_dns_packet(packet, udp) -> None:
    dns = packet[DNS]
    print("  Protocol       : DNS (UDP 53)")
    print(f"  Src Port       : {udp.sport}")
    print(f"  Dst Port       : {udp.dport}")

    if dns.qr == 0 and packet.haslayer(DNSQR):
        query = packet[DNSQR]
        print(f"  DNS Query      : {decode_dns_name(query.qname)}")
        return

    if dns.qr != 1:
        return

    print(f"  Answer Count   : {dns.ancount}")
    for index in range(dns.ancount):
        answer = dns.an[index]
        if not isinstance(answer, DNSRR):
            continue

        name = decode_dns_name(answer.rrname)
        rdata = decode_dns_name(answer.rdata)
        print(f"  DNS Answer {index + 1:<2}: {name} -> {rdata}")


def process_packet(packet) -> None:
    print("\n" + SEPARATOR)

    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"op={arp.op}"
        print(f"  Protocol       : ARP ({op})")
        print(f"  Sender IP/MAC  : {arp.psrc}  /  {arp.hwsrc}")
        print(f"  Target IP/MAC  : {arp.pdst}  /  {arp.hwdst}")
        return

    if not packet.haslayer(IP):
        print("  Protocol       : Non-IP frame (skipped)")
        return

    ip = packet[IP]
    print(f"  Source IP      : {ip.src}")
    print(f"  Destination IP : {ip.dst}")
    print(f"  Packet size    : {len(packet)} bytes")

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        type_names = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            8: "Echo Request",
            11: "Time Exceeded",
        }
        icmp_type = type_names.get(icmp.type, f"Type {icmp.type}")
        print(f"  Protocol       : ICMP - {icmp_type}")
        return

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"  Protocol       : {guess_tcp_protocol(packet, tcp)}")
        print(f"  Src Port       : {tcp.sport}")
        print(f"  Dst Port       : {tcp.dport}")
        print(f"  TCP Flags      : {format_tcp_flags(tcp.flags)}")
        print(f"  Payload        : {get_payload(packet)}")
        return

    if packet.haslayer(UDP):
        udp = packet[UDP]
        if packet.haslayer(DNS):
            print_dns_packet(packet, udp)
        else:
            print("  Protocol       : UDP")
            print(f"  Src Port       : {udp.sport}")
            print(f"  Dst Port       : {udp.dport}")
            print(f"  Payload        : {get_payload(packet)}")
        return

    print(f"  Protocol       : Other (proto={ip.proto})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("-i", "--iface", default=None, help="Network interface")
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=10,
        help="Number of packets to capture. Use 0 to run until stopped. (default: 10)",
    )
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')

    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be 0 or greater")

    return args


def main() -> None:
    args = parse_args()

    iface_label = args.iface or "auto"
    filter_label = args.filter or "none"

    print(SEPARATOR)
    print("  Packet Sniffer")
    print(f"  Interface : {iface_label}")
    print(f"  Filter    : {filter_label}")
    print(f"  Count     : {args.count}")
    print(SEPARATOR)
    print("  Capturing... Press Ctrl+C to stop early.\n")

    sniff_kwargs = {
        "prn": process_packet,
        "store": False,
        "count": args.count,
    }
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        sys.exit("\nPermission denied. Run this script as Administrator/root.\n")
    except Scapy_Exception as error:
        sys.exit(f"\nScapy error: {error}\n")
    except KeyboardInterrupt:
        pass

    print("\n" + SEPARATOR)
    print("  Capture complete.")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
