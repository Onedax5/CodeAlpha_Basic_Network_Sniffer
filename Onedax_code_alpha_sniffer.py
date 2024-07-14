import argparse
from scapy.all import *
from prettytable import PrettyTable
import time

def handle_packet(packet, output_pcap=None):
    table = PrettyTable()
    table.field_names = ["Timestamp", "Packet Type", "Source", "Destination", "Protocol", "Details"]

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if ARP in packet:
        src_mac = packet[ARP].hwsrc
        src_ip = packet[ARP].psrc
        dst_mac = packet[ARP].hwdst
        dst_ip = packet[ARP].pdst
        table.add_row([timestamp, "ARP", f"{src_mac} ({src_ip})", f"{dst_mac} ({dst_ip})", "N/A", "N/A"])

    elif IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            src_ip_port = f"{src_ip}:{src_port}"
            dst_ip_port = f"{dst_ip}:{dst_port}"
            packet_type = "TCP"
            details = f"Protocol: {protocol}"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            src_ip_port = f"{src_ip}:{src_port}"
            dst_ip_port = f"{dst_ip}:{dst_port}"
            packet_type = "UDP"
            details = f"Protocol: {protocol}"
        elif ICMP in packet:
            src_ip_port = f"{src_ip}:N/A"
            dst_ip_port = f"{dst_ip}:N/A"
            packet_type = "ICMP"
            details = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        else:
            src_ip_port = "N/A"
            dst_ip_port = "N/A"
            packet_type = "IP"
            details = f"Protocol: {protocol}"

        table.add_row([timestamp, packet_type, src_ip_port, dst_ip_port, protocol, details])

    print(table)

    if output_pcap:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            pcap_writer.write(packet)

def start_sniffing(interface="eth0", packet_count=None, output_pcap=None, protocol_filters=None):
    if packet_count is None:
        packet_count = 99999999  # Set count to a large number if None
    captured_packets = []
    if protocol_filters is None:
        filter_expression = ""
    else:
        filter_expression = " or ".join([f"({f})" for f in protocol_filters.split(",")])
    try:
        sniffed_packets = sniff(iface=interface, filter=filter_expression, prn=lambda pkt: handle_packet(pkt, output_pcap), count=packet_count, store=False)
        for packet in sniffed_packets:
            captured_packets.append(packet)
    except KeyboardInterrupt:  # Handle KeyboardInterrupt exception
        pass  # Do nothing when Ctrl+C is pressed

parser = argparse.ArgumentParser(description="Network Sniffer")

parser.add_argument("-i", "--interface", help="Interface to sniff on", default="eth0")
parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
parser.add_argument("-w", "--write", help="Output file (in .pcap format)")
parser.add_argument("-f", "--filters", help="Protocol and port filters separated by comma (e.g., icmp,tcp,udp)")

args = parser.parse_args()

if args.filters:
    protocol_filters = args.filters.lower()
else:
    protocol_filters = None

start_sniffing(interface=args.interface, packet_count=args.count, output_pcap=args.write, protocol_filters=protocol_filters)
