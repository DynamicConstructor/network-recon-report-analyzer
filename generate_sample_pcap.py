"""Create a synthetic Ethernet/IPv4 capture containing only documentation IPs."""

import argparse
import socket
import struct
from pathlib import Path


def ipv4_packet(source, destination, protocol, source_port=0, dest_port=0):
    transport = struct.pack("!HH", source_port, dest_port) + b"\x00" * 16 if protocol == 6 else (
        struct.pack("!HHHH", source_port, dest_port, 8, 0) if protocol == 17 else b"\x00" * 8)
    ip = (b"\x45\x00" + struct.pack("!H", 20 + len(transport)) + b"\x00\x01\x00\x00\x40" +
          bytes([protocol]) + b"\x00\x00" + socket.inet_aton(source) + socket.inet_aton(destination))
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ip + transport


def write_fixture(path):
    packets = [
        ipv4_packet("192.0.2.10", "198.51.100.20", 6, 50000, 443),
        ipv4_packet("192.0.2.10", "198.51.100.53", 17, 52000, 53),
        ipv4_packet("198.51.100.20", "192.0.2.10", 6, 443, 50000),
    ]
    with Path(path).open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for idx, packet in enumerate(packets):
            out.write(struct.pack("<IIII", 1700000000 + idx, 0, len(packet), len(packet)))
            out.write(packet)
    return len(packets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate fake, header-only sample PCAP")
    parser.add_argument("output", nargs="?", default="sample-traffic.pcap")
    args = parser.parse_args()
    print(f"Saved {write_fixture(args.output)} synthetic packets to {args.output}")
