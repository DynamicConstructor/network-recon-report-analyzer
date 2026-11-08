"""Read basic Ethernet/IPv4 PCAP metadata offline. Never captures or sends traffic."""

import argparse
import json
import socket
import struct
from collections import Counter
from pathlib import Path


def read_pcap(path):
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("PCAP global header is incomplete")
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            byte_order = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            byte_order = ">"
        else:
            raise ValueError("Unsupported capture format (classic PCAP required)")
        _, major, minor, _, _, snaplen, linktype = struct.unpack(byte_order + "IHHIIII", header)
        if (major, minor) != (2, 4) or linktype != 1:
            raise ValueError("Only classic Ethernet PCAP version 2.4 is supported")
        if snaplen < 14:
            raise ValueError("Invalid capture snap length")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("Truncated packet header")
            _, _, included, original = struct.unpack(byte_order + "IIII", record)
            if included > snaplen or included > 16_000_000 or original < included:
                raise ValueError("Invalid packet lengths")
            packet = stream.read(included)
            if len(packet) != included:
                raise ValueError("Truncated packet data")
            yield packet


def decode_packet(packet):
    if len(packet) < 14:
        return None
    ethertype = struct.unpack("!H", packet[12:14])[0]
    if ethertype != 0x0800:
        return {"protocol": "NON_IPV4"}
    data = packet[14:]
    if len(data) < 20 or data[0] >> 4 != 4:
        return {"protocol": "MALFORMED_IPV4"}
    header_bytes = (data[0] & 0x0f) * 4
    if header_bytes < 20 or len(data) < header_bytes:
        return {"protocol": "MALFORMED_IPV4"}
    proto = data[9]
    source = socket.inet_ntoa(data[12:16])
    destination = socket.inet_ntoa(data[16:20])
    name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP_{proto}")
    result = {"protocol": name, "source_ip": source, "destination_ip": destination}
    # Non-initial fragments cannot safely be treated as complete transport headers.
    fragment_offset = struct.unpack("!H", data[6:8])[0] & 0x1fff
    if fragment_offset == 0 and proto in (6, 17) and len(data) >= header_bytes + 4:
        result["source_port"], result["destination_port"] = struct.unpack("!HH", data[header_bytes:header_bytes + 4])
    return result


def analyze_capture(path):
    protocol_counts = Counter()
    source_counts = Counter()
    destination_ports = Counter()
    flows = Counter()
    total = 0
    for raw in read_pcap(path):
        total += 1
        packet = decode_packet(raw)
        if packet is None:
            protocol_counts["TRUNCATED_ETHERNET"] += 1
            continue
        protocol_counts[packet["protocol"]] += 1
        if "source_ip" in packet:
            source_counts[packet["source_ip"]] += 1
            if "destination_port" in packet:
                destination_ports[f"{packet['protocol']}/{packet['destination_port']}"] += 1
                flows[(packet["source_ip"], packet["destination_ip"], packet["protocol"],
                       packet["destination_port"])] += 1
    return {"total_packets": total,
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "source_counts": dict(sorted(source_counts.items())),
            "destination_ports": dict(sorted(destination_ports.items())),
            "flows": [{"source_ip": a, "destination_ip": b, "protocol": p,
                       "destination_port": port, "packets": count}
                      for (a, b, p, port), count in sorted(flows.items())],
            "disclaimer": "Offline packet metadata only; no payload reconstruction or vulnerability proof."}


def markdown(report):
    lines = ["# Offline Packet Metadata Report", "", report["disclaimer"], "",
             f"**Packets:** {report['total_packets']}", "", "## Protocols", ""]
    lines += [f"- {key}: {value}" for key, value in report["protocol_counts"].items()]
    lines += ["", "## Destination ports", ""]
    lines += [f"- {key}: {value}" for key, value in report["destination_ports"].items()]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Offline Ethernet/IPv4 PCAP metadata inventory")
    p.add_argument("pcap_file")
    p.add_argument("--format", choices=["json", "markdown"], default="json")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        report = analyze_capture(args.pcap_file)
        output = json.dumps(report, indent=2) if args.format == "json" else markdown(report)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
            print(f"Saved {args.format} report to {args.output}")
        else:
            print(output)
    except (ValueError, OSError) as exc:
        p.error(str(exc))
