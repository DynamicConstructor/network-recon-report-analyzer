"""Offline Nmap XML inventory analysis. Does not conduct network scanning."""
import argparse
import json
import xml.etree.ElementTree as ET


def analyze(path):
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError("Expected Nmap XML root <nmaprun>")
    hosts = []
    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        services = []
        notes = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = service.get("name", "unknown") if service is not None else "unknown"
            port_number = int(port.attrib["portid"])
            services.append({"protocol": port.get("protocol"), "port": port_number,
                             "service": name})
            if name.lower() == "telnet" or port_number == 23:
                notes.append("Review unencrypted Telnet; prefer encrypted remote administration")
            elif name.lower() == "ftp" or port_number == 21:
                notes.append("Review FTP exposure and encrypted alternatives")
        hosts.append({"address": address.get("addr"), "open_services": services,
                      "review_notes": sorted(set(notes))})
    return {"host_count": len(hosts), "hosts": hosts}


def to_markdown(report):
    lines = ["# Offline Network Inventory Report", "",
             "Source: supplied Nmap XML; findings are service observations, not validated vulnerabilities.", "",
             f"Hosts: **{report['host_count']}**", ""]
    for host in report["hosts"]:
        lines.extend([f"## {host['address']}", "", "| Protocol | Port | Service |",
                      "|---|---:|---|"])
        for service in host["open_services"]:
            lines.append(f"| {service['protocol']} | {service['port']} | {service['service']} |")
        if not host["open_services"]:
            lines.append("| — | — | No open services recorded |")
        lines.extend(["", "### Review notes", ""])
        lines.extend([f"- {note}" for note in host["review_notes"]] or ["- No automated review notes"])
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Analyze an existing authorized Nmap XML file")
    p.add_argument("xml_file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--markdown", help="Write a Markdown inventory report to this path")
    args = p.parse_args()
    try:
        report = analyze(args.xml_file)
    except (ET.ParseError, ValueError, OSError, KeyError) as exc:
        p.error(str(exc))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Hosts in report: {report['host_count']}")
        for host in report["hosts"]:
            print(f"\nHost: {host['address']}")
            for service in host["open_services"]:
                print(f"  {service['protocol']}/{service['port']}  {service['service']}")
            for note in host["review_notes"]:
                print(f"  REVIEW: {note}")
    if args.markdown:
        from pathlib import Path
        Path(args.markdown).write_text(to_markdown(report), encoding="utf-8")
        print(f"Saved report to {args.markdown}")
