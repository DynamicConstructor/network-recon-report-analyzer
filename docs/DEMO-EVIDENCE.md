# Demonstration Evidence — Offline Network Reporting

**Scope:** Fictional Nmap XML and generated header-only PCAP. No network scan or live capture.

```bash
python analyze_nmap.py samples/authorized_lab.xml
python generate_sample_pcap.py synthetic.pcap
python pcap_workbench.py synthetic.pcap --format markdown --output packet-report.md
python -m unittest discover -s tests -v
```

The XML example includes a Telnet port that merits review, not a confirmed vulnerability. The generated three-packet capture has **TCP: 2**, **UDP: 1**, and three simple flow entries. **10 cloud tests passed**, including malformed packet length and Ethernet padding checks.

Alexander should save a personal screenshot of the generated report, then add a genuine synthetic ICMP test. Do not commit identifiable real network captures.
