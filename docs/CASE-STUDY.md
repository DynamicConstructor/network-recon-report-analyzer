# Case Study: Turning Scan XML Into a Network Inventory

## Problem

Raw service-discovery output can be difficult to summarize for review. Analysts need a structured host inventory and careful distinctions between exposed services and validated weaknesses.

## Approach

One parser reads existing Nmap XML to inventory open services and review selected legacy protocols. A separate classic-PCAP parser summarizes Ethernet/IPv4 protocol counts, source IPs, destination ports, and flows. Both are fully offline and initiate no scanning or capture.

## Architecture

`Synthetic/authorized Nmap XML → XML parser → open-service inventory → review notes → reports`

## Engineering decisions

- Offline processing makes the demonstration reproducible and prevents accidental scanning.
- The sample uses documentation-only addresses.
- The report uses language such as **review** rather than declaring a confirmed vulnerability.
- Tests cover the expected synthetic inventory and report rendering.

## Demonstrated outcome

Ten Python tests passed in the latest cloud verification. Two fictional hosts appear in the XML fixture; a second generated fixture contains three fake packets. The code rejects malformed IPv4 total lengths and ignores Ethernet padding when identifying ports. The illustrative Telnet exposure is an inventory review item, not a confirmed vulnerability.

## Next personal contribution

Alexander can independently add an ICMP synthetic fixture and explain exactly how its protocol counts differ. He should only use owned/authorized captures and never publish private packet data.
