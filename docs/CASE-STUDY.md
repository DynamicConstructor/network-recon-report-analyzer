# Case Study: Turning Scan XML Into a Network Inventory

## Problem

Raw service-discovery output can be difficult to summarize for review. Analysts need a structured host inventory and careful distinctions between exposed services and validated weaknesses.

## Approach

The parser reads an existing Nmap XML file, collects open TCP services, and attaches review notes for selected legacy protocols. It produces console, JSON, and Markdown output; it never initiates its own network scan.

## Architecture

`Synthetic/authorized Nmap XML → XML parser → open-service inventory → review notes → reports`

## Engineering decisions

- Offline processing makes the demonstration reproducible and prevents accidental scanning.
- The sample uses documentation-only addresses.
- The report uses language such as **review** rather than declaring a confirmed vulnerability.
- Tests cover the expected synthetic inventory and report rendering.

## Demonstrated outcome

Three tests passed and two synthetic hosts were summarized in cloud verification. The illustrative Telnet exposure is only an inventory finding. No third-party system or packet data was examined.

## Next personal contribution

Alexander can add protocol grouping, port-count summaries, or an authorized Wireshark metadata case study with redacted evidence.
