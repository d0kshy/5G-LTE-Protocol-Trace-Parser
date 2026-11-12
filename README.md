# 5G/LTE Protocol Trace Parser


First of all, let's separate the **network protocol flow** from the **software architecture**. The project cis based on **4 modular engineering parts**, where each part feeds data into the next:

```
[ .pcap file ] ──> Part 1: Ingestion & Filtering
                        │
                        ▼
                   Part 2: State Machine & Session Tracker  <-- (Initial Attach is here)
                        │
                        ▼
                   Part 3: Anomaly & Failure Diagnostics
                        │
                        ▼
                   Part 4: Call Flow Visualizer & CLI Output

```



---

## Part 1: Ingestion & Packet Filtering (The Input Layer)

Before decoding 5G state transitions, script needs a clean pipeline to read `.pcap` files and strip away irrelevant background noise (ARP, DNS, TCP retransmissions, etc.).

**What to build:** A `PcapReader` module wrapping `pyshark` (which uses Wireshark's `tshark` dissector engine under the hood—crucial because writing raw ASN.1 PER decoders from scratch takes months).

**Key Tasks:**
1. Use 2–3 real sample `.pcap` files (e.g., from Open5GS or srsRAN test suites) covering a successful 5G registration and a failed one.
2. Apply display filters (`nr-rrc || ngap || nas-5gs`) so Python loop only inspects control-plane signaling packets.
3. Normalize each packet into a clean Python `@dataclass` (timestamp, packet number, source/dest interface, protocol layer, message name, and raw dictionary of fields).

---

