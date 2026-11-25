# Entry Point: Handles command-line arguments (input .pcap path, optional UE filters, output directory).
# Ingestion Module: Wraps the packet capture reader, applies display filters, and converts raw packets into your clean internal format.
# Models Module: Defines the standardized structures for normalized packets and tracked UE sessions.
# Engine & Diagnostics Modules: Reserved for Parts 2 and 3 (state machine tracking, identity correlation, and cause-code checks).
# Visualizer Module: Reserved for Part 4 (terminal summary tables and Mermaid/PlantUML diagram generation).

import argparse
import pyshark


class IndexCard:
    def __init__(
            self,
            frame_number,
            timestamp,
            direction="Unknown",  # e.g., "UE -> gNodeB" or "gNodeB -> AMF"
            protocol_layer="Unknown",  # "RRC", "NGAP", or "NAS"
            message_name="Unknown",  # e.g., "RRCSetupRequest"
            details=None,
    ):
        self.frame_number = frame_number
        self.timestamp = timestamp
        self.direction = direction  # e.g., "UE -> gNodeB" or "gNodeB -> AMF"
        self.protocol_layer = protocol_layer  # "RRC", "NGAP", or "NAS"
        self.message_name = message_name  # e.g., "RRCSetupRequest"
        # Key-value pairs {"ue_id": "12345", "cause": "mo-Data"}
        self.details = details if details is not None else {}


def parse_trace_file(file_path):
    # Step 1: Open the file and ignore non-5G traffic
    raw_packets = pyshark.FileCapture(
        file_path,
        target_protocols=("nr-rrc", "ngap", "nas-5gs")
    )

    clean_cards = []

    for packet in raw_packets:
        frame_num = int(packet.number)
        timest = float(packet.timestamp)

# Case 1: Radio message between Phone and Tower
        if hasattr(packet, "nr_rrc"):
            card = IndexCard(
                frame_number=frame_num,
                timestamp=timest,
                protocol_layer="RRC"
            )

        clean_cards.append(card)
# Case 2: Core message between Tower and Core Network
        if hasattr(packet, "ngap"):
            card = IndexCard(
                frame_number=frame_num,
                timestamp=timest,
                protocol_layer="NGAP"
            )

        clean_cards.append(card)
# Case 3: Piggybacked NAS letter inside previous types of messages
        if hasattr(packet, "nas_5gs"):
            nas_card = IndexCard(
                frame_number=frame_num,
                timestamp=timest,
                protocol_layer="NAS"
            )

        clean_cards.append(nas_card)

    raw_packets.close()
    return clean_cards


def main():
    parser = argparse.ArgumentParser("5G/LTE Protocol Trace Parser")
    parser.add_argument(
        "pcap_file", help="Enter path to the input .pacp or .pcapng file"
    )
    args = parser.parse_args()

    cards = parse_trace_file(args.pcap_file)
    print(f"Parsed {len(cards)} signaling events: \n")
    for card in cards:
        print(card)


if __name__ == "__main__":
    main()
