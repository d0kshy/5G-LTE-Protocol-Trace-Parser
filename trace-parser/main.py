# Entry Point: Handles command-line arguments (input .pcap path, optional UE filters, output directory).
# Ingestion Module: Wraps the packet capture reader, applies display filters, and converts raw packets into your clean internal format.
# Models Module: Defines the standardized structures for normalized packets and tracked UE sessions.
# Engine & Diagnostics Modules: Reserved for Parts 2 and 3 (state machine tracking, identity correlation, and cause-code checks).
# Visualizer Module: Reserved for Part 4 (terminal summary tables and Mermaid/PlantUML diagram generation).

class IndexCard:
    frame_number = 0
    timestamp = 0
    direction = " "  # e.g., "UE -> gNodeB" or "gNodeB -> AMF"
    protocol_layer = " "  # "RRC", "NGAP", or "NAS"
    message_name = " "  # e.g., "RRCSetupRequest"
    details = dict()  # Key-value pairs {"ue_id": "12345", "cause": "mo-Data"}


def parse_trace_file(file_path):
    # Step 1: Open the file and ignore non-5G traffic
    target_protocols = ("nr-rrc", "ngap", "nas-5gs")
    clean_cards = []

    with open(file_path) as f:
        for line in f:
            if any(proto in line for proto in target_protocols):
                clean_cards.append(line.strip())

    # Step 2: Loop through every matching packet one by one
    for packet in clean_cards:
        # Case A: It is a Radio message between Phone and Tower
        if "NR-RRC" in packet:
            card = IndexCard()
            card.frame_number = packet.number
            card.timestamp = packet.time
            card.protocol_layer = "RRC"
            # card.message_name   = GET_RRC_MESSAGE_NAME(packet) # e.g., "RRCSetupComplete"
            # card.direction      = GET_DIRECTION(card.message_name)
            # card.details        = EXTRACT_RRC_IDS(packet)
            clean_cards.append(card)

            # Case B: It is a Core message between Tower and Core Network
            if "NGAP" in packet:
                card = IndexCard()
                card.frame_number = packet.number
                card.timestamp = packet.time
                card.protocol_layer = "NGAP"
            # card.message_name   = GET_NGAP_MESSAGE_NAME(packet) // e.g., "InitialUEMessage"
            # card.direction      = GET_DIRECTION(card.message_name)
            # card.details        = EXTRACT_NGAP_IDS(packet)
                clean_cards.append(card)

            # Case C: Check if a NAS letter was hidden inside the RRC or NGAP box
            if "NAS-5GS" in packet:
                nas_card = IndexCard()
                nas_card.frame_number = packet.number
                nas_card.timestamp = packet.time
                nas_card.protocol_layer = "NAS"
#             nas_card.message_name   = GET_NAS_MESSAGE_NAME(packet) // e.g., "RegistrationRequest"
#             nas_card.direction      = GET_DIRECTION(nas_card.message_name)
#             nas_card.details        = EXTRACT_NAS_DETAILS(packet)
                clean_cards.append(nas_card)

#     CLOSE(raw_packets)
#     RETURN clean_cards
