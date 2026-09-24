"""
IDS/IPS Packet Ingestion & Parsing CLI Entrypoint.
Compliant with Assignment 1 specifications:
- Accepts PCAP file input (--pcap) or Live Network Interface (--interface / -i).
- Dissects packets layer-by-layer into NormalizedEvent via ParsingPipeline.
- Exports results to JSON Lines format (.jsonl) via JsonLinesLogger.
"""

import sys
import os
import time
import argparse
from typing import Optional

from src.capture import PcapCapture, LiveCapture, BasePacketSource
from src.pipeline import ParsingPipeline
from src.logger import JsonLinesLogger


def parse_arguments() -> argparse.Namespace:
    """Parses and validates command line arguments."""
    parser = argparse.ArgumentParser(
        description="IDS/IPS Packet Capture and Normalization Parser (Assignment 1)"
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--pcap",
        type=str,
        help="Path to an offline PCAP capture file to parse"
    )
    input_group.add_argument(
        "--interface",
        type=str,
        help="Network interface name for live packet capture (e.g., eth0, Wi-Fi)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="output.jsonl",
        help="Destination path for JSON Lines output file (default: output.jsonl)"
    )

    return parser.parse_args()


def main() -> int:
    """Main execution orchestrator."""
    args = parse_arguments()

    # Validate PCAP existence if provided
    if args.pcap and not os.path.exists(args.pcap):
        sys.stderr.write(f"[ERROR] PCAP file not found: {args.pcap}\n")
        return 1

    # Initialize Capture Source
    source: BasePacketSource
    if args.pcap:
        source = PcapCapture(filepath=args.pcap)
        print(f"[*] Mode: PCAP Replay -> {args.pcap}")
    else:
        source = LiveCapture(interface=args.interface)
        print(f"[*] Mode: Live Capture -> Interface: {args.interface or 'Default'}")

    print(f"[*] Output destination: {args.output}")

    pipeline = ParsingPipeline()
    total_packets = 0
    malformed_count = 0
    start_time = time.time()

    try:
        with JsonLinesLogger(filepath=args.output) as logger:
            for event in pipeline.process_stream(source.read_packets()):
                logger.log_event(event)
                total_packets += 1
                if event.is_malformed:
                    malformed_count += 1

    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user (Ctrl+C). Finalizing logs...")
    except Exception as exc:
        sys.stderr.write(f"\n[FATAL] Unexpected error: {str(exc)}\n")
        return 1

    elapsed = time.time() - start_time
    rate = (total_packets / elapsed) if elapsed > 0 else 0.0

    print("=" * 60)
    print("           IDS/IPS INGESTION & PARSING SUMMARY")
    print("=" * 60)
    print(f" Total Packets Processed : {total_packets}")
    print(f" Malformed Packets       : {malformed_count}")
    print(f" Execution Elapsed Time  : {elapsed:.3f} seconds")
    print(f" Throughput              : {rate:.1f} packets/sec")
    print(f" Log File Written        : {os.path.abspath(args.output)}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
