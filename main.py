"""
IDS/IPS Packet Ingestion, Preprocessing & Flow Tracking CLI Entrypoint.
Compliant with Assignment 1 & 2 specifications:
- Accepts PCAP file input (--pcap) or Live Network Interface (--interface / -i).
- Executes 5-stage pipeline: Parser -> Decoder -> Preprocessor -> Flow Tracker.
- Exports enriched events to JSON Lines format (--output).
- Optionally exports bidirectional flow records and metrics (--output-flows).
- Configurable idle timeouts and invalid packet policies (Mục 2).
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
        description="IDS/IPS Packet Capture, Decoder, Preprocessor & Flow Tracker (Assignment 2)"
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
        help="Destination path for enriched event JSON Lines output (default: output.jsonl)"
    )
    parser.add_argument(
        "--output-flows",
        type=str,
        default=None,
        help="Optional destination path for bidirectional Flow records JSON Lines output (.jsonl)"
    )
    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=300.0,
        help="Idle timeout in seconds for TCP flows (default: 300.0)"
    )
    parser.add_argument(
        "--udp-timeout",
        type=float,
        default=60.0,
        help="Idle timeout in seconds for UDP flows (default: 60.0)"
    )
    parser.add_argument(
        "--drop-invalid",
        action="store_true",
        help="Policy flag: tag invalid packets with action DROP instead of INSPECT"
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

    print(f"[*] Enriched Events output : {args.output}")
    if args.output_flows:
        print(f"[*] Flow Records output    : {args.output_flows}")

    pipeline = ParsingPipeline(
        tcp_idle_timeout=args.tcp_timeout,
        udp_idle_timeout=args.udp_timeout,
        drop_invalid=args.drop_invalid
    )

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

        # Export Flow Records if requested or by default at end of pipeline
        all_flows = pipeline.flush_flows()
        total_flows = len(all_flows)

        if args.output_flows:
            with JsonLinesLogger(filepath=args.output_flows) as flow_logger:
                for flow in all_flows:
                    flow_logger.log_event(flow)

    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user (Ctrl+C). Finalizing logs...")
    except Exception as exc:
        sys.stderr.write(f"\n[FATAL] Unexpected error: {str(exc)}\n")
        return 1

    elapsed = time.time() - start_time
    rate = (total_packets / elapsed) if elapsed > 0 else 0.0

    print("=" * 60)
    print("      IDS/IPS PIPELINE & FLOW TRACKER SUMMARY")
    print("=" * 60)
    print(f" Total Packets Processed : {total_packets}")
    print(f" Total Flows Tracked     : {total_flows}")
    print(f" Malformed Packets       : {malformed_count}")
    print(f" Execution Elapsed Time  : {elapsed:.3f} seconds")
    print(f" Throughput              : {rate:.1f} packets/sec")
    print(f" Events Log Written      : {os.path.abspath(args.output)}")
    if args.output_flows:
        print(f" Flows Log Written       : {os.path.abspath(args.output_flows)}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
