"""
IDS/IPS Packet Ingestion, Preprocessing, Flow Tracking & Core Engine CLI Entrypoint.
Compliant with Assignment 1, 2 & 3 specifications:
- Accepts PCAP file input (--pcap) or Live Network Interface (--interface / -i).
- Executes 5-stage pipeline: Parser -> Decoder -> Preprocessor -> Flow Tracker -> Core Engine.
- Supports Snort rule loading from file or directory (--rules / -r).
- Exports enriched events to JSON Lines format (--output).
- Optionally exports bidirectional flow records (--output-flows).
- Exports standardized detection alerts to JSON Lines format (--alerts).
- Configurable idle timeouts and invalid packet policies.
"""

import sys
import os
import time
import argparse
from typing import Optional

from src.capture import PcapCapture, LiveCapture, BasePacketSource
from src.pipeline import ParsingPipeline
from src.logger import JsonLinesLogger
from src.rules import RuleRepository, RuleEvaluationEngine


def parse_arguments() -> argparse.Namespace:
    """Parses and validates command line arguments."""
    parser = argparse.ArgumentParser(
        description="IDS/IPS Packet Capture, Decoder, Preprocessor, Flow Tracker & Core Snort Engine (Assignment 3)"
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
        "--rules", "-r",
        type=str,
        default=None,
        help="Path to Snort rules file (.rules) or directory containing rule files"
    )
    parser.add_argument(
        "--alerts",
        type=str,
        default=None,
        help="Destination path for Detection Events (Alerts) JSON Lines output (.jsonl)"
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

    # Validate and load Snort rules if provided
    rule_engine: Optional[RuleEvaluationEngine] = None
    repo: Optional[RuleRepository] = None

    if args.rules:
        if not os.path.exists(args.rules):
            sys.stderr.write(f"[ERROR] Rules path not found: {args.rules}\n")
            return 1

        repo = RuleRepository()
        if os.path.isdir(args.rules):
            repo.load_from_directory(args.rules)
        else:
            repo.load_from_file(args.rules)

        rule_engine = RuleEvaluationEngine(repository=repo)
        if not args.alerts:
            args.alerts = "alerts.jsonl"

    # Initialize Capture Source
    source: BasePacketSource
    if args.pcap:
        source = PcapCapture(filepath=args.pcap)
        print(f"[*] Mode: PCAP Replay -> {args.pcap}")
    else:
        source = LiveCapture(interface=args.interface)
        print(f"[*] Mode: Live Capture -> Interface: {args.interface or 'Default'}")

    if args.rules and repo:
        print(f"[*] Rules Source           : {args.rules}")
        print(f"    -> Valid: {repo.valid_count} | Invalid: {repo.invalid_count} | Unsupported: {repo.unsupported_count}")

    print(f"[*] Enriched Events output : {args.output}")
    if args.output_flows:
        print(f"[*] Flow Records output    : {args.output_flows}")
    if args.alerts:
        print(f"[*] Detection Alerts output: {args.alerts}")

    pipeline = ParsingPipeline(
        tcp_idle_timeout=args.tcp_timeout,
        udp_idle_timeout=args.udp_timeout,
        drop_invalid=args.drop_invalid,
        rule_engine=rule_engine
    )

    total_packets = 0
    malformed_count = 0
    start_time = time.time()

    try:
        with JsonLinesLogger(filepath=args.output) as logger:
            alerts_logger = JsonLinesLogger(filepath=args.alerts) if args.alerts else None
            try:
                for event in pipeline.process_stream(source.read_packets()):
                    logger.log_event(event)
                    total_packets += 1
                    if event.is_malformed:
                        malformed_count += 1
                    if alerts_logger and event.alerts:
                        for alert in event.alerts:
                            alerts_logger.log_event(alert)
            finally:
                if alerts_logger:
                    alerts_logger.close()

        # Export Flow Records if requested
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
    print("      IDS/IPS PIPELINE & CORE DETECTION ENGINE SUMMARY")
    print("=" * 60)
    print(f" Total Packets Processed : {total_packets}")
    print(f" Total Flows Tracked     : {total_flows}")
    print(f" Malformed Packets       : {malformed_count}")
    if rule_engine and repo:
        metrics = rule_engine.get_metrics()
        print(f" Valid Rules Active      : {repo.valid_count}")
        print(f" Candidate Checks        : {metrics['candidate_rules_checked']}")
        print(f" Detection Alerts Total  : {metrics['alerts_generated']}")
    print(f" Execution Elapsed Time  : {elapsed:.3f} seconds")
    print(f" Throughput              : {rate:.1f} packets/sec")
    print(f" Events Log Written      : {os.path.abspath(args.output)}")
    if args.output_flows:
        print(f" Flows Log Written       : {os.path.abspath(args.output_flows)}")
    if args.alerts:
        print(f" Alerts Log Written      : {os.path.abspath(args.alerts)}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
