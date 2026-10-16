"""
IDS/IPS Packet Ingestion, Preprocessing, Flow Tracking & Core Snort Engine CLI Entrypoint.
Compliant with Assignment 1, 2 & 3 specifications and Snort CLI conventions:
- Snort Test Mode (-T / --test-rules [rule_path]): Validate and report on rule syntax then exit.
- Rule Deployment (--rules / -r / -R): Load rules from file or directory into Core Engine.
- Granular Rule Selection (--enable-sids / --disable-sids): Enable/disable specific rule SIDs.
- Packet Replay (--pcap / -p) or Live Sniffing (--interface / -i).
- 5-stage pipeline: Parser -> Decoder -> Preprocessor -> Flow Tracker -> Core Engine.
- Export enriched events (--output), flow records (--output-flows), and alerts (--alerts).
"""

import sys
import os
import time
import argparse
from typing import Optional, Set

from src.capture import PcapCapture, LiveCapture, BasePacketSource
from src.pipeline import ParsingPipeline
from src.logger import JsonLinesLogger
from src.rules import RuleRepository, RuleEvaluationEngine


def parse_arguments() -> argparse.Namespace:
    """Parses and validates command line arguments."""
    parser = argparse.ArgumentParser(
        description="IDS/IPS Packet Capture, Decoder, Preprocessor, Flow Tracker & Core Snort Engine (Assignment 3)"
    )

    # Traffic Input Source (Snort style: -p / --pcap, -i / --interface)
    input_group = parser.add_argument_group("Traffic Input Options")
    input_group.add_argument(
        "--pcap", "-p",
        type=str,
        default=None,
        help="Path to an offline PCAP capture file to parse"
    )
    input_group.add_argument(
        "--interface", "-i",
        type=str,
        default=None,
        help="Network interface name for live packet capture (e.g., eth0, Wi-Fi)"
    )

    # Snort Rule Options (Snort style: -r / -R / --rules, -T / --test-rules)
    rule_group = parser.add_argument_group("Snort Rule Options")
    rule_group.add_argument(
        "-T", "--test-rules",
        nargs="?",
        const=True,
        default=None,
        metavar="RULE_PATH",
        help="Snort test mode: validate rules then exit. Can pass path directly: -T <path_to_rules>"
    )
    rule_group.add_argument(
        "--rules", "-r", "-R",
        type=str,
        default=None,
        help="Path to Snort rules file (.rules) or directory containing rule files"
    )
    rule_group.add_argument(
        "--enable-sids",
        type=str,
        default=None,
        help="Comma-separated list of rule SIDs to specifically enable (e.g., 300001,300002)"
    )
    rule_group.add_argument(
        "--disable-sids",
        type=str,
        default=None,
        help="Comma-separated list of rule SIDs to disable (e.g., 300003)"
    )

    # Output & Logging Options
    out_group = parser.add_argument_group("Output & Logging Options")
    out_group.add_argument(
        "--alerts",
        type=str,
        default=None,
        help="Destination path for Detection Events (Alerts) JSON Lines output (.jsonl)"
    )
    out_group.add_argument(
        "--output",
        type=str,
        default="output.jsonl",
        help="Destination path for enriched event JSON Lines output (default: output.jsonl)"
    )
    out_group.add_argument(
        "--output-flows",
        type=str,
        default=None,
        help="Optional destination path for bidirectional Flow records JSON Lines output (.jsonl)"
    )

    # Pipeline Policy Options
    policy_group = parser.add_argument_group("Pipeline Policy Options")
    policy_group.add_argument(
        "--tcp-timeout",
        type=float,
        default=300.0,
        help="Idle timeout in seconds for TCP flows (default: 300.0)"
    )
    policy_group.add_argument(
        "--udp-timeout",
        type=float,
        default=60.0,
        help="Idle timeout in seconds for UDP flows (default: 60.0)"
    )
    policy_group.add_argument(
        "--drop-invalid",
        action="store_true",
        help="Policy flag: tag invalid packets with action DROP instead of INSPECT"
    )

    return parser.parse_args()


def run_rule_validation_mode(repo: RuleRepository, rules_path: str) -> int:
    """
    Executes Snort-style rule validation test (-T) and prints a comprehensive report.
    """
    print("=" * 70)
    print("        SNORT RULES VALIDATION & VERIFICATION REPORT (-T)")
    print("=" * 70)
    print(f" Rules Source Path       : {os.path.abspath(rules_path)}")
    print(f" Total Rules Loaded      : {repo.total_rules}")
    print(f"  -> Valid Rules         : {repo.valid_count}")
    print(f"  -> Invalid Rules       : {repo.invalid_count}")
    print(f"  -> Unsupported Rules   : {repo.unsupported_count}")
    print("-" * 70)

    # 1. Invalid Rules Breakdown
    if repo.invalid_rules:
        print(" [!] INVALID RULES (Syntax errors / missing fields):")
        for idx, rule in enumerate(repo.invalid_rules, start=1):
            sid_str = f"SID={rule.sid}" if rule.sid else "NO_SID"
            print(f"     #{idx:02d} [{sid_str}] Reason: {rule.reason}")
            print(f"         Raw: {rule.raw_text}")
        print("-" * 70)

    # 2. Unsupported Rules Breakdown
    if repo.unsupported_rules:
        print(" [?] UNSUPPORTED RULES (Keywords out of scope):")
        for idx, rule in enumerate(repo.unsupported_rules, start=1):
            sid_str = f"SID={rule.sid}" if rule.sid else "NO_SID"
            print(f"     #{idx:02d} [{sid_str}] Reason: {rule.reason}")
            print(f"         Raw: {rule.raw_text}")
        print("-" * 70)

    # 3. Valid Rules Ready for Deployment
    if repo.valid_rules:
        print(" [+] VALID RULES READY FOR DEPLOYMENT:")
        for sid, rule in repo.valid_rules.items():
            proto = rule.header.protocol if rule.header else "UNKNOWN"
            direction = rule.header.direction if rule.header else "->"
            src_str = f"{rule.header.src_ip}:{rule.header.src_port}" if rule.header else "any"
            dst_str = f"{rule.header.dst_ip}:{rule.header.dst_port}" if rule.header else "any"
            msg = f'"{rule.msg}"' if rule.msg else "None"
            print(f"     [SID {sid:6d}] {rule.header.action} {proto} {src_str} {direction} {dst_str} | msg:{msg}")
        print("-" * 70)

    if repo.invalid_rules:
        print("[WARNING] Invalid rules detected and quarantined. Engine remains fully functional.")
    else:
        print("[SUCCESS] All rules parsed and verified with 100% valid syntax!")
    print("=" * 70)
    return 0


def main() -> int:
    """Main execution orchestrator."""
    args = parse_arguments()

    # Parse enabled/disabled SIDs if provided (Mục 4.1)
    enabled_sids: Optional[Set[int]] = None
    if args.enable_sids:
        enabled_sids = {int(s.strip()) for s in args.enable_sids.split(",") if s.strip().isdigit()}

    disabled_sids: Optional[Set[int]] = None
    if args.disable_sids:
        disabled_sids = {int(s.strip()) for s in args.disable_sids.split(",") if s.strip().isdigit()}

    # 1. Handle Snort Test Mode (-T / --test-rules [path])
    if args.test_rules:
        rules_path = args.test_rules if isinstance(args.test_rules, str) else args.rules
        if not rules_path:
            sys.stderr.write("[ERROR] Vui lòng chỉ định đường dẫn file rule: python main.py -T <path_to_rules>\n")
            return 1
        if not os.path.exists(rules_path):
            sys.stderr.write(f"[ERROR] Rules path not found: {rules_path}\n")
            return 1

        repo = RuleRepository()
        if os.path.isdir(rules_path):
            repo.load_from_directory(rules_path, enabled_sids=enabled_sids, disabled_sids=disabled_sids)
        else:
            repo.load_from_file(rules_path, enabled_sids=enabled_sids, disabled_sids=disabled_sids)

        return run_rule_validation_mode(repo, rules_path)

    # 2. Check Traffic Input Source for Deployment Mode
    if not args.pcap and not args.interface:
        sys.stderr.write(
            "[ERROR] No traffic input specified. Provide --pcap <file> or --interface <name>, "
            "or use -T <path_to_rules> to test rule syntax.\n"
        )
        return 1

    if args.pcap and not os.path.exists(args.pcap):
        sys.stderr.write(f"[ERROR] PCAP file not found: {args.pcap}\n")
        return 1

    # 3. Load Snort Rules for Deployment
    rule_engine: Optional[RuleEvaluationEngine] = None
    repo: Optional[RuleRepository] = None

    if args.rules:
        if not os.path.exists(args.rules):
            sys.stderr.write(f"[ERROR] Rules path not found: {args.rules}\n")
            return 1

        repo = RuleRepository()
        if os.path.isdir(args.rules):
            repo.load_from_directory(args.rules, enabled_sids=enabled_sids, disabled_sids=disabled_sids)
        else:
            repo.load_from_file(args.rules, enabled_sids=enabled_sids, disabled_sids=disabled_sids)

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
        print(f"[*] Rules Deployed Source  : {args.rules}")
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

    print("=" * 70)
    print("      IDS/IPS PIPELINE & CORE DETECTION ENGINE SUMMARY")
    print("=" * 70)
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
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
