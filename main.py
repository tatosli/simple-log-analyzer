import argparse

from analyzer.parser import parse_logs
from analyzer.detector import detect_suspicious
from analyzer.scorer import score_events
from analyzer.reporter import write_report

from security.blacklist import write_blacklist
from security.firewall import export_iptables, export_ufw


def parse_args():
    parser = argparse.ArgumentParser(description="Simple Log Analyzer")

    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"], default="txt")

    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--only-high", action="store_true")
    parser.add_argument("--group-by-ip", action="store_true")

    parser.add_argument("--ssh-threshold", type=int, default=5)
    parser.add_argument("--ssh-window", type=int, default=60)

    parser.add_argument("--blacklist", action="store_true")
    parser.add_argument("--blacklist-score", type=int, default=30)

    parser.add_argument(
        "--export-firewall",
        choices=["iptables", "ufw"],
        help="Export blacklist as firewall rules"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    logs = parse_logs(args.input)

    suspicious = detect_suspicious(
        logs,
        ssh_threshold=args.ssh_threshold,
        ssh_window=args.ssh_window
    )

    suspicious = score_events(suspicious)

    write_report(
        suspicious,
        args.output,
        fmt=args.format,
        summary=args.summary,
        only_high=args.only_high,
        group_by_ip=args.group_by_ip
    )

    if args.blacklist:
        new_ips = write_blacklist(
            suspicious,
            min_score=args.blacklist_score
        )

        print(f"\nBlacklist'e eklenen IP sayısı: {len(new_ips)}")

        if args.export_firewall and new_ips:
            if args.export_firewall == "iptables":
                export_iptables(new_ips)
                print("iptables script oluşturuldu")

            elif args.export_firewall == "ufw":
                export_ufw(new_ips)
                print("ufw rules dosyası oluşturuldu")


if __name__ == "__main__":
    main()
