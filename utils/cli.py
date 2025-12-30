import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple Log Analyzer - Detect suspicious log entries"
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Input log file path"
    )

    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Output report file path"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["txt", "json", "csv", "html"],
        default="txt",
        help="Output format"
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show attack summary"
    )

    parser.add_argument(
        "--only-high",
        action="store_true",
        help="Show only high severity events"
    )

    parser.add_argument(
        "--group-by-ip",
        action="store_true",
        help="Group suspicious events by source IP"
    )

    parser.add_argument(
        "--ssh-threshold",
        type=int,
        default=5,
        help="SSH brute force attempt threshold"
    )

    parser.add_argument(
        "--ssh-window",
        type=int,
        default=60,
        help="Time window (seconds) for SSH brute force detection"
    )

    parser.add_argument(
        "--blacklist",
        action="store_true",
        help="Generate blacklist and firewall rules"
    )

    parser.add_argument(
        "--blacklist-score",
        type=int,
        default=30,
        help="Score threshold for blacklist"
    )

    parser.add_argument(
        "--export-firewall",
        choices=["iptables", "ufw"],
        help="Export firewall rules (iptables or ufw)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions without writing files"
    )

    return parser.parse_args()