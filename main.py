import argparse
from analyzer.reader import read_logs
from analyzer.detector import detect_suspicious
from analyzer.reporter import write_report


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
        choices=["txt", "json", "csv"],
        default="txt",
        help="Output format: txt, json, csv"
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show attack summary"
    )

    parser.add_argument(
        "--only-high",
        action="store_true",
        help="Show only high severity attacks"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    lines = read_logs(args.input)
    suspicious = detect_suspicious(lines)

    if args.only_high:
        suspicious = [s for s in suspicious if s["severity"] == "HIGH"]

    # ===== SUMMARY =====
    if args.summary:
        type_summary = {}
        severity_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for s in suspicious:
            # attack type sayımı
            type_summary[s["type"]] = type_summary.get(s["type"], 0) + 1

            # severity sayımı
            sev = s.get("severity", "LOW")
            if sev not in severity_summary:
                severity_summary[sev] = 0
            severity_summary[sev] += 1

        print("\n=== ATTACK TYPE SUMMARY ===")
        for k, v in type_summary.items():
            print(f"{k}: {v}")

        print("\n=== SEVERITY SUMMARY ===")
        for k, v in severity_summary.items():
            print(f"{k}: {v}")

    # ===== REPORT =====
    write_report(
        total=len(lines),
        suspicious=suspicious,
        output_file=args.output,
        output_format=args.format
    )

    print("\nAnaliz tamamlandı.")
    print(f"Girdi: {args.input}")
    print(f"Çıktı: {args.output}")
    print(f"Toplam satır: {len(lines)} | Şüpheli: {len(suspicious)}")


if __name__ == "__main__":
    main()
