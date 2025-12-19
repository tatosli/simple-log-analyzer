import argparse
from analyzer.reader import read_logs
from analyzer.detector import detect_suspicious
from analyzer.aggregator import aggregate_by_ip, calculate_risk_level
from analyzer.reporter import write_report

def parse_args():
    parser = argparse.ArgumentParser(description="Simple Log Analyzer")

    parser.add_argument("-i", "--input", required=True, help="Input log file")
    parser.add_argument("-o", "--output", required=True, help="Output report file")
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"], default="txt")

    parser.add_argument("--summary", action="store_true", help="Show attack summary")
    parser.add_argument("--only-high", action="store_true", help="Only HIGH severity")
    parser.add_argument("--group-by-ip", action="store_true", help="Group by IP")
    parser.add_argument("--ssh-threshold", type=int, default=5, help="SSH failed attempts threshold (default: 5)")
    parser.add_argument("--ssh-window", type=int, default=60, help="SSH brute-force time window in seconds (default: 60)")


    return parser.parse_args()

def main():
    args = parse_args()

    # 1️⃣ Logları oku
    lines = read_logs(args.input)

    # 2️⃣ Şüpheli aktiviteleri tespit et (SSH brute-force dahil)
    suspicious = detect_suspicious(
        lines,
        ssh_threshold=args.ssh_threshold,
        ssh_window=args.ssh_window
    )

    # 3️⃣ Sadece HIGH severity istenirse filtrele
    if args.only_high:
        suspicious = [s for s in suspicious if s["severity"] == "HIGH"]

    # 4️⃣ Summary (ekrana bas)
    if args.summary:
        type_summary = {}
        severity_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for s in suspicious:
            type_summary[s["type"]] = type_summary.get(s["type"], 0) + 1
            severity_summary[s["severity"]] += 1

        print("\n=== ATTACK TYPE SUMMARY ===")
        for k, v in type_summary.items():
            print(f"{k}: {v}")

        print("\n=== SEVERITY SUMMARY ===")
        for k, v in severity_summary.items():
            print(f"{k}: {v}")

    # 5️⃣ Rapor yaz
    write_report(
        total=len(lines),
        suspicious=suspicious,
        output_file=args.output,
        output_format=args.format
    )

    # 6️⃣ Bilgi çıktısı
    print("\nAnaliz tamamlandı.")
    print(f"Girdi: {args.input}")
    print(f"Çıktı: {args.output}")
    print(f"Toplam satır: {len(lines)} | Şüpheli: {len(suspicious)}")


if __name__ == "__main__":
    main()
