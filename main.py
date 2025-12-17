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
    return parser.parse_args()

def main():
    args = parse_args()

    lines = read_logs(args.input)
    suspicious = detect_suspicious(lines)
    write_report(
    total=len(lines),
    suspicious=suspicious,
    output_file=args.output,
    output_format=args.format
    )

    print("Analiz tamamlandı.")
    print(f"Girdi: {args.input}")
    print(f"Çıktı: {args.output}")
    print(f"Toplam satır: {len(lines)} | Şüpheli: {len(suspicious)}")

if __name__ == "__main__":
    main()
