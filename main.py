from analyzer.reader import read_logs
from analyzer.detector import detect_suspicious
from analyzer.reporter import write_report

INPUT_FILE = "input.txt"
OUTPUT_FILE = "report.txt"

def main():
    lines = read_logs(INPUT_FILE)
    suspicious = detect_suspicious(lines)
    write_report(len(lines), suspicious, OUTPUT_FILE)
    print("Analiz tamamlandı.")

if __name__ == "__main__":
    main()
