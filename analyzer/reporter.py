import json
import csv

def write_report(total, suspicious, output_file, output_format="txt"):
    if output_format == "json":
        write_json(total, suspicious, output_file)
    elif output_format == "csv":
        write_csv(total, suspicious, output_file)
    else:
        write_txt(total, suspicious, output_file)

def write_txt(total, suspicious, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Toplam satır: {total}\n")
        f.write(f"Şüpheli satır: {len(suspicious)}\n\n")

        for item in suspicious:
            f.write(f"Type: {item['type']}\n")
            f.write(f"Severity: {item['severity']}\n")
            f.write(f"IP: {item['ip']}\n")
            f.write(f"Log: {item['line']}\n")
            f.write("-" * 40 + "\n")

def write_json(total, suspicious, output_file):
    data = {
        "total_lines": total,
        "suspicious_count": len(suspicious),
        "entries": suspicious
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(total, suspicious, output_file):
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "attack_type", "severity", "log"])

        for item in suspicious:
            writer.writerow([
                item["ip"],
                item["type"],
                item["severity"],
                item["line"]
            ])
