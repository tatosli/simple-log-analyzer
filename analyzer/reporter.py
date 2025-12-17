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
    high = 0
    medium = 0

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Toplam satır: {total}\n")
        f.write(f"Şüpheli satır: {len(suspicious)}\n\n")

        for item in suspicious:
            f.write(f"IP: {item['ip']}\n")
            f.write(f"Log: {item['line']}\n")

            for match in item["matches"]:
                f.write(f"  - {match['type']} | Severity: {match['severity']}\n")
                if match["severity"] == "HIGH":
                    high += 1
                else:
                    medium += 1

            f.write("\n")

        f.write("ÖZET:\n")
        f.write(f"HIGH risk: {high}\n")
        f.write(f"MEDIUM risk: {medium}\n")


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
            for match in item["matches"]:
                writer.writerow([
                    item["ip"],
                    match["type"],
                    match["severity"],
                    item["line"]
                ])
