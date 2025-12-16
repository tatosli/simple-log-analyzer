def write_report(total, suspicious, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Toplam satır: {total}\n")
        f.write(f"Şüpheli satır: {len(suspicious)}\n")
        ratio = (len(suspicious) / total) * 100 if total > 0 else 0
        f.write(f"Şüpheli oranı: %{ratio:.2f}\n\n")

        for line in suspicious:
            f.write("[SUSPICIOUS] " + line)
