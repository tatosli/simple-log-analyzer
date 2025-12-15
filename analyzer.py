# -*- coding: utf-8 -*-

import argparse

parser = argparse.ArgumentParser(description="Simple Log Risk Analyzer")
parser.add_argument("--input", required=True, help="Input log file")
parser.add_argument("--output", required=True, help="Output report file")

args = parser.parse_args()

input_file = args.input
output_file = args.output

keywords = ["error", "failed", "unauthorized"]

total_lines = 0
suspicious_count = 0

with open(input_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

cleaned = []
for line in lines:
    if line.strip() == "":
        continue

    total_lines += 1
    lower_line = line.lower()

    is_suspicious = False
    for kw in keywords:
        if kw in lower_line:
            is_suspicious = True
            break

    if is_suspicious:
        suspicious_count += 1
        cleaned.append("[SUSPICIOUS] " + line)
    else:
        cleaned.append(line)

with open(output_file, "w", encoding="utf-8") as f:
    f.writelines(cleaned)

ratio = (suspicious_count / total_lines) * 100 if total_lines else 0

print("Analysis completed")
print(f"Total lines: {total_lines}")
print(f"Suspicious lines: {suspicious_count}")
print(f"Risk ratio: %{ratio:.2f}")
