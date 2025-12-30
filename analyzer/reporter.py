"""
Rapor oluşturma modülü - Exception handling ile güçlendirilmiş
"""
import json
import csv
import sys
from utils.validators import validate_output_path
from analyzer.html_reporter import generate_html_report


def write_report(total, suspicious, output_file, output_format="txt"):
    """
    Analiz raporunu yaz
    
    Args:
        total: Toplam log satırı sayısı
        suspicious: Şüpheli event listesi
        output_file: Çıktı dosya yolu
        output_format: Rapor formatı (txt, json, csv, html)
    """
    # Çıktı dosyası doğrulama
    is_valid, error_msg = validate_output_path(output_file)
    
    if not is_valid:
        print(f"❌ Hata: {error_msg}")
        sys.exit(1)
    
    try:
        if output_format == "json":
            write_json(total, suspicious, output_file)
        elif output_format == "csv":
            write_csv(suspicious, output_file)
        elif output_format == "html":
            generate_html_report(total, suspicious, output_file)
        else:
            write_txt(total, suspicious, output_file)
        
        print(f"✅ Rapor oluşturuldu: {output_file}")
    
    except PermissionError:
        print(f"❌ Dosya yazma izni yok: {output_file}")
        sys.exit(1)
    
    except IOError as e:
        print(f"❌ Dosya yazma hatası: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ Rapor oluşturma hatası: {e}")
        sys.exit(1)


def write_txt(total, suspicious, output_file):
    """
    Text formatında rapor yaz
    
    Args:
        total: Toplam log satırı sayısı
        suspicious: Şüpheli event listesi
        output_file: Çıktı dosya yolu
    """
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            # Başlık
            f.write("=" * 60 + "\n")
            f.write("        SECURITY ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            # Özet
            f.write(f"📊 Total log lines analyzed: {total}\n")
            f.write(f"🚨 Suspicious events detected: {len(suspicious)}\n")
            
            if suspicious:
                # Severity istatistikleri
                severity_counts = {}
                for item in suspicious:
                    sev = item.get("severity", "UNKNOWN")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                f.write(f"\n📈 Severity breakdown:\n")
                for severity, count in sorted(severity_counts.items()):
                    f.write(f"   - {severity}: {count}\n")
                
                # Attack type istatistikleri
                type_counts = {}
                for item in suspicious:
                    attack_type = item.get("type", "UNKNOWN")
                    type_counts[attack_type] = type_counts.get(attack_type, 0) + 1
                
                f.write(f"\n🎯 Attack types:\n")
                for attack_type, count in sorted(type_counts.items()):
                    f.write(f"   - {attack_type}: {count}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("=" * 60 + "\n\n")
            
            if not suspicious:
                f.write("✅ No suspicious activity detected!\n")
            else:
                # Detaylı bulgular
                for idx, item in enumerate(suspicious, 1):
                    f.write(f"[{idx}] {'-' * 55}\n")
                    f.write(f"IP Address:  {item.get('ip', 'N/A')}\n")
                    f.write(f"Attack Type: {item.get('type', 'N/A')}\n")
                    f.write(f"Severity:    {item.get('severity', 'N/A')}\n")
                    f.write(f"Risk Score:  {item.get('score', 'N/A')}\n")
                    f.write(f"Details:     {item.get('line', 'N/A')[:100]}...\n")
                    f.write("\n")
            
            f.write("=" * 60 + "\n")
            f.write("End of Report\n")
            f.write("=" * 60 + "\n")
    
    except Exception as e:
        raise IOError(f"Text rapor yazma hatası: {e}")


def write_json(total, suspicious, output_file):
    """
    JSON formatında rapor yaz
    
    Args:
        total: Toplam log satırı sayısı
        suspicious: Şüpheli event listesi
        output_file: Çıktı dosya yolu
    """
    try:
        report = {
            "summary": {
                "total_lines": total,
                "suspicious_count": len(suspicious),
                "timestamp": None  # Sonra datetime eklenebilir
            },
            "threats": suspicious
        }
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    except Exception as e:
        raise IOError(f"JSON rapor yazma hatası: {e}")


def write_csv(suspicious, output_file):
    """
    CSV formatında rapor yaz
    
    Args:
        suspicious: Şüpheli event listesi
        output_file: Çıktı dosya yolu
    """
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            if not suspicious:
                # Boş CSV
                writer = csv.writer(f)
                writer.writerow(["No suspicious events detected"])
                return
            
            fieldnames = ["ip", "type", "severity", "score", "details"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for item in suspicious:
                writer.writerow({
                    "ip": item.get("ip", "N/A"),
                    "type": item.get("type", "N/A"),
                    "severity": item.get("severity", "N/A"),
                    "score": item.get("score", "N/A"),
                    "details": item.get("line", "N/A")[:200]  # İlk 200 karakter
                })
    
    except Exception as e:
        raise IOError(f"CSV rapor yazma hatası: {e}")  