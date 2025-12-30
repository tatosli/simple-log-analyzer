"""
IP blacklist yönetimi - Exception handling ile güçlendirilmiş
"""
import os
import sys
from utils.validators import validate_ip, validate_score


def write_blacklist(suspicious, min_score, dry_run=False, filename="blacklist.txt"):
    """
    Blacklist dosyasını güncelle
    
    Args:
        suspicious: Şüpheli event listesi
        min_score: Minimum skor threshold
        dry_run: Sadece simüle et, dosyaya yazma
        filename: Blacklist dosya adı
    
    Returns:
        list: Eklenen yeni IP'ler
    """
    # Skor doğrulama
    is_valid, error_msg = validate_score(min_score)
    if not is_valid:
        print(f"❌ Geçersiz minimum skor: {error_msg}")
        sys.exit(1)
    
    print(f"\n🔒 Blacklist kontrolü başlatılıyor (min_score: {min_score})...")
    
    existing_ips = set()
    
    # Mevcut blacklist'i oku
    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                existing_ips = {line.strip() for line in f if line.strip()}
            print(f"📋 Mevcut blacklist'te {len(existing_ips)} IP var")
        except Exception as e:
            print(f"⚠️  Mevcut blacklist okunamadı: {e}")
    
    new_ips = []
    invalid_ips = []
    
    # Yeni IP'leri filtrele
    for item in suspicious:
        ip = item.get("ip")
        score = item.get("score", 0)
        
        # IP doğrulama
        if not ip or not validate_ip(ip):
            invalid_ips.append(ip)
            continue
        
        # Skor kontrolü
        if score >= min_score and ip not in existing_ips:
            new_ips.append({
                "ip": ip,
                "score": score,
                "type": item.get("type", "UNKNOWN")
            })
    
    # Geçersiz IP uyarısı
    if invalid_ips:
        print(f"⚠️  {len(invalid_ips)} geçersiz IP atlandı: {invalid_ips[:5]}")
    
    # Yeni IP yoksa
    if not new_ips:
        print("✅ Blacklist'e eklenecek yeni IP yok")
        return []
    
    # Dry run kontrolü
    if dry_run:
        print(f"\n🔍 [DRY-RUN] Blacklist'e eklenecek {len(new_ips)} IP:")
        for item in new_ips[:10]:  # İlk 10'u göster
            print(f"   - {item['ip']} (skor: {item['score']}, tip: {item['type']})")
        
        if len(new_ips) > 10:
            print(f"   ... ve {len(new_ips) - 10} IP daha")
        
        return [item['ip'] for item in new_ips]
    
    # Dosyaya yaz
    try:
        with open(filename, "a") as f:
            for item in new_ips:
                f.write(item['ip'] + "\n")
        
        print(f"✅ {len(new_ips)} yeni IP blacklist'e eklendi")
        
        # Özet göster
        for item in new_ips[:5]:
            print(f"   + {item['ip']} (skor: {item['score']})")
        
        if len(new_ips) > 5:
            print(f"   ... ve {len(new_ips) - 5} IP daha")
        
        return [item['ip'] for item in new_ips]
    
    except PermissionError:
        print(f"❌ Blacklist dosyasına yazma izni yok: {filename}")
        sys.exit(1)
    
    except IOError as e:
        print(f"❌ Blacklist yazma hatası: {e}")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")
        sys.exit(1)


def read_blacklist(filename="blacklist.txt"):
    """
    Blacklist dosyasını oku
    
    Args:
        filename: Blacklist dosya adı
    
    Returns:
        set: IP adresleri seti
    """
    if not os.path.exists(filename):
        return set()
    
    try:
        with open(filename, "r") as f:
            ips = {line.strip() for line in f if line.strip() and validate_ip(line.strip())}
        return ips
    
    except Exception as e:
        print(f"⚠️  Blacklist okuma hatası: {e}")
        return set()


def is_blacklisted(ip, filename="blacklist.txt"):
    """
    IP blacklist'te mi kontrol et
    
    Args:
        ip: Kontrol edilecek IP
        filename: Blacklist dosya adı
    
    Returns:
        bool: Blacklist'te mi?
    """
    blacklist = read_blacklist(filename)
    return ip in blacklist