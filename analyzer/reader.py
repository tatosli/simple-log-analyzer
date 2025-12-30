"""
Log dosyası okuma modülü - Exception handling ile güçlendirilmiş
"""
import os
import sys
from utils.validators import validate_file_path, sanitize_log_line


def read_logs(file_path):
    """
    Log dosyasını oku ve satırlara böl
    
    Args:
        file_path: Okunacak log dosyasının yolu
    
    Returns:
        list: Log satırları listesi
    
    Raises:
        FileNotFoundError: Dosya bulunamazsa
        PermissionError: Dosya okunamazsa
        ValueError: Dosya çok büyükse
    """
    # Dosya doğrulama
    is_valid, error_msg = validate_file_path(file_path)
    
    if not is_valid:
        print(f"❌ Hata: {error_msg}")
        sys.exit(1)
    
    print(f"📂 Log dosyası okunuyor: {file_path}")
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        # Log satırlarını temizle
        cleaned_lines = [sanitize_log_line(line) for line in lines]
        
        # Boş satırları filtrele
        cleaned_lines = [line for line in cleaned_lines if line]
        
        print(f"✅ {len(cleaned_lines)} satır başarıyla okundu")
        
        return cleaned_lines
    
    except FileNotFoundError:
        print(f"❌ Dosya bulunamadı: {file_path}")
        sys.exit(1)
    
    except PermissionError:
        print(f"❌ Dosya okuma izni yok: {file_path}")
        sys.exit(1)
    
    except UnicodeDecodeError as e:
        print(f"❌ Dosya encoding hatası: {e}")
        print("ℹ️  Dosya UTF-8 formatında olmayabilir")
        sys.exit(1)
    
    except MemoryError:
        print(f"❌ Dosya çok büyük, bellek yetersiz")
        print("ℹ️  Daha küçük bir dosya kullanın veya streaming modunu deneyin")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")
        sys.exit(1)


def read_logs_streaming(file_path, chunk_size=10000):
    """
    Büyük log dosyalarını chunk'lar halinde oku
    
    Args:
        file_path: Okunacak log dosyasının yolu
        chunk_size: Her chunk'ta kaç satır olacak
    
    Yields:
        list: Her seferinde chunk_size kadar log satırı
    """
    # Dosya doğrulama
    is_valid, error_msg = validate_file_path(file_path)
    
    if not is_valid:
        print(f"❌ Hata: {error_msg}")
        sys.exit(1)
    
    print(f"📂 Log dosyası streaming modunda okunuyor: {file_path}")
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            chunk = []
            line_count = 0
            
            for line in f:
                cleaned_line = sanitize_log_line(line)
                
                if cleaned_line:
                    chunk.append(cleaned_line)
                    line_count += 1
                
                if len(chunk) >= chunk_size:
                    print(f"  📦 {line_count} satır işlendi...")
                    yield chunk
                    chunk = []
            
            # Son chunk'ı da gönder
            if chunk:
                print(f"  📦 {line_count} satır işlendi (son chunk)")
                yield chunk
        
        print(f"✅ Toplam {line_count} satır başarıyla okundu")
    
    except Exception as e:
        print(f"❌ Streaming okuma hatası: {e}")
        sys.exit(1)


def get_file_info(file_path):
    """
    Dosya hakkında bilgi al
    
    Args:
        file_path: Dosya yolu
    
    Returns:
        dict: Dosya bilgileri
    """
    try:
        stat = os.stat(file_path)
        
        return {
            "path": file_path,
            "size_bytes": stat.st_size,
            "size_mb": stat.st_size / (1024 * 1024),
            "created": stat.st_ctime,
            "modified": stat.st_mtime,
            "readable": os.access(file_path, os.R_OK)
        }
    
    except Exception as e:
        return {"error": str(e)}