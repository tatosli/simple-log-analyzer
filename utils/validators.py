"""
Input validation ve sanitization fonksiyonları
"""
import re
import os
import ipaddress


def validate_file_path(file_path):
    """
    Dosya yolunu doğrula
    
    Args:
        file_path: Kontrol edilecek dosya yolu
    
    Returns:
        tuple: (bool, str) - (Geçerli mi?, Hata mesajı)
    """
    if not file_path:
        return False, "Dosya yolu boş olamaz"
    
    if not os.path.exists(file_path):
        return False, f"Dosya bulunamadı: {file_path}"
    
    if not os.path.isfile(file_path):
        return False, f"Geçerli bir dosya değil: {file_path}"
    
    if not os.access(file_path, os.R_OK):
        return False, f"Dosya okunamıyor (izin hatası): {file_path}"
    
    # Dosya boyutu kontrolü (500MB limit)
    file_size = os.path.getsize(file_path)
    max_size = 500 * 1024 * 1024  # 500MB
    
    if file_size > max_size:
        size_mb = file_size / (1024 * 1024)
        return False, f"Dosya çok büyük ({size_mb:.2f}MB). Maximum 500MB destekleniyor."
    
    return True, ""


def validate_output_path(file_path):
    """
    Çıktı dosya yolunu doğrula
    
    Args:
        file_path: Kontrol edilecek çıktı dosya yolu
    
    Returns:
        tuple: (bool, str) - (Geçerli mi?, Hata mesajı)
    """
    if not file_path:
        return False, "Çıktı dosya yolu boş olamaz"
    
    directory = os.path.dirname(file_path)
    
    # Eğer dizin belirtilmişse ve yoksa
    if directory and not os.path.exists(directory):
        return False, f"Dizin bulunamadı: {directory}"
    
    # Eğer dizin belirtilmişse yazma izni kontrolü
    if directory and not os.access(directory, os.W_OK):
        return False, f"Dizine yazma izni yok: {directory}"
    
    # Eğer dizin belirtilmemişse mevcut dizini kontrol et
    if not directory and not os.access(".", os.W_OK):
        return False, "Mevcut dizine yazma izni yok"
    
    return True, ""


def validate_ip(ip):
    """
    IP adresini doğrula
    
    Args:
        ip: Kontrol edilecek IP adresi
    
    Returns:
        bool: Geçerli IP adresi mi?
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip):
    """
    Private IP adresi mi kontrol et
    
    Args:
        ip: Kontrol edilecek IP adresi
    
    Returns:
        bool: Private IP mi?
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_loopback_ip(ip):
    """
    Loopback IP adresi mi kontrol et
    
    Args:
        ip: Kontrol edilecek IP adresi
    
    Returns:
        bool: Loopback IP mi?
    """
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def sanitize_log_line(line):
    """
    Log satırını temizle (log injection saldırılarına karşı)
    
    Args:
        line: Temizlenecek log satırı
    
    Returns:
        str: Temizlenmiş log satırı
    """
    if not line:
        return ""
    
    # ANSI escape codes kaldır
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)
    
    # Null bytes kaldır
    line = line.replace('\x00', '')
    
    # Carriage return attacks için
    line = line.replace('\r', '')
    
    # Excessive whitespace temizle
    line = re.sub(r'\s+', ' ', line)
    
    return line.strip()


def validate_threshold(value, min_val=1, max_val=1000):
    """
    Threshold değerini doğrula
    
    Args:
        value: Kontrol edilecek değer
        min_val: Minimum değer
        max_val: Maximum değer
    
    Returns:
        tuple: (bool, str) - (Geçerli mi?, Hata mesajı)
    """
    if not isinstance(value, int):
        return False, "Threshold değeri tam sayı olmalı"
    
    if value < min_val:
        return False, f"Threshold en az {min_val} olmalı"
    
    if value > max_val:
        return False, f"Threshold en fazla {max_val} olabilir"
    
    return True, ""


def validate_score(score):
    """
    Risk skorunu doğrula
    
    Args:
        score: Kontrol edilecek skor
    
    Returns:
        tuple: (bool, str) - (Geçerli mi?, Hata mesajı)
    """
    if not isinstance(score, (int, float)):
        return False, "Skor sayısal bir değer olmalı"
    
    if score < 0:
        return False, "Skor negatif olamaz"
    
    if score > 100:
        return False, "Skor 100'den büyük olamaz"
    
    return True, ""