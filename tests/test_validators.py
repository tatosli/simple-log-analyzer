"""
Unit tests for utils/validators.py
"""
import pytest
import os
import tempfile
from utils.validators import (
    validate_file_path,
    validate_output_path,
    validate_ip,
    is_private_ip,
    is_loopback_ip,
    sanitize_log_line,
    validate_threshold,
    validate_score
)


class TestValidateFilePath:
    """Test file path validation"""
    
    def test_valid_file(self):
        """Test with a valid file"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_path = f.name
        
        try:
            is_valid, error_msg = validate_file_path(temp_path)
            assert is_valid == True
            assert error_msg == ""
        finally:
            os.unlink(temp_path)
    
    def test_nonexistent_file(self):
        """Test with non-existent file"""
        is_valid, error_msg = validate_file_path("/path/to/nonexistent/file.txt")
        assert is_valid == False
        assert "bulunamadı" in error_msg.lower()
    
    def test_empty_path(self):
        """Test with empty path"""
        is_valid, error_msg = validate_file_path("")
        assert is_valid == False
        assert "boş" in error_msg.lower()
    
    def test_directory_instead_of_file(self):
        """Test with directory instead of file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            is_valid, error_msg = validate_file_path(tmpdir)
            assert is_valid == False
            assert "geçerli bir dosya değil" in error_msg.lower()


class TestValidateIP:
    """Test IP address validation"""
    
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses"""
        assert validate_ip("192.168.1.1") == True
        assert validate_ip("10.0.0.1") == True
        assert validate_ip("8.8.8.8") == True
        assert validate_ip("255.255.255.255") == True
    
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses"""
        assert validate_ip("::1") == True
        assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True
        assert validate_ip("2001:db8::1") == True
    
    def test_invalid_ip(self):
        """Test invalid IP addresses"""
        assert validate_ip("256.1.1.1") == False
        assert validate_ip("192.168.1") == False
        assert validate_ip("not.an.ip.address") == False
        assert validate_ip("") == False
        assert validate_ip("192.168.1.1.1") == False


class TestIsPrivateIP:
    """Test private IP detection"""
    
    def test_private_ips(self):
        """Test private IP ranges"""
        assert is_private_ip("192.168.1.1") == True
        assert is_private_ip("10.0.0.1") == True
        assert is_private_ip("172.16.0.1") == True
        assert is_private_ip("172.31.255.255") == True
    
    def test_public_ips(self):
        """Test public IP addresses"""
        assert is_private_ip("8.8.8.8") == False
        assert is_private_ip("1.1.1.1") == False
        assert is_private_ip("93.184.216.34") == False  # example.com IP
    
    def test_invalid_ip(self):
        """Test invalid IP"""
        assert is_private_ip("not.an.ip") == False


class TestIsLoopbackIP:
    """Test loopback IP detection"""
    
    def test_loopback_ips(self):
        """Test loopback addresses"""
        assert is_loopback_ip("127.0.0.1") == True
        assert is_loopback_ip("127.0.0.255") == True
        assert is_loopback_ip("::1") == True
    
    def test_non_loopback_ips(self):
        """Test non-loopback addresses"""
        assert is_loopback_ip("192.168.1.1") == False
        assert is_loopback_ip("8.8.8.8") == False


class TestSanitizeLogLine:
    """Test log line sanitization"""
    
    def test_normal_log(self):
        """Test normal log line"""
        line = "192.168.1.1 - GET /index.html 200"
        result = sanitize_log_line(line)
        assert result == line
    
    def test_ansi_codes(self):
        """Test ANSI escape code removal"""
        line = "\x1b[31mRed text\x1b[0m normal text"
        result = sanitize_log_line(line)
        assert "\x1b" not in result
        assert "Red text normal text" in result
    
    def test_null_bytes(self):
        """Test null byte removal"""
        line = "text\x00with\x00nulls"
        result = sanitize_log_line(line)
        assert "\x00" not in result
        assert "textwith" in result or "text with" in result
    
    def test_excessive_whitespace(self):
        """Test excessive whitespace removal"""
        line = "text    with     many      spaces"
        result = sanitize_log_line(line)
        assert "    " not in result
        assert result == "text with many spaces"
    
    def test_empty_line(self):
        """Test empty line"""
        assert sanitize_log_line("") == ""
        assert sanitize_log_line("   ") == ""
    
    def test_carriage_return(self):
        """Test carriage return removal"""
        line = "text\rwith\rreturns"
        result = sanitize_log_line(line)
        assert "\r" not in result


class TestValidateThreshold:
    """Test threshold validation"""
    
    def test_valid_threshold(self):
        """Test valid threshold values"""
        is_valid, error_msg = validate_threshold(5)
        assert is_valid == True
        assert error_msg == ""
        
        is_valid, error_msg = validate_threshold(100)
        assert is_valid == True
    
    def test_threshold_too_low(self):
        """Test threshold below minimum"""
        is_valid, error_msg = validate_threshold(0)
        assert is_valid == False
        assert "en az" in error_msg.lower()
    
    def test_threshold_too_high(self):
        """Test threshold above maximum"""
        is_valid, error_msg = validate_threshold(1001)
        assert is_valid == False
        assert "en fazla" in error_msg.lower()
    
    def test_non_integer_threshold(self):
        """Test non-integer threshold"""
        is_valid, error_msg = validate_threshold("not_a_number")
        assert is_valid == False
        assert "tam sayı" in error_msg.lower()
    
    def test_custom_range(self):
        """Test custom min/max range"""
        is_valid, error_msg = validate_threshold(5, min_val=10, max_val=20)
        assert is_valid == False
        
        is_valid, error_msg = validate_threshold(15, min_val=10, max_val=20)
        assert is_valid == True


class TestValidateScore:
    """Test score validation"""
    
    def test_valid_score(self):
        """Test valid score values"""
        is_valid, error_msg = validate_score(50)
        assert is_valid == True
        assert error_msg == ""
        
        is_valid, error_msg = validate_score(0)
        assert is_valid == True
        
        is_valid, error_msg = validate_score(100)
        assert is_valid == True
        
        is_valid, error_msg = validate_score(75.5)
        assert is_valid == True
    
    def test_negative_score(self):
        """Test negative score"""
        is_valid, error_msg = validate_score(-10)
        assert is_valid == False
        assert "negatif" in error_msg.lower()
    
    def test_score_too_high(self):
        """Test score above 100"""
        is_valid, error_msg = validate_score(150)
        assert is_valid == False
        assert "100" in error_msg
    
    def test_non_numeric_score(self):
        """Test non-numeric score"""
        is_valid, error_msg = validate_score("not_a_number")
        assert is_valid == False
        assert "sayısal" in error_msg.lower()