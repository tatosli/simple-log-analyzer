"""
Unit tests for security/blacklist.py
"""
import pytest
import os
import tempfile
from security.blacklist import write_blacklist, read_blacklist, is_blacklisted


class TestWriteBlacklist:
    """Test blacklist writing"""
    
    def test_write_new_ips(self):
        """Test writing new IPs to empty blacklist"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        
        try:
            events = [
                {"ip": "192.168.1.1", "score": 100, "type": "SQL_INJECTION"},
                {"ip": "192.168.1.2", "score": 80, "type": "XSS"}
            ]
            
            new_ips = write_blacklist(events, min_score=50, filename=temp_file)
            
            assert len(new_ips) == 2
            assert "192.168.1.1" in new_ips
            assert "192.168.1.2" in new_ips
            
            # Verify file content
            with open(temp_file, 'r') as f:
                content = f.read().strip().split('\n')
                assert "192.168.1.1" in content
                assert "192.168.1.2" in content
        
        finally:
            os.unlink(temp_file)
    
    def test_filter_by_score(self):
        """Test filtering IPs by minimum score"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        
        try:
            events = [
                {"ip": "192.168.1.1", "score": 100, "type": "SQL_INJECTION"},
                {"ip": "192.168.1.2", "score": 40, "type": "LOW_RISK"},
                {"ip": "192.168.1.3", "score": 80, "type": "XSS"}
            ]
            
            new_ips = write_blacklist(events, min_score=50, filename=temp_file)
            
            assert len(new_ips) == 2
            assert "192.168.1.1" in new_ips
            assert "192.168.1.2" not in new_ips
            assert "192.168.1.3" in new_ips
        
        finally:
            os.unlink(temp_file)
    
    def test_skip_existing_ips(self):
        """Test skipping IPs that are already in blacklist"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("192.168.1.1\n")
            temp_file = f.name
        
        try:
            events = [
                {"ip": "192.168.1.1", "score": 100, "type": "SQL_INJECTION"},
                {"ip": "192.168.1.2", "score": 80, "type": "XSS"}
            ]
            
            new_ips = write_blacklist(events, min_score=50, filename=temp_file)
            
            assert len(new_ips) == 1
            assert "192.168.1.1" not in new_ips
            assert "192.168.1.2" in new_ips
        
        finally:
            os.unlink(temp_file)
    
    def test_dry_run_mode(self):
        """Test dry-run mode (no file writing)"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        
        try:
            events = [
                {"ip": "192.168.1.1", "score": 100, "type": "SQL_INJECTION"}
            ]
            
            new_ips = write_blacklist(events, min_score=50, dry_run=True, filename=temp_file)
            
            assert len(new_ips) == 1
            assert "192.168.1.1" in new_ips
            
            # File should be empty (dry-run doesn't write)
            with open(temp_file, 'r') as f:
                content = f.read().strip()
                assert content == ""
        
        finally:
            os.unlink(temp_file)
    
    def test_invalid_ip(self):
        """Test handling of invalid IPs"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        
        try:
            events = [
                {"ip": "192.168.1.1", "score": 100, "type": "SQL_INJECTION"},
                {"ip": "invalid.ip.address", "score": 100, "type": "ATTACK"},
                {"ip": "999.999.999.999", "score": 100, "type": "ATTACK"}
            ]
            
            new_ips = write_blacklist(events, min_score=50, filename=temp_file)
            
            # Only valid IP should be added
            assert len(new_ips) == 1
            assert "192.168.1.1" in new_ips
        
        finally:
            os.unlink(temp_file)
    
    def test_empty_events(self):
        """Test with empty events list"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        
        try:
            events = []
            
            new_ips = write_blacklist(events, min_score=50, filename=temp_file)
            
            assert len(new_ips) == 0
        
        finally:
            os.unlink(temp_file)


class TestReadBlacklist:
    """Test blacklist reading"""
    
    def test_read_existing_blacklist(self):
        """Test reading existing blacklist"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("192.168.1.1\n")
            f.write("192.168.1.2\n")
            f.write("10.0.0.1\n")
            temp_file = f.name
        
        try:
            ips = read_blacklist(temp_file)
            
            assert len(ips) == 3
            assert "192.168.1.1" in ips
            assert "192.168.1.2" in ips
            assert "10.0.0.1" in ips
        
        finally:
            os.unlink(temp_file)
    
    def test_read_nonexistent_file(self):
        """Test reading non-existent blacklist"""
        ips = read_blacklist("/path/to/nonexistent/file.txt")
        
        assert len(ips) == 0
    
    def test_read_with_invalid_ips(self):
        """Test reading blacklist with invalid IPs"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("192.168.1.1\n")
            f.write("invalid.ip\n")
            f.write("192.168.1.2\n")
            f.write("999.999.999.999\n")
            temp_file = f.name
        
        try:
            ips = read_blacklist(temp_file)
            
            # Only valid IPs should be returned
            assert len(ips) == 2
            assert "192.168.1.1" in ips
            assert "192.168.1.2" in ips
            assert "invalid.ip" not in ips
        
        finally:
            os.unlink(temp_file)
    
    def test_read_with_empty_lines(self):
        """Test reading blacklist with empty lines"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("192.168.1.1\n")
            f.write("\n")
            f.write("192.168.1.2\n")
            f.write("   \n")
            temp_file = f.name
        
        try:
            ips = read_blacklist(temp_file)
            
            assert len(ips) == 2
            assert "192.168.1.1" in ips
            assert "192.168.1.2" in ips
        
        finally:
            os.unlink(temp_file)


class TestIsBlacklisted:
    """Test blacklist checking"""
    
    def test_ip_is_blacklisted(self):
        """Test checking if IP is blacklisted"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("192.168.1.1\n")
            f.write("10.0.0.1\n")
            temp_file = f.name
        
        try:
            assert is_blacklisted("192.168.1.1", temp_file) == True
            assert is_blacklisted("10.0.0.1", temp_file) == True
            assert is_blacklisted("192.168.1.2", temp_file) == False
        
        finally:
            os.unlink(temp_file)
    
    def test_nonexistent_blacklist(self):
        """Test checking against non-existent blacklist"""
        result = is_blacklisted("192.168.1.1", "/path/to/nonexistent.txt")
        
        assert result == False