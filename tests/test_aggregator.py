"""
Unit tests for analyzer/aggregator.py
"""
import pytest
from analyzer.aggregator import score_events, aggregate_by_ip, calculate_risk_level


class TestScoreEvents:
    """Test event scoring"""
    
    def test_sql_injection_score(self):
        """Test SQL injection scoring"""
        events = [
            {"type": "SQL_INJECTION", "ip": "192.168.1.1"}
        ]
        
        scored = score_events(events)
        
        assert scored[0]["score"] == 10
    
    def test_xss_score(self):
        """Test XSS scoring"""
        events = [
            {"type": "XSS", "ip": "192.168.1.1"}
        ]
        
        scored = score_events(events)
        
        assert scored[0]["score"] == 8
    
    def test_path_traversal_score(self):
        """Test path traversal scoring"""
        events = [
            {"type": "PATH_TRAVERSAL", "ip": "192.168.1.1"}
        ]
        
        scored = score_events(events)
        
        assert scored[0]["score"] == 9
    
    def test_brute_force_score(self):
        """Test brute force scoring"""
        events = [
            {"type": "BRUTE_FORCE", "ip": "192.168.1.1"},
            {"type": "SSH_BRUTE_FORCE", "ip": "192.168.1.2"}
        ]
        
        scored = score_events(events)
        
        assert scored[0]["score"] == 7
        assert scored[1]["score"] == 7
    
    def test_unknown_type_score(self):
        """Test unknown attack type scoring"""
        events = [
            {"type": "UNKNOWN_ATTACK", "ip": "192.168.1.1"}
        ]
        
        scored = score_events(events)
        
        assert scored[0]["score"] == 5
    
    def test_multiple_events(self):
        """Test scoring multiple events"""
        events = [
            {"type": "SQL_INJECTION", "ip": "192.168.1.1"},
            {"type": "XSS", "ip": "192.168.1.2"},
            {"type": "PATH_TRAVERSAL", "ip": "192.168.1.3"}
        ]
        
        scored = score_events(events)
        
        assert len(scored) == 3
        assert scored[0]["score"] == 10
        assert scored[1]["score"] == 8
        assert scored[2]["score"] == 9
    
    def test_case_insensitive_matching(self):
        """Test case-insensitive type matching"""
        events = [
            {"type": "sql_injection", "ip": "192.168.1.1"},
            {"type": "SQL_INJECTION", "ip": "192.168.1.2"},
            {"type": "Sql_Injection", "ip": "192.168.1.3"}
        ]
        
        scored = score_events(events)
        
        assert all(e["score"] == 10 for e in scored)


class TestAggregateByIP:
    """Test IP aggregation"""
    
    def test_single_ip_single_attack(self):
        """Test aggregation with single IP and single attack"""
        events = [
            {"ip": "192.168.1.1", "type": "SQL_INJECTION", "score": 10}
        ]
        
        aggregated = aggregate_by_ip(events)
        
        assert "192.168.1.1" in aggregated
        assert aggregated["192.168.1.1"]["total_score"] == 10
        assert aggregated["192.168.1.1"]["count"] == 1
        assert aggregated["192.168.1.1"]["attacks"]["SQL_INJECTION"] == 1
    
    def test_single_ip_multiple_attacks(self):
        """Test aggregation with single IP and multiple attacks"""
        events = [
            {"ip": "192.168.1.1", "type": "SQL_INJECTION", "score": 10},
            {"ip": "192.168.1.1", "type": "XSS", "score": 8},
            {"ip": "192.168.1.1", "type": "PATH_TRAVERSAL", "score": 9}
        ]
        
        aggregated = aggregate_by_ip(events)
        
        assert aggregated["192.168.1.1"]["total_score"] == 27
        assert aggregated["192.168.1.1"]["count"] == 3
        assert aggregated["192.168.1.1"]["attacks"]["SQL_INJECTION"] == 1
        assert aggregated["192.168.1.1"]["attacks"]["XSS"] == 1
        assert aggregated["192.168.1.1"]["attacks"]["PATH_TRAVERSAL"] == 1
    
    def test_multiple_ips(self):
        """Test aggregation with multiple IPs"""
        events = [
            {"ip": "192.168.1.1", "type": "SQL_INJECTION", "score": 10},
            {"ip": "192.168.1.2", "type": "XSS", "score": 8},
            {"ip": "192.168.1.3", "type": "PATH_TRAVERSAL", "score": 9}
        ]
        
        aggregated = aggregate_by_ip(events)
        
        assert len(aggregated) == 3
        assert "192.168.1.1" in aggregated
        assert "192.168.1.2" in aggregated
        assert "192.168.1.3" in aggregated
    
    def test_repeated_attack_type(self):
        """Test aggregation with repeated attack types from same IP"""
        events = [
            {"ip": "192.168.1.1", "type": "SQL_INJECTION", "score": 10},
            {"ip": "192.168.1.1", "type": "SQL_INJECTION", "score": 10},
            {"ip": "192.168.1.1", "type": "SQL_INJECTION", "score": 10}
        ]
        
        aggregated = aggregate_by_ip(events)
        
        assert aggregated["192.168.1.1"]["total_score"] == 30
        assert aggregated["192.168.1.1"]["count"] == 3
        assert aggregated["192.168.1.1"]["attacks"]["SQL_INJECTION"] == 3
    
    def test_empty_events(self):
        """Test aggregation with empty events list"""
        events = []
        
        aggregated = aggregate_by_ip(events)
        
        assert len(aggregated) == 0


class TestCalculateRiskLevel:
    """Test risk level calculation"""
    
    def test_critical_level(self):
        """Test CRITICAL risk level"""
        assert calculate_risk_level(15) == "CRITICAL"
        assert calculate_risk_level(20) == "CRITICAL"
        assert calculate_risk_level(100) == "CRITICAL"
    
    def test_high_level(self):
        """Test HIGH risk level"""
        assert calculate_risk_level(8) == "HIGH"
        assert calculate_risk_level(10) == "HIGH"
        assert calculate_risk_level(14) == "HIGH"
    
    def test_medium_level(self):
        """Test MEDIUM risk level"""
        assert calculate_risk_level(4) == "MEDIUM"
        assert calculate_risk_level(6) == "MEDIUM"
        assert calculate_risk_level(7) == "MEDIUM"
    
    def test_low_level(self):
        """Test LOW risk level"""
        assert calculate_risk_level(0) == "LOW"
        assert calculate_risk_level(1) == "LOW"
        assert calculate_risk_level(3) == "LOW"
    
    def test_boundary_values(self):
        """Test boundary values"""
        assert calculate_risk_level(3) == "LOW"
        assert calculate_risk_level(4) == "MEDIUM"
        
        assert calculate_risk_level(7) == "MEDIUM"
        assert calculate_risk_level(8) == "HIGH"
        
        assert calculate_risk_level(14) == "HIGH"
        assert calculate_risk_level(15) == "CRITICAL"

def score_events(suspicious):
    """Her event'e risk skoru ekle"""
    for event in suspicious:
        # Event türüne göre skor ata
        event_type = event.get("type", "").lower()
        
        if "sql" in event_type or "command" in event_type:
            event["score"] = 10
        elif "xxe" in event_type:
            event["score"] = 9
        elif "path_traversal" in event_type or "ldap" in event_type or "upload" in event_type:
            event["score"] = 9
        elif "xss" in event_type:
            event["score"] = 8
        elif "brute_force" in event_type or "ssh" in event_type:
            event["score"] = 7
        elif "agent" in event_type or "directory" in event_type:
            event["score"] = 6
        else:
            event["score"] = 5
    
    return suspicious