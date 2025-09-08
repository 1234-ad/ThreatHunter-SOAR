"""
Comprehensive test suite for ThreatHunter-SOAR Threat Detection Engine
Tests all major components including YARA rules, ML detection, and incident response
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import numpy as np

# Import modules to test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from core.threat_engine import ThreatDetectionEngine, ThreatDetection
from core.incident_manager import IncidentManager, Incident, IncidentSeverity, IncidentStatus
from ml_pipeline.models.threat_classifier import ThreatClassifier, FeatureExtractor

class TestThreatDetectionEngine:
    """Test suite for the Threat Detection Engine"""
    
    @pytest.fixture
    async def threat_engine(self):
        """Create a threat engine instance for testing"""
        engine = ThreatDetectionEngine()
        await engine.initialize()
        return engine
    
    @pytest.fixture
    def sample_log_data(self):
        """Sample log data for testing"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "192.168.1.100",
            "destination_ip": "8.8.8.8",
            "source_port": 12345,
            "destination_port": 53,
            "protocol": "udp",
            "process_name": "chrome.exe",
            "command_line": "chrome.exe --no-sandbox",
            "user_name": "testuser",
            "bytes_in": 100,
            "bytes_out": 200,
            "file_path": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\chrome.exe"
        }
    
    @pytest.fixture
    def malicious_log_data(self):
        """Malicious log data for testing detection"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "10.0.0.50",
            "destination_ip": "192.168.1.1",
            "source_port": 4444,
            "destination_port": 80,
            "protocol": "tcp",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "user_name": "admin",
            "bytes_in": 1000,
            "bytes_out": 50000,
            "file_path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
        }
    
    @pytest.mark.asyncio
    async def test_engine_initialization(self, threat_engine):
        """Test threat engine initialization"""
        assert threat_engine.is_running
        assert threat_engine.yara_rules is not None
        assert len(threat_engine.sigma_rules) > 0
        assert len(threat_engine.behavioral_baselines) > 0
    
    @pytest.mark.asyncio
    async def test_benign_log_analysis(self, threat_engine, sample_log_data):
        """Test analysis of benign log data"""
        result = await threat_engine.analyze_log(sample_log_data)
        
        assert "threat_detected" in result
        assert "timestamp" in result
        
        # Benign traffic should have low or no threat detection
        if result["threat_detected"]:
            assert result["max_severity"] in ["LOW", "MEDIUM"]
    
    @pytest.mark.asyncio
    async def test_malicious_log_analysis(self, threat_engine, malicious_log_data):
        """Test analysis of malicious log data"""
        result = await threat_engine.analyze_log(malicious_log_data)
        
        assert result["threat_detected"] is True
        assert result["max_severity"] in ["HIGH", "CRITICAL"]
        assert result["detection_count"] > 0
        assert len(result["detections"]) > 0
        
        # Check for PowerShell detection
        powershell_detected = any(
            "powershell" in detection["description"].lower() 
            for detection in result["detections"]
        )
        assert powershell_detected
    
    @pytest.mark.asyncio
    async def test_ioc_extraction(self, threat_engine, sample_log_data):
        """Test IOC extraction from log data"""
        iocs = threat_engine._extract_iocs(sample_log_data)
        
        assert "ip" in iocs
        assert "192.168.1.100" in iocs["ip"]
        assert "8.8.8.8" in iocs["ip"]
    
    @pytest.mark.asyncio
    async def test_yara_analysis(self, threat_engine, malicious_log_data):
        """Test YARA rule analysis"""
        detections = await threat_engine._yara_analysis(malicious_log_data)
        
        # Should detect PowerShell suspicious activity
        assert len(detections) > 0
        assert any("powershell" in d.description.lower() for d in detections)
    
    @pytest.mark.asyncio
    async def test_sigma_analysis(self, threat_engine, malicious_log_data):
        """Test Sigma rule analysis"""
        detections = await threat_engine._sigma_analysis(malicious_log_data)
        
        # Should detect suspicious process creation
        assert len(detections) > 0
        assert any("process" in d.description.lower() for d in detections)
    
    @pytest.mark.asyncio
    async def test_behavioral_analysis(self, threat_engine, sample_log_data):
        """Test behavioral analysis"""
        # Modify log data to trigger behavioral detection
        sample_log_data["process_count"] = 1000  # Abnormally high
        
        detections = await threat_engine._behavioral_analysis(sample_log_data)
        
        assert len(detections) > 0
        assert any("behavioral" in d.threat_type for d in detections)
    
    @pytest.mark.asyncio
    async def test_network_anomaly_detection(self, threat_engine, malicious_log_data):
        """Test network anomaly detection"""
        detections = await threat_engine._network_anomaly_detection(malicious_log_data)
        
        # Should detect suspicious port 4444
        assert len(detections) > 0
        assert any("4444" in str(d.indicators) for d in detections)
    
    @pytest.mark.asyncio
    async def test_threat_engine_health(self, threat_engine):
        """Test threat engine health check"""
        assert threat_engine.is_healthy() is True
    
    @pytest.mark.asyncio
    async def test_latest_threats(self, threat_engine):
        """Test getting latest threats"""
        result = await threat_engine.get_latest_threats()
        
        assert "latest_threats" in result
        assert "stats" in result
        assert "timestamp" in result

class TestIncidentManager:
    """Test suite for the Incident Manager"""
    
    @pytest.fixture
    def incident_manager(self):
        """Create an incident manager instance for testing"""
        return IncidentManager()
    
    @pytest.fixture
    def sample_detection_result(self):
        """Sample detection result for incident creation"""
        return {
            "threat_detected": True,
            "threat_score": 8.5,
            "max_severity": "HIGH",
            "detection_count": 2,
            "detections": [
                {
                    "threat_id": "test_threat_001",
                    "threat_type": "malware",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "description": "Suspicious PowerShell execution detected",
                    "indicators": ["powershell.exe", "-enc"],
                    "mitre_techniques": ["T1059.001"]
                }
            ],
            "mitre_techniques": ["T1059.001"],
            "recommended_actions": ["Isolate system", "Collect evidence"],
            "log_data": {
                "hostname": "WORKSTATION-01",
                "source_ip": "192.168.1.100"
            }
        }
    
    @pytest.mark.asyncio
    async def test_incident_creation(self, incident_manager, sample_detection_result):
        """Test incident creation from detection result"""
        incident_id = await incident_manager.create_incident(
            sample_detection_result, 
            "analyst_001"
        )
        
        assert incident_id is not None
        assert incident_id in incident_manager.incidents
        
        incident = incident_manager.incidents[incident_id]
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.status == IncidentStatus.NEW
        assert incident.threat_type == "malware"
        assert len(incident.timeline) > 0
    
    @pytest.mark.asyncio
    async def test_playbook_matching(self, incident_manager):
        """Test playbook matching logic"""
        # Create a test incident
        incident = Incident(
            incident_id="test_incident",
            title="Test Malware Incident",
            description="Test incident",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.NEW,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            assigned_to=None,
            created_by="analyst_001",
            threat_type="malware",
            indicators=["test_indicator"],
            mitre_tactics=[],
            mitre_techniques=[],
            containment_actions=[],
            eradication_actions=[],
            recovery_actions=[],
            artifacts=[],
            timeline=[],
            active_playbooks=[],
            completed_playbooks=[],
            affected_systems=["WORKSTATION-01"],
            network_segments=[],
            estimated_impact="Medium impact"
        )
        
        matching_playbooks = incident_manager._find_matching_playbooks(incident)
        
        assert len(matching_playbooks) > 0
        assert "malware_response_v1" in matching_playbooks
    
    @pytest.mark.asyncio
    async def test_playbook_execution(self, incident_manager, sample_detection_result):
        """Test playbook execution"""
        # Create incident
        incident_id = await incident_manager.create_incident(
            sample_detection_result, 
            "analyst_001"
        )
        
        # Execute playbook
        await incident_manager._execute_playbook(incident_id, "malware_response_v1")
        
        incident = incident_manager.incidents[incident_id]
        assert "malware_response_v1" in incident.completed_playbooks
        assert len(incident.timeline) > 1  # Should have additional timeline entries
    
    @pytest.mark.asyncio
    async def test_incident_status_update(self, incident_manager, sample_detection_result):
        """Test incident status updates"""
        # Create incident
        incident_id = await incident_manager.create_incident(
            sample_detection_result, 
            "analyst_001"
        )
        
        # Update status
        success = await incident_manager.update_incident_status(
            incident_id, 
            "investigating", 
            "analyst_002"
        )
        
        assert success is True
        
        incident = incident_manager.incidents[incident_id]
        assert incident.status == IncidentStatus.INVESTIGATING
        
        # Check timeline update
        status_change_events = [
            event for event in incident.timeline 
            if event.get("event") == "Status Change"
        ]
        assert len(status_change_events) > 0
    
    @pytest.mark.asyncio
    async def test_incident_listing(self, incident_manager, sample_detection_result):
        """Test incident listing with filters"""
        # Create multiple incidents
        incident_id1 = await incident_manager.create_incident(
            sample_detection_result, 
            "analyst_001"
        )
        
        # Modify detection result for second incident
        sample_detection_result["threat_score"] = 3.0
        sample_detection_result["max_severity"] = "MEDIUM"
        incident_id2 = await incident_manager.create_incident(
            sample_detection_result, 
            "analyst_002"
        )
        
        # Test listing all incidents
        all_incidents = await incident_manager.list_incidents()
        assert len(all_incidents) == 2
        
        # Test filtering by severity
        high_incidents = await incident_manager.list_incidents(severity="high")
        assert len(high_incidents) == 1
        
        # Test filtering by status
        new_incidents = await incident_manager.list_incidents(status="new")
        assert len(new_incidents) == 2
    
    def test_incident_manager_health(self, incident_manager):
        """Test incident manager health check"""
        assert incident_manager.is_healthy() is True

class TestThreatClassifier:
    """Test suite for the ML Threat Classifier"""
    
    @pytest.fixture
    def threat_classifier(self):
        """Create a threat classifier instance for testing"""
        return ThreatClassifier()
    
    @pytest.fixture
    def feature_extractor(self):
        """Create a feature extractor instance for testing"""
        return FeatureExtractor()
    
    @pytest.fixture
    def sample_training_data(self):
        """Sample training data for ML model"""
        return [
            {
                "source_ip": "192.168.1.100",
                "destination_ip": "8.8.8.8",
                "source_port": 12345,
                "destination_port": 53,
                "protocol": "udp",
                "bytes_in": 100,
                "bytes_out": 200,
                "process_name": "chrome.exe",
                "command_line": "chrome.exe --no-sandbox",
                "file_path": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\chrome.exe"
            },
            {
                "source_ip": "10.0.0.50",
                "destination_ip": "192.168.1.1",
                "source_port": 4444,
                "destination_port": 80,
                "protocol": "tcp",
                "bytes_in": 1000,
                "bytes_out": 50000,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
                "file_path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
            },
            {
                "source_ip": "172.16.0.10",
                "destination_ip": "172.16.0.20",
                "source_port": 445,
                "destination_port": 445,
                "protocol": "tcp",
                "bytes_in": 5000,
                "bytes_out": 10000,
                "process_name": "svchost.exe",
                "command_line": "svchost.exe -k netsvcs",
                "file_path": "C:\\\\Windows\\\\System32\\\\svchost.exe"
            }
        ]
    
    @pytest.fixture
    def sample_labels(self):
        """Sample labels for training data"""
        return ["benign", "malware", "lateral_movement"]
    
    def test_feature_extraction_network(self, feature_extractor, sample_training_data):
        """Test network feature extraction"""
        features = feature_extractor.extract_network_features(sample_training_data[0])
        
        assert "src_port" in features
        assert "dst_port" in features
        assert "protocol" in features
        assert "src_ip_private" in features
        assert "dst_ip_private" in features
        assert features["src_port"] == 12345
        assert features["dst_port"] == 53
    
    def test_feature_extraction_process(self, feature_extractor, sample_training_data):
        """Test process feature extraction"""
        features = feature_extractor.extract_process_features(sample_training_data[1])
        
        assert "process_name_len" in features
        assert "cmdline_len" in features
        assert "powershell_detected" in features
        assert "encoded_command" in features
        assert features["powershell_detected"] is True
        assert features["encoded_command"] is True
    
    def test_entropy_calculation(self, feature_extractor):
        """Test entropy calculation"""
        # Test with random string (high entropy)
        high_entropy_text = "aB3$kL9@mN2#pQ7&"
        high_entropy = feature_extractor._calculate_entropy(high_entropy_text)
        
        # Test with repetitive string (low entropy)
        low_entropy_text = "aaaaaaaaaa"
        low_entropy = feature_extractor._calculate_entropy(low_entropy_text)
        
        assert high_entropy > low_entropy
        assert high_entropy > 3.0  # Should be reasonably high
        assert low_entropy < 1.0   # Should be very low
    
    def test_base64_ratio_calculation(self, feature_extractor):
        """Test base64 ratio calculation"""
        # Test with base64 string
        base64_text = "SGVsbG8gV29ybGQ="
        base64_ratio = feature_extractor._base64_ratio(base64_text)
        
        # Test with regular text
        regular_text = "Hello World!"
        regular_ratio = feature_extractor._base64_ratio(regular_text)
        
        assert base64_ratio > regular_ratio
        assert base64_ratio > 0.8  # Should be high for base64
    
    def test_suspicious_port_detection(self, feature_extractor):
        """Test suspicious port detection"""
        assert feature_extractor._is_suspicious_port(4444) is True
        assert feature_extractor._is_suspicious_port(8080) is True
        assert feature_extractor._is_suspicious_port(80) is False
        assert feature_extractor._is_suspicious_port(443) is False
    
    def test_private_ip_detection(self, feature_extractor):
        """Test private IP detection"""
        assert feature_extractor._is_private_ip("192.168.1.1") is True
        assert feature_extractor._is_private_ip("10.0.0.1") is True
        assert feature_extractor._is_private_ip("172.16.0.1") is True
        assert feature_extractor._is_private_ip("8.8.8.8") is False
        assert feature_extractor._is_private_ip("1.1.1.1") is False
    
    def test_classifier_initialization(self, threat_classifier):
        """Test threat classifier initialization"""
        threat_classifier.initialize_models()
        
        assert len(threat_classifier.models) > 0
        assert "random_forest" in threat_classifier.models
        assert "gradient_boosting" in threat_classifier.models
        assert "neural_network" in threat_classifier.models
        assert len(threat_classifier.ensemble_weights) > 0
    
    def test_feature_preparation(self, threat_classifier, sample_training_data):
        """Test feature preparation for ML models"""
        X, feature_names = threat_classifier.prepare_features(sample_training_data)
        
        assert X.shape[0] == len(sample_training_data)
        assert X.shape[1] > 0  # Should have features
        assert len(feature_names) > 0
    
    def test_model_training(self, threat_classifier, sample_training_data, sample_labels):
        """Test ML model training"""
        # Note: This is a minimal test with limited data
        # In practice, you'd need much more training data
        
        results = threat_classifier.train(sample_training_data, sample_labels)
        
        assert threat_classifier.is_trained is True
        assert "model_scores" in results
        assert "evaluation_results" in results
        assert results["training_samples"] == len(sample_training_data)
    
    def test_threat_prediction(self, threat_classifier, sample_training_data, sample_labels):
        """Test threat prediction"""
        # Train model first
        threat_classifier.train(sample_training_data, sample_labels)
        
        # Test prediction
        test_data = sample_training_data[1]  # Use malware sample
        prediction = threat_classifier.predict(test_data)
        
        assert "threat_type" in prediction
        assert "confidence" in prediction
        assert "threat_score" in prediction
        assert "severity" in prediction
        assert prediction["confidence"] >= 0.0
        assert prediction["confidence"] <= 1.0
        assert prediction["threat_score"] >= 0.0
        assert prediction["threat_score"] <= 100.0

class TestIntegration:
    """Integration tests for the complete system"""
    
    @pytest.fixture
    async def full_system(self):
        """Set up complete system for integration testing"""
        threat_engine = ThreatDetectionEngine()
        incident_manager = IncidentManager()
        
        await threat_engine.initialize()
        
        return {
            "threat_engine": threat_engine,
            "incident_manager": incident_manager
        }
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_detection(self, full_system):
        """Test complete end-to-end threat detection and incident creation"""
        threat_engine = full_system["threat_engine"]
        incident_manager = full_system["incident_manager"]
        
        # Malicious log data
        malicious_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": "10.0.0.50",
            "destination_ip": "192.168.1.1",
            "source_port": 4444,
            "destination_port": 80,
            "protocol": "tcp",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "user_name": "admin",
            "hostname": "WORKSTATION-01"
        }
        
        # 1. Detect threat
        detection_result = await threat_engine.analyze_log(malicious_log)
        
        assert detection_result["threat_detected"] is True
        
        # 2. Create incident
        incident_id = await incident_manager.create_incident(
            detection_result, 
            "analyst_001"
        )
        
        assert incident_id is not None
        
        # 3. Verify incident was created with correct data
        incident = incident_manager.incidents[incident_id]
        assert incident.threat_type in ["malware", "suspicious_activity"]
        assert incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
        assert "WORKSTATION-01" in incident.affected_systems
        
        # 4. Verify playbook was triggered
        assert len(incident.active_playbooks) > 0 or len(incident.completed_playbooks) > 0
        
        # 5. Verify timeline entries
        assert len(incident.timeline) > 0
        creation_events = [
            event for event in incident.timeline 
            if event.get("event") == "Incident Created"
        ]
        assert len(creation_events) > 0

# Pytest configuration and fixtures
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# Test data generators
def generate_network_traffic_data(count=100):
    """Generate synthetic network traffic data for testing"""
    import random
    
    data = []
    for i in range(count):
        data.append({
            "source_ip": f"192.168.1.{random.randint(1, 254)}",
            "destination_ip": f"8.8.{random.randint(1, 8)}.{random.randint(1, 8)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([80, 443, 53, 22, 21, 25]),
            "protocol": random.choice(["tcp", "udp"]),
            "bytes_in": random.randint(100, 10000),
            "bytes_out": random.randint(100, 10000),
            "duration": random.randint(1, 300)
        })
    
    return data

def generate_process_data(count=50):
    """Generate synthetic process data for testing"""
    import random
    
    processes = [
        "chrome.exe", "firefox.exe", "notepad.exe", "calc.exe",
        "powershell.exe", "cmd.exe", "svchost.exe", "explorer.exe"
    ]
    
    data = []
    for i in range(count):
        process = random.choice(processes)
        data.append({
            "process_name": process,
            "command_line": f"{process} --normal-operation",
            "process_id": random.randint(1000, 9999),
            "parent_process_id": random.randint(100, 999),
            "user_name": random.choice(["user1", "admin", "system"]),
            "file_path": f"C:\\\\Program Files\\\\{process}"
        })
    
    return data

# Performance tests
class TestPerformance:
    """Performance tests for the system"""
    
    @pytest.mark.asyncio
    async def test_threat_detection_performance(self):
        """Test threat detection performance with multiple logs"""
        threat_engine = ThreatDetectionEngine()
        await threat_engine.initialize()
        
        # Generate test data
        test_logs = generate_network_traffic_data(100)
        
        import time
        start_time = time.time()
        
        # Process all logs
        results = []
        for log in test_logs:
            result = await threat_engine.analyze_log(log)
            results.append(result)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Performance assertions
        assert processing_time < 30.0  # Should process 100 logs in under 30 seconds
        assert len(results) == 100
        
        # Calculate throughput
        throughput = len(test_logs) / processing_time
        print(f"Threat detection throughput: {throughput:.2f} logs/second")
        
        assert throughput > 3.0  # Should process at least 3 logs per second

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])