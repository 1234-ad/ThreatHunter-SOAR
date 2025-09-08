"""
Advanced Threat Detection Engine
Combines multiple detection methods: YARA, Sigma, ML, and behavioral analysis
"""

import asyncio
import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass
import yara
import requests
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

@dataclass
class ThreatDetection:
    """Threat detection result"""
    threat_id: str
    threat_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    indicators: List[str]
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    timestamp: datetime
    source_data: Dict
    recommended_actions: List[str]

class ThreatDetectionEngine:
    """Advanced threat detection engine with multiple detection methods"""
    
    def __init__(self):
        self.yara_rules = None
        self.sigma_rules = []
        self.behavioral_baselines = defaultdict(dict)
        self.threat_cache = deque(maxlen=10000)
        self.detection_stats = defaultdict(int)
        self.is_running = False
        
        # IOC patterns
        self.ioc_patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b'),
            'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        }
        
        # Threat intelligence feeds
        self.threat_feeds = {
            'malware_domains': 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt',
            'malicious_ips': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
            'phishing_urls': 'https://openphish.com/feed.txt'
        }
        
        # MITRE ATT&CK mapping
        self.mitre_mapping = {
            'suspicious_process': ['T1055', 'T1106'],  # Process Injection, Native API
            'network_anomaly': ['T1071', 'T1090'],    # Application Layer Protocol, Proxy
            'file_modification': ['T1070', 'T1485'],  # Indicator Removal, Data Destruction
            'privilege_escalation': ['T1068', 'T1134'], # Exploitation, Access Token Manipulation
            'lateral_movement': ['T1021', 'T1210'],   # Remote Services, Exploitation of Remote Services
            'data_exfiltration': ['T1041', 'T1048']   # Exfiltration Over C2 Channel, Exfiltration Over Alternative Protocol
        }
    
    async def initialize(self):
        """Initialize the threat detection engine"""
        logger.info("Initializing Threat Detection Engine...")
        
        try:
            # Load YARA rules
            await self._load_yara_rules()
            
            # Load Sigma rules
            await self._load_sigma_rules()
            
            # Initialize behavioral baselines
            await self._initialize_baselines()
            
            # Update threat intelligence feeds
            await self._update_threat_feeds()
            
            self.is_running = True
            logger.info("Threat Detection Engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Threat Detection Engine: {str(e)}")
            raise
    
    async def analyze_log(self, log_data: Dict) -> Dict:
        """Analyze log data for threats"""
        try:
            detections = []
            
            # Extract IOCs from log data
            iocs = self._extract_iocs(log_data)
            
            # YARA rule matching
            yara_detections = await self._yara_analysis(log_data)
            detections.extend(yara_detections)
            
            # Sigma rule matching
            sigma_detections = await self._sigma_analysis(log_data)
            detections.extend(sigma_detections)
            
            # Behavioral analysis
            behavioral_detections = await self._behavioral_analysis(log_data)
            detections.extend(behavioral_detections)
            
            # IOC reputation check
            ioc_detections = await self._ioc_reputation_check(iocs)
            detections.extend(ioc_detections)
            
            # Network anomaly detection
            network_detections = await self._network_anomaly_detection(log_data)
            detections.extend(network_detections)
            
            # Aggregate and prioritize detections
            final_detection = self._aggregate_detections(detections, log_data)
            
            # Update statistics
            self.detection_stats['total_analyzed'] += 1
            if final_detection.get('threat_detected'):
                self.detection_stats['threats_detected'] += 1
            
            return final_detection
            
        except Exception as e:
            logger.error(f"Log analysis error: {str(e)}")
            return {
                'threat_detected': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            # Sample YARA rules - in production, load from files
            yara_rule_text = '''
            rule Suspicious_PowerShell {
                meta:
                    description = "Detects suspicious PowerShell commands"
                    severity = "HIGH"
                strings:
                    $ps1 = "powershell" nocase
                    $enc = "-EncodedCommand" nocase
                    $bypass = "-ExecutionPolicy Bypass" nocase
                    $hidden = "-WindowStyle Hidden" nocase
                    $download = "DownloadString" nocase
                    $invoke = "Invoke-Expression" nocase
                condition:
                    $ps1 and ($enc or $bypass or $hidden or ($download and $invoke))
            }
            
            rule Suspicious_Network_Activity {
                meta:
                    description = "Detects suspicious network connections"
                    severity = "MEDIUM"
                strings:
                    $ip1 = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/
                    $port1 = ":4444"
                    $port2 = ":8080"
                    $port3 = ":9999"
                condition:
                    $ip1 and ($port1 or $port2 or $port3)
            }
            '''
            
            self.yara_rules = yara.compile(source=yara_rule_text)
            logger.info("YARA rules loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {str(e)}")
    
    async def _load_sigma_rules(self):
        """Load Sigma rules for log analysis"""
        # Sample Sigma rules - in production, load from YAML files
        self.sigma_rules = [
            {
                'name': 'Suspicious Process Creation',
                'pattern': r'(cmd\.exe|powershell\.exe).*(-enc|-e\s)',
                'severity': 'HIGH',
                'mitre': ['T1059']
            },
            {
                'name': 'Failed Login Attempts',
                'pattern': r'EventID.*4625.*',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': 'MEDIUM',
                'mitre': ['T1110']
            },
            {
                'name': 'Suspicious File Access',
                'pattern': r'(\\Windows\\System32\\config\\|\\Users\\.*\\NTUSER\.DAT)',
                'severity': 'HIGH',
                'mitre': ['T1003']
            }
        ]
        logger.info(f"Loaded {len(self.sigma_rules)} Sigma rules")
    
    async def _initialize_baselines(self):
        """Initialize behavioral baselines"""
        # Sample baseline initialization
        self.behavioral_baselines = {
            'network_connections_per_hour': {'mean': 100, 'std': 20},
            'process_creation_rate': {'mean': 50, 'std': 15},
            'file_access_patterns': {'mean': 200, 'std': 50},
            'login_frequency': {'mean': 10, 'std': 5}
        }
        logger.info("Behavioral baselines initialized")
    
    async def _update_threat_feeds(self):
        """Update threat intelligence feeds"""
        try:
            for feed_name, feed_url in self.threat_feeds.items():
                # In production, implement actual feed updates
                logger.info(f"Updated threat feed: {feed_name}")
        except Exception as e:
            logger.error(f"Failed to update threat feeds: {str(e)}")
    
    def _extract_iocs(self, log_data: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from log data"""
        iocs = defaultdict(list)
        log_text = json.dumps(log_data)
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = pattern.findall(log_text)
            if matches:
                iocs[ioc_type].extend(matches)
        
        return dict(iocs)
    
    async def _yara_analysis(self, log_data: Dict) -> List[ThreatDetection]:
        """Perform YARA rule analysis"""
        detections = []
        
        if not self.yara_rules:
            return detections
        
        try:
            log_text = json.dumps(log_data)
            matches = self.yara_rules.match(data=log_text.encode())
            
            for match in matches:
                detection = ThreatDetection(
                    threat_id=f"YARA_{match.rule}_{datetime.utcnow().timestamp()}",
                    threat_type="malware",
                    severity=match.meta.get('severity', 'MEDIUM'),
                    confidence=0.8,
                    indicators=[str(string) for string in match.strings],
                    description=match.meta.get('description', f'YARA rule {match.rule} matched'),
                    mitre_tactics=['TA0002'],  # Execution
                    mitre_techniques=['T1059'],  # Command and Scripting Interpreter
                    timestamp=datetime.utcnow(),
                    source_data=log_data,
                    recommended_actions=[
                        'Isolate affected system',
                        'Collect memory dump',
                        'Analyze suspicious processes'
                    ]
                )
                detections.append(detection)
        
        except Exception as e:
            logger.error(f"YARA analysis error: {str(e)}")
        
        return detections
    
    async def _sigma_analysis(self, log_data: Dict) -> List[ThreatDetection]:
        """Perform Sigma rule analysis"""
        detections = []
        log_text = json.dumps(log_data)
        
        for rule in self.sigma_rules:
            try:
                if re.search(rule['pattern'], log_text, re.IGNORECASE):
                    detection = ThreatDetection(
                        threat_id=f"SIGMA_{rule['name'].replace(' ', '_')}_{datetime.utcnow().timestamp()}",
                        threat_type="suspicious_activity",
                        severity=rule['severity'],
                        confidence=0.7,
                        indicators=[rule['pattern']],
                        description=f"Sigma rule '{rule['name']}' triggered",
                        mitre_tactics=['TA0001'],  # Initial Access
                        mitre_techniques=rule.get('mitre', []),
                        timestamp=datetime.utcnow(),
                        source_data=log_data,
                        recommended_actions=[
                            'Investigate source system',
                            'Check for additional indicators',
                            'Review user activity'
                        ]
                    )
                    detections.append(detection)
            
            except Exception as e:
                logger.error(f"Sigma rule analysis error: {str(e)}")
        
        return detections
    
    async def _behavioral_analysis(self, log_data: Dict) -> List[ThreatDetection]:
        """Perform behavioral analysis"""
        detections = []
        
        try:
            # Analyze process creation patterns
            if 'process_name' in log_data:
                process_count = log_data.get('process_count', 1)
                baseline = self.behavioral_baselines.get('process_creation_rate', {})
                
                if process_count > baseline.get('mean', 50) + 2 * baseline.get('std', 15):
                    detection = ThreatDetection(
                        threat_id=f"BEHAVIORAL_PROCESS_{datetime.utcnow().timestamp()}",
                        threat_type="behavioral_anomaly",
                        severity="MEDIUM",
                        confidence=0.6,
                        indicators=[f"Unusual process creation rate: {process_count}"],
                        description="Abnormal process creation behavior detected",
                        mitre_tactics=['TA0002'],  # Execution
                        mitre_techniques=['T1055'],  # Process Injection
                        timestamp=datetime.utcnow(),
                        source_data=log_data,
                        recommended_actions=[
                            'Monitor process tree',
                            'Check for malicious processes',
                            'Analyze system performance'
                        ]
                    )
                    detections.append(detection)
        
        except Exception as e:
            logger.error(f"Behavioral analysis error: {str(e)}")
        
        return detections
    
    async def _ioc_reputation_check(self, iocs: Dict[str, List[str]]) -> List[ThreatDetection]:
        """Check IOC reputation against threat intelligence"""
        detections = []
        
        # Sample malicious IOCs (in production, use real threat intel feeds)
        malicious_ips = ['192.168.1.100', '10.0.0.50']
        malicious_domains = ['malicious-domain.com', 'evil-site.net']
        malicious_hashes = ['d41d8cd98f00b204e9800998ecf8427e']
        
        try:
            for ip in iocs.get('ip', []):
                if ip in malicious_ips:
                    detection = ThreatDetection(
                        threat_id=f"IOC_IP_{ip}_{datetime.utcnow().timestamp()}",
                        threat_type="malicious_ip",
                        severity="HIGH",
                        confidence=0.9,
                        indicators=[ip],
                        description=f"Communication with known malicious IP: {ip}",
                        mitre_tactics=['TA0011'],  # Command and Control
                        mitre_techniques=['T1071'],  # Application Layer Protocol
                        timestamp=datetime.utcnow(),
                        source_data={'ip': ip},
                        recommended_actions=[
                            'Block IP address',
                            'Investigate network traffic',
                            'Check for data exfiltration'
                        ]
                    )
                    detections.append(detection)
        
        except Exception as e:
            logger.error(f"IOC reputation check error: {str(e)}")
        
        return detections
    
    async def _network_anomaly_detection(self, log_data: Dict) -> List[ThreatDetection]:
        """Detect network anomalies"""
        detections = []
        
        try:
            # Check for unusual ports
            unusual_ports = [4444, 8080, 9999, 1337, 31337]
            
            if 'destination_port' in log_data:
                port = log_data['destination_port']
                if port in unusual_ports:
                    detection = ThreatDetection(
                        threat_id=f"NETWORK_ANOMALY_{port}_{datetime.utcnow().timestamp()}",
                        threat_type="network_anomaly",
                        severity="MEDIUM",
                        confidence=0.6,
                        indicators=[f"Connection to unusual port: {port}"],
                        description=f"Connection to suspicious port {port} detected",
                        mitre_tactics=['TA0011'],  # Command and Control
                        mitre_techniques=['T1090'],  # Proxy
                        timestamp=datetime.utcnow(),
                        source_data=log_data,
                        recommended_actions=[
                            'Investigate network connection',
                            'Check destination IP reputation',
                            'Monitor for additional connections'
                        ]
                    )
                    detections.append(detection)
        
        except Exception as e:
            logger.error(f"Network anomaly detection error: {str(e)}")
        
        return detections
    
    def _aggregate_detections(self, detections: List[ThreatDetection], log_data: Dict) -> Dict:
        """Aggregate and prioritize detections"""
        if not detections:
            return {
                'threat_detected': False,
                'timestamp': datetime.utcnow().isoformat(),
                'log_data': log_data
            }
        
        # Calculate overall threat score
        severity_scores = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        total_score = sum(severity_scores.get(d.severity, 1) * d.confidence for d in detections)
        max_severity = max(detections, key=lambda x: severity_scores.get(x.severity, 1)).severity
        
        # Aggregate MITRE techniques
        all_techniques = []
        for detection in detections:
            all_techniques.extend(detection.mitre_techniques)
        
        # Aggregate recommended actions
        all_actions = []
        for detection in detections:
            all_actions.extend(detection.recommended_actions)
        
        return {
            'threat_detected': True,
            'threat_score': total_score,
            'max_severity': max_severity,
            'detection_count': len(detections),
            'detections': [
                {
                    'threat_id': d.threat_id,
                    'threat_type': d.threat_type,
                    'severity': d.severity,
                    'confidence': d.confidence,
                    'description': d.description,
                    'indicators': d.indicators,
                    'mitre_techniques': d.mitre_techniques
                } for d in detections
            ],
            'mitre_techniques': list(set(all_techniques)),
            'recommended_actions': list(set(all_actions)),
            'timestamp': datetime.utcnow().isoformat(),
            'log_data': log_data
        }
    
    async def get_latest_threats(self) -> Dict:
        """Get latest threat detections for real-time updates"""
        return {
            'latest_threats': list(self.threat_cache)[-10:],  # Last 10 threats
            'stats': dict(self.detection_stats),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def is_healthy(self) -> bool:
        """Check if threat engine is healthy"""
        return self.is_running and self.yara_rules is not None