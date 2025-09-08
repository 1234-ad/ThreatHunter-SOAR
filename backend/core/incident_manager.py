"""
Automated Incident Response Manager
Handles incident creation, escalation, and automated response workflows
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

class IncidentStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PlaybookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

@dataclass
class IncidentArtifact:
    """Evidence and artifacts collected during incident response"""
    artifact_id: str
    artifact_type: str  # file, network_capture, memory_dump, log_file
    file_path: str
    hash_md5: str
    hash_sha256: str
    collected_at: datetime
    collected_by: str
    description: str
    size_bytes: int

@dataclass
class PlaybookAction:
    """Individual action within a playbook"""
    action_id: str
    action_type: str  # isolate, collect, notify, block, scan
    description: str
    parameters: Dict
    status: PlaybookStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None
    error_message: Optional[str] = None

@dataclass
class Incident:
    """Incident data structure"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str]
    created_by: str
    
    # Threat information
    threat_type: str
    indicators: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    
    # Response information
    containment_actions: List[str]
    eradication_actions: List[str]
    recovery_actions: List[str]
    
    # Evidence and artifacts
    artifacts: List[IncidentArtifact]
    
    # Timeline
    timeline: List[Dict]
    
    # Playbook execution
    active_playbooks: List[str]
    completed_playbooks: List[str]
    
    # Additional metadata
    affected_systems: List[str]
    network_segments: List[str]
    estimated_impact: str
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None

class IncidentManager:
    """Automated incident response manager"""
    
    def __init__(self):
        self.incidents = {}  # In production, use database
        self.playbooks = {}
        self.active_responses = {}
        self.escalation_rules = []
        self.notification_channels = []
        self.is_running = False
        
        # Initialize default playbooks
        self._initialize_playbooks()
        
        # Initialize escalation rules
        self._initialize_escalation_rules()
    
    def _initialize_playbooks(self):
        """Initialize default incident response playbooks"""
        
        # Malware Incident Playbook
        malware_playbook = {
            'playbook_id': 'malware_response_v1',
            'name': 'Malware Incident Response',
            'description': 'Automated response for malware detections',
            'trigger_conditions': ['threat_type:malware', 'severity:high,critical'],
            'actions': [
                PlaybookAction(
                    action_id='isolate_system',
                    action_type='isolate',
                    description='Isolate infected system from network',
                    parameters={'isolation_type': 'network', 'preserve_evidence': True},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='collect_memory',
                    action_type='collect',
                    description='Collect memory dump from infected system',
                    parameters={'artifact_type': 'memory_dump', 'compression': True},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='scan_network',
                    action_type='scan',
                    description='Scan network for lateral movement',
                    parameters={'scan_type': 'lateral_movement', 'scope': 'subnet'},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='notify_team',
                    action_type='notify',
                    description='Notify incident response team',
                    parameters={'channels': ['email', 'slack'], 'urgency': 'high'},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='block_iocs',
                    action_type='block',
                    description='Block malicious IOCs on security devices',
                    parameters={'devices': ['firewall', 'proxy', 'dns'], 'duration': '24h'},
                    status=PlaybookStatus.PENDING
                )
            ]
        }
        
        # Network Intrusion Playbook
        network_playbook = {
            'playbook_id': 'network_intrusion_v1',
            'name': 'Network Intrusion Response',
            'description': 'Automated response for network intrusions',
            'trigger_conditions': ['threat_type:network_intrusion', 'severity:medium,high,critical'],
            'actions': [
                PlaybookAction(
                    action_id='capture_traffic',
                    action_type='collect',
                    description='Capture network traffic for analysis',
                    parameters={'duration': '30m', 'interfaces': ['all'], 'filter': 'suspicious_ips'},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='block_source_ip',
                    action_type='block',
                    description='Block source IP address',
                    parameters={'devices': ['firewall'], 'duration': '1h', 'review_required': True},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='analyze_logs',
                    action_type='analyze',
                    description='Analyze security logs for related activity',
                    parameters={'timeframe': '24h', 'log_sources': ['firewall', 'ids', 'proxy']},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='notify_soc',
                    action_type='notify',
                    description='Notify SOC team for investigation',
                    parameters={'channels': ['soc_dashboard', 'email'], 'priority': 'medium'},
                    status=PlaybookStatus.PENDING
                )
            ]
        }
        
        # Data Exfiltration Playbook
        exfiltration_playbook = {
            'playbook_id': 'data_exfiltration_v1',
            'name': 'Data Exfiltration Response',
            'description': 'Automated response for data exfiltration attempts',
            'trigger_conditions': ['threat_type:data_exfiltration', 'severity:high,critical'],
            'actions': [
                PlaybookAction(
                    action_id='block_external_comms',
                    action_type='block',
                    description='Block external communications from affected system',
                    parameters={'direction': 'outbound', 'protocols': ['http', 'https', 'ftp'], 'duration': '2h'},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='preserve_evidence',
                    action_type='collect',
                    description='Preserve forensic evidence',
                    parameters={'artifacts': ['disk_image', 'network_logs', 'system_logs']},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='notify_legal',
                    action_type='notify',
                    description='Notify legal and compliance teams',
                    parameters={'channels': ['secure_email'], 'urgency': 'critical', 'encryption': True},
                    status=PlaybookStatus.PENDING
                ),
                PlaybookAction(
                    action_id='assess_data_impact',
                    action_type='analyze',
                    description='Assess potential data impact',
                    parameters={'data_classification': 'all', 'scope': 'affected_systems'},
                    status=PlaybookStatus.PENDING
                )
            ]
        }
        
        self.playbooks = {
            'malware_response_v1': malware_playbook,
            'network_intrusion_v1': network_playbook,
            'data_exfiltration_v1': exfiltration_playbook
        }
        
        logger.info(f"Initialized {len(self.playbooks)} incident response playbooks")
    
    def _initialize_escalation_rules(self):
        """Initialize incident escalation rules"""
        self.escalation_rules = [
            {
                'rule_id': 'critical_immediate',
                'conditions': {'severity': 'critical'},
                'actions': ['notify_ciso', 'notify_management', 'activate_crisis_team'],
                'timeframe': 0  # Immediate
            },
            {
                'rule_id': 'high_15min',
                'conditions': {'severity': 'high', 'status': 'new'},
                'actions': ['notify_senior_analyst', 'assign_lead_investigator'],
                'timeframe': 900  # 15 minutes
            },
            {
                'rule_id': 'medium_1hour',
                'conditions': {'severity': 'medium', 'status': 'new'},
                'actions': ['notify_team_lead', 'assign_analyst'],
                'timeframe': 3600  # 1 hour
            },
            {
                'rule_id': 'stale_incident',
                'conditions': {'status': 'investigating', 'age_hours': 24},
                'actions': ['escalate_to_manager', 'request_status_update'],
                'timeframe': 86400  # 24 hours
            }
        ]
        
        logger.info(f"Initialized {len(self.escalation_rules)} escalation rules")
    
    async def create_incident(self, detection_result: Dict, analyst_id: str) -> str:
        """Create new incident from threat detection"""
        try:
            incident_id = str(uuid.uuid4())
            
            # Determine severity based on threat score
            threat_score = detection_result.get('threat_score', 0)
            if threat_score >= 10:
                severity = IncidentSeverity.CRITICAL
            elif threat_score >= 7:
                severity = IncidentSeverity.HIGH
            elif threat_score >= 4:
                severity = IncidentSeverity.MEDIUM
            else:
                severity = IncidentSeverity.LOW
            
            # Create incident
            incident = Incident(
                incident_id=incident_id,
                title=f"Threat Detection: {detection_result.get('detections', [{}])[0].get('threat_type', 'Unknown')}",
                description=self._generate_incident_description(detection_result),
                severity=severity,
                status=IncidentStatus.NEW,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                assigned_to=None,
                created_by=analyst_id,
                threat_type=detection_result.get('detections', [{}])[0].get('threat_type', 'unknown'),
                indicators=self._extract_indicators(detection_result),
                mitre_tactics=[],
                mitre_techniques=detection_result.get('mitre_techniques', []),
                containment_actions=[],
                eradication_actions=[],
                recovery_actions=[],
                artifacts=[],
                timeline=[{
                    'timestamp': datetime.utcnow().isoformat(),
                    'event': 'Incident Created',
                    'description': 'Incident created from automated threat detection',
                    'actor': analyst_id
                }],
                active_playbooks=[],
                completed_playbooks=[],
                affected_systems=self._extract_affected_systems(detection_result),
                network_segments=[],
                estimated_impact=self._estimate_impact(severity, detection_result)
            )
            
            # Store incident
            self.incidents[incident_id] = incident
            
            # Trigger automated response
            await self._trigger_automated_response(incident)
            
            # Apply escalation rules
            await self._apply_escalation_rules(incident)
            
            logger.info(f"Created incident {incident_id} with severity {severity.value}")
            return incident_id
            
        except Exception as e:
            logger.error(f"Failed to create incident: {str(e)}")
            raise
    
    def _generate_incident_description(self, detection_result: Dict) -> str:
        """Generate incident description from detection result"""
        detections = detection_result.get('detections', [])
        if not detections:
            return "Automated threat detection triggered"
        
        primary_detection = detections[0]
        description = f"Threat Type: {primary_detection.get('threat_type', 'Unknown')}\\n"
        description += f"Severity: {primary_detection.get('severity', 'Unknown')}\\n"
        description += f"Confidence: {primary_detection.get('confidence', 0):.2f}\\n"
        description += f"Description: {primary_detection.get('description', 'No description available')}\\n"
        
        if primary_detection.get('indicators'):
            description += f"Indicators: {', '.join(primary_detection['indicators'])}\\n"
        
        return description
    
    def _extract_indicators(self, detection_result: Dict) -> List[str]:
        """Extract indicators from detection result"""
        indicators = []
        for detection in detection_result.get('detections', []):
            indicators.extend(detection.get('indicators', []))
        return list(set(indicators))
    
    def _extract_affected_systems(self, detection_result: Dict) -> List[str]:
        """Extract affected systems from detection result"""
        log_data = detection_result.get('log_data', {})
        systems = []
        
        if 'hostname' in log_data:
            systems.append(log_data['hostname'])
        if 'source_ip' in log_data:
            systems.append(log_data['source_ip'])
        if 'computer_name' in log_data:
            systems.append(log_data['computer_name'])
        
        return list(set(systems))
    
    def _estimate_impact(self, severity: IncidentSeverity, detection_result: Dict) -> str:
        """Estimate incident impact"""
        impact_map = {
            IncidentSeverity.CRITICAL: "High - Potential for significant business disruption",
            IncidentSeverity.HIGH: "Medium-High - May affect business operations",
            IncidentSeverity.MEDIUM: "Medium - Limited business impact expected",
            IncidentSeverity.LOW: "Low - Minimal business impact"
        }
        return impact_map.get(severity, "Unknown impact")
    
    async def _trigger_automated_response(self, incident: Incident):
        """Trigger automated response playbooks"""
        try:
            # Find matching playbooks
            matching_playbooks = self._find_matching_playbooks(incident)
            
            for playbook_id in matching_playbooks:
                await self._execute_playbook(incident.incident_id, playbook_id)
            
        except Exception as e:
            logger.error(f"Failed to trigger automated response: {str(e)}")
    
    def _find_matching_playbooks(self, incident: Incident) -> List[str]:
        """Find playbooks that match incident conditions"""
        matching_playbooks = []
        
        for playbook_id, playbook in self.playbooks.items():
            conditions = playbook.get('trigger_conditions', [])
            
            for condition in conditions:
                if ':' in condition:
                    key, values = condition.split(':', 1)
                    value_list = [v.strip() for v in values.split(',')]
                    
                    if key == 'threat_type' and incident.threat_type in value_list:
                        matching_playbooks.append(playbook_id)
                        break
                    elif key == 'severity' and incident.severity.value in value_list:
                        matching_playbooks.append(playbook_id)
                        break
        
        return matching_playbooks
    
    async def _execute_playbook(self, incident_id: str, playbook_id: str):
        """Execute incident response playbook"""
        try:
            incident = self.incidents.get(incident_id)
            playbook = self.playbooks.get(playbook_id)
            
            if not incident or not playbook:
                logger.error(f"Invalid incident {incident_id} or playbook {playbook_id}")
                return
            
            logger.info(f"Executing playbook {playbook_id} for incident {incident_id}")
            
            # Add to active playbooks
            incident.active_playbooks.append(playbook_id)
            
            # Execute actions sequentially
            for action in playbook['actions']:
                try:
                    await self._execute_action(incident_id, action)
                except Exception as e:
                    logger.error(f"Action {action.action_id} failed: {str(e)}")
                    action.status = PlaybookStatus.FAILED
                    action.error_message = str(e)
            
            # Move to completed playbooks
            incident.active_playbooks.remove(playbook_id)
            incident.completed_playbooks.append(playbook_id)
            
            # Update incident timeline
            incident.timeline.append({
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'Playbook Completed',
                'description': f'Completed execution of playbook: {playbook["name"]}',
                'actor': 'system'
            })
            
            logger.info(f"Completed playbook {playbook_id} for incident {incident_id}")
            
        except Exception as e:
            logger.error(f"Failed to execute playbook {playbook_id}: {str(e)}")
    
    async def _execute_action(self, incident_id: str, action: PlaybookAction):
        """Execute individual playbook action"""
        try:
            action.status = PlaybookStatus.RUNNING
            action.started_at = datetime.utcnow()
            
            logger.info(f"Executing action {action.action_id}: {action.description}")
            
            # Simulate action execution based on type
            if action.action_type == 'isolate':
                result = await self._isolate_system(action.parameters)
            elif action.action_type == 'collect':
                result = await self._collect_evidence(action.parameters)
            elif action.action_type == 'notify':
                result = await self._send_notification(action.parameters)
            elif action.action_type == 'block':
                result = await self._block_indicators(action.parameters)
            elif action.action_type == 'scan':
                result = await self._scan_network(action.parameters)
            elif action.action_type == 'analyze':
                result = await self._analyze_data(action.parameters)
            else:
                result = {'status': 'unknown_action_type'}
            
            action.result = result
            action.status = PlaybookStatus.COMPLETED
            action.completed_at = datetime.utcnow()
            
            # Update incident timeline
            incident = self.incidents[incident_id]
            incident.timeline.append({
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'Action Completed',
                'description': f'Completed action: {action.description}',
                'actor': 'system',
                'result': result
            })
            
        except Exception as e:
            action.status = PlaybookStatus.FAILED
            action.error_message = str(e)
            action.completed_at = datetime.utcnow()
            raise
    
    async def _isolate_system(self, parameters: Dict) -> Dict:
        """Simulate system isolation"""
        await asyncio.sleep(2)  # Simulate processing time
        return {
            'status': 'success',
            'message': f'System isolated using {parameters.get("isolation_type", "network")} isolation',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _collect_evidence(self, parameters: Dict) -> Dict:
        """Simulate evidence collection"""
        await asyncio.sleep(5)  # Simulate processing time
        artifact_type = parameters.get('artifact_type', 'unknown')
        return {
            'status': 'success',
            'message': f'Collected {artifact_type} evidence',
            'artifact_id': str(uuid.uuid4()),
            'size_mb': 150,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _send_notification(self, parameters: Dict) -> Dict:
        """Simulate notification sending"""
        await asyncio.sleep(1)  # Simulate processing time
        channels = parameters.get('channels', [])
        return {
            'status': 'success',
            'message': f'Notifications sent via {", ".join(channels)}',
            'recipients': 5,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _block_indicators(self, parameters: Dict) -> Dict:
        """Simulate IOC blocking"""
        await asyncio.sleep(3)  # Simulate processing time
        devices = parameters.get('devices', [])
        return {
            'status': 'success',
            'message': f'IOCs blocked on {", ".join(devices)}',
            'blocked_count': 10,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _scan_network(self, parameters: Dict) -> Dict:
        """Simulate network scanning"""
        await asyncio.sleep(10)  # Simulate processing time
        scan_type = parameters.get('scan_type', 'general')
        return {
            'status': 'success',
            'message': f'Completed {scan_type} network scan',
            'hosts_scanned': 50,
            'suspicious_findings': 2,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _analyze_data(self, parameters: Dict) -> Dict:
        """Simulate data analysis"""
        await asyncio.sleep(7)  # Simulate processing time
        return {
            'status': 'success',
            'message': 'Data analysis completed',
            'findings': 3,
            'confidence': 0.85,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _apply_escalation_rules(self, incident: Incident):
        """Apply escalation rules to incident"""
        try:
            for rule in self.escalation_rules:
                if self._matches_escalation_conditions(incident, rule['conditions']):
                    if rule['timeframe'] == 0:
                        # Immediate escalation
                        await self._execute_escalation_actions(incident, rule['actions'])
                    else:
                        # Schedule delayed escalation
                        asyncio.create_task(
                            self._delayed_escalation(incident.incident_id, rule, rule['timeframe'])
                        )
        
        except Exception as e:
            logger.error(f"Failed to apply escalation rules: {str(e)}")
    
    def _matches_escalation_conditions(self, incident: Incident, conditions: Dict) -> bool:
        """Check if incident matches escalation conditions"""
        for key, value in conditions.items():
            if key == 'severity' and incident.severity.value != value:
                return False
            elif key == 'status' and incident.status.value != value:
                return False
            elif key == 'age_hours':
                age_hours = (datetime.utcnow() - incident.created_at).total_seconds() / 3600
                if age_hours < value:
                    return False
        return True
    
    async def _delayed_escalation(self, incident_id: str, rule: Dict, delay_seconds: int):
        """Execute delayed escalation"""
        await asyncio.sleep(delay_seconds)
        
        incident = self.incidents.get(incident_id)
        if incident and self._matches_escalation_conditions(incident, rule['conditions']):
            await self._execute_escalation_actions(incident, rule['actions'])
    
    async def _execute_escalation_actions(self, incident: Incident, actions: List[str]):
        """Execute escalation actions"""
        for action in actions:
            try:
                if action == 'notify_ciso':
                    await self._notify_ciso(incident)
                elif action == 'notify_management':
                    await self._notify_management(incident)
                elif action == 'activate_crisis_team':
                    await self._activate_crisis_team(incident)
                elif action == 'notify_senior_analyst':
                    await self._notify_senior_analyst(incident)
                elif action == 'assign_lead_investigator':
                    await self._assign_lead_investigator(incident)
                
                # Update timeline
                incident.timeline.append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'event': 'Escalation Action',
                    'description': f'Executed escalation action: {action}',
                    'actor': 'system'
                })
                
            except Exception as e:
                logger.error(f"Escalation action {action} failed: {str(e)}")
    
    async def _notify_ciso(self, incident: Incident):
        """Notify CISO of critical incident"""
        logger.info(f"CISO notification sent for incident {incident.incident_id}")
    
    async def _notify_management(self, incident: Incident):
        """Notify management of critical incident"""
        logger.info(f"Management notification sent for incident {incident.incident_id}")
    
    async def _activate_crisis_team(self, incident: Incident):
        """Activate crisis response team"""
        logger.info(f"Crisis team activated for incident {incident.incident_id}")
    
    async def _notify_senior_analyst(self, incident: Incident):
        """Notify senior analyst"""
        logger.info(f"Senior analyst notified for incident {incident.incident_id}")
    
    async def _assign_lead_investigator(self, incident: Incident):
        """Assign lead investigator"""
        incident.assigned_to = "senior_analyst_001"
        logger.info(f"Lead investigator assigned to incident {incident.incident_id}")
    
    async def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get incident by ID"""
        incident = self.incidents.get(incident_id)
        if incident:
            return asdict(incident)
        return None
    
    async def list_incidents(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict]:
        """List incidents with optional filtering"""
        incidents = []
        
        for incident in self.incidents.values():
            if status and incident.status.value != status:
                continue
            if severity and incident.severity.value != severity:
                continue
            
            incidents.append(asdict(incident))
        
        return sorted(incidents, key=lambda x: x['created_at'], reverse=True)
    
    async def update_incident_status(self, incident_id: str, status: str, analyst_id: str) -> bool:
        """Update incident status"""
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        
        old_status = incident.status.value
        incident.status = IncidentStatus(status)
        incident.updated_at = datetime.utcnow()
        
        # Update timeline
        incident.timeline.append({
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'Status Change',
            'description': f'Status changed from {old_status} to {status}',
            'actor': analyst_id
        })
        
        return True
    
    def is_healthy(self) -> bool:
        """Check if incident manager is healthy"""
        return len(self.playbooks) > 0 and len(self.escalation_rules) > 0