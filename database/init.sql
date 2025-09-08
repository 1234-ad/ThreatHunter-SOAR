-- ThreatHunter-SOAR Database Initialization
-- Creates all necessary tables and indexes for the SOC platform

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS threats;
CREATE SCHEMA IF NOT EXISTS incidents;
CREATE SCHEMA IF NOT EXISTS intel;
CREATE SCHEMA IF NOT EXISTS playbooks;
CREATE SCHEMA IF NOT EXISTS users;

-- ============================================================================
-- USERS AND AUTHENTICATION
-- ============================================================================

CREATE TABLE users.analysts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE users.sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analyst_id UUID REFERENCES users.analysts(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- THREAT INTELLIGENCE
-- ============================================================================

CREATE TABLE intel.iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type VARCHAR(50) NOT NULL, -- ip, domain, hash, url, email
    ioc_value VARCHAR(500) NOT NULL,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source VARCHAR(100) NOT NULL,
    tags TEXT[],
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE intel.threat_feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    feed_name VARCHAR(100) NOT NULL,
    feed_url VARCHAR(500),
    feed_type VARCHAR(50) NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE,
    update_frequency INTEGER DEFAULT 3600, -- seconds
    is_enabled BOOLEAN DEFAULT true,
    api_key_required BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE intel.mitre_techniques (
    technique_id VARCHAR(20) PRIMARY KEY,
    technique_name VARCHAR(255) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT,
    detection_methods TEXT[],
    mitigation_methods TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- THREAT DETECTIONS
-- ============================================================================

CREATE TABLE threats.detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    detection_name VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    source_system VARCHAR(100) NOT NULL,
    source_ip INET,
    destination_ip INET,
    affected_systems TEXT[],
    indicators TEXT[],
    mitre_techniques VARCHAR(20)[],
    raw_data JSONB,
    detection_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    analyst_id UUID REFERENCES users.analysts(id),
    status VARCHAR(50) DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'confirmed', 'false_positive', 'resolved')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE threats.detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(50) NOT NULL, -- yara, sigma, custom
    rule_content TEXT NOT NULL,
    threat_types VARCHAR(100)[],
    severity VARCHAR(20) NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    false_positive_rate DECIMAL(5,4) DEFAULT 0.0000,
    created_by UUID REFERENCES users.analysts(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INCIDENTS
-- ============================================================================

CREATE TABLE incidents.incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_number VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(50) NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'contained', 'eradicated', 'recovered', 'closed')),
    priority INTEGER DEFAULT 3 CHECK (priority >= 1 AND priority <= 5),
    
    -- Assignment
    assigned_to UUID REFERENCES users.analysts(id),
    created_by UUID REFERENCES users.analysts(id) NOT NULL,
    
    -- Threat information
    threat_type VARCHAR(100),
    attack_vectors TEXT[],
    indicators TEXT[],
    mitre_tactics VARCHAR(100)[],
    mitre_techniques VARCHAR(20)[],
    
    -- Impact assessment
    affected_systems TEXT[],
    affected_users TEXT[],
    business_impact TEXT,
    estimated_cost DECIMAL(12,2),
    
    -- Timeline
    detected_at TIMESTAMP WITH TIME ZONE,
    contained_at TIMESTAMP WITH TIME ZONE,
    eradicated_at TIMESTAMP WITH TIME ZONE,
    recovered_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    tags TEXT[],
    external_references TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE incidents.incident_timeline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES incidents.incidents(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    event_description TEXT NOT NULL,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    actor_type VARCHAR(50) NOT NULL, -- system, analyst, external
    actor_id VARCHAR(255),
    additional_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE incidents.evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES incidents.incidents(id) ON DELETE CASCADE,
    evidence_type VARCHAR(100) NOT NULL, -- file, network_capture, memory_dump, log_file, screenshot
    file_name VARCHAR(500),
    file_path VARCHAR(1000),
    file_size BIGINT,
    hash_md5 VARCHAR(32),
    hash_sha1 VARCHAR(40),
    hash_sha256 VARCHAR(64),
    collected_by UUID REFERENCES users.analysts(id),
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    chain_of_custody JSONB,
    description TEXT,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- PLAYBOOKS AND AUTOMATION
-- ============================================================================

CREATE TABLE playbooks.playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_name VARCHAR(255) NOT NULL,
    version VARCHAR(20) NOT NULL DEFAULT '1.0',
    description TEXT,
    trigger_conditions JSONB NOT NULL,
    phases JSONB NOT NULL,
    variables JSONB,
    success_criteria TEXT[],
    created_by UUID REFERENCES users.analysts(id),
    is_active BOOLEAN DEFAULT true,
    execution_count INTEGER DEFAULT 0,
    success_rate DECIMAL(5,2) DEFAULT 0.00,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE playbooks.executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id UUID REFERENCES playbooks.playbooks(id),
    incident_id UUID REFERENCES incidents.incidents(id),
    execution_status VARCHAR(50) NOT NULL DEFAULT 'running' CHECK (execution_status IN ('running', 'completed', 'failed', 'paused', 'cancelled')),
    started_by UUID REFERENCES users.analysts(id),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    execution_log JSONB,
    error_message TEXT,
    success_criteria_met BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE playbooks.action_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID REFERENCES playbooks.executions(id) ON DELETE CASCADE,
    action_id VARCHAR(255) NOT NULL,
    action_name VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    result_data JSONB,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- SYSTEM MONITORING
-- ============================================================================

CREATE TABLE threats.system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,4) NOT NULL,
    metric_unit VARCHAR(50),
    system_component VARCHAR(100) NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    tags JSONB
);

CREATE TABLE threats.alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    condition_operator VARCHAR(10) NOT NULL CHECK (condition_operator IN ('>', '<', '>=', '<=', '=', '!=')),
    threshold_value DECIMAL(15,4) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    notification_channels TEXT[],
    is_enabled BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users.analysts(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- IOCs indexes
CREATE INDEX idx_iocs_type_value ON intel.iocs(ioc_type, ioc_value);
CREATE INDEX idx_iocs_threat_type ON intel.iocs(threat_type);
CREATE INDEX idx_iocs_first_seen ON intel.iocs(first_seen);
CREATE INDEX idx_iocs_confidence ON intel.iocs(confidence_score DESC);
CREATE INDEX idx_iocs_tags ON intel.iocs USING GIN(tags);

-- Detections indexes
CREATE INDEX idx_detections_time ON threats.detections(detection_time DESC);
CREATE INDEX idx_detections_severity ON threats.detections(severity);
CREATE INDEX idx_detections_status ON threats.detections(status);
CREATE INDEX idx_detections_source_ip ON threats.detections(source_ip);
CREATE INDEX idx_detections_threat_type ON threats.detections(threat_type);
CREATE INDEX idx_detections_indicators ON threats.detections USING GIN(indicators);
CREATE INDEX idx_detections_mitre ON threats.detections USING GIN(mitre_techniques);

-- Incidents indexes
CREATE INDEX idx_incidents_status ON incidents.incidents(status);
CREATE INDEX idx_incidents_severity ON incidents.incidents(severity);
CREATE INDEX idx_incidents_assigned ON incidents.incidents(assigned_to);
CREATE INDEX idx_incidents_created ON incidents.incidents(created_at DESC);
CREATE INDEX idx_incidents_number ON incidents.incidents(incident_number);

-- Timeline indexes
CREATE INDEX idx_timeline_incident ON incidents.incident_timeline(incident_id);
CREATE INDEX idx_timeline_time ON incidents.incident_timeline(event_time DESC);

-- Evidence indexes
CREATE INDEX idx_evidence_incident ON incidents.evidence(incident_id);
CREATE INDEX idx_evidence_type ON incidents.evidence(evidence_type);
CREATE INDEX idx_evidence_hashes ON incidents.evidence(hash_sha256, hash_md5, hash_sha1);

-- Playbook indexes
CREATE INDEX idx_playbooks_active ON playbooks.playbooks(is_active);
CREATE INDEX idx_executions_status ON playbooks.executions(execution_status);
CREATE INDEX idx_executions_incident ON playbooks.executions(incident_id);

-- System metrics indexes
CREATE INDEX idx_metrics_name_time ON threats.system_metrics(metric_name, recorded_at DESC);
CREATE INDEX idx_metrics_component ON threats.system_metrics(system_component);

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers to relevant tables
CREATE TRIGGER update_analysts_updated_at BEFORE UPDATE ON users.analysts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_iocs_updated_at BEFORE UPDATE ON intel.iocs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_detections_updated_at BEFORE UPDATE ON threats.detections FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_incidents_updated_at BEFORE UPDATE ON incidents.incidents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_playbooks_updated_at BEFORE UPDATE ON playbooks.playbooks FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to generate incident numbers
CREATE OR REPLACE FUNCTION generate_incident_number()
RETURNS TRIGGER AS $$
BEGIN
    NEW.incident_number = 'INC-' || TO_CHAR(NOW(), 'YYYY') || '-' || LPAD(nextval('incidents.incident_number_seq')::TEXT, 6, '0');
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create sequence for incident numbers
CREATE SEQUENCE incidents.incident_number_seq START 1;

-- Apply incident number trigger
CREATE TRIGGER generate_incident_number_trigger BEFORE INSERT ON incidents.incidents FOR EACH ROW EXECUTE FUNCTION generate_incident_number();

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default admin user (password: admin123 - change in production!)
INSERT INTO users.analysts (username, email, password_hash, full_name, role) VALUES
('admin', 'admin@threathunter-soar.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Gm.F5u', 'System Administrator', 'admin');

-- Insert sample MITRE techniques
INSERT INTO intel.mitre_techniques (technique_id, technique_name, tactic, description) VALUES
('T1059', 'Command and Scripting Interpreter', 'Execution', 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.'),
('T1055', 'Process Injection', 'Defense Evasion', 'Adversaries may inject code into processes in order to evade process-based defenses.'),
('T1071', 'Application Layer Protocol', 'Command and Control', 'Adversaries may communicate using application layer protocols.'),
('T1003', 'OS Credential Dumping', 'Credential Access', 'Adversaries may attempt to dump credentials to obtain account login information.'),
('T1486', 'Data Encrypted for Impact', 'Impact', 'Adversaries may encrypt data on target systems to interrupt availability.');

-- Insert default threat feeds
INSERT INTO intel.threat_feeds (feed_name, feed_url, feed_type, update_frequency) VALUES
('VirusTotal', 'https://www.virustotal.com/api/v3/', 'api', 3600),
('AbuseIPDB', 'https://api.abuseipdb.com/api/v2/', 'api', 7200),
('AlienVault OTX', 'https://otx.alienvault.com/api/v1/', 'api', 3600),
('Malware Domain List', 'http://www.malwaredomainlist.com/hostslist/hosts.txt', 'text', 86400);

-- Create views for common queries
CREATE VIEW threats.recent_detections AS
SELECT 
    d.*,
    a.username as analyst_username,
    a.full_name as analyst_name
FROM threats.detections d
LEFT JOIN users.analysts a ON d.analyst_id = a.id
WHERE d.detection_time >= NOW() - INTERVAL '24 hours'
ORDER BY d.detection_time DESC;

CREATE VIEW incidents.active_incidents AS
SELECT 
    i.*,
    assigned.username as assigned_username,
    assigned.full_name as assigned_name,
    creator.username as creator_username,
    creator.full_name as creator_name
FROM incidents.incidents i
LEFT JOIN users.analysts assigned ON i.assigned_to = assigned.id
LEFT JOIN users.analysts creator ON i.created_by = creator.id
WHERE i.status NOT IN ('closed')
ORDER BY i.priority ASC, i.created_at DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO soar_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA threats TO soar_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA incidents TO soar_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA intel TO soar_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA playbooks TO soar_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA users TO soar_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA incidents TO soar_user;

-- Database initialization complete
SELECT 'ThreatHunter-SOAR database initialized successfully!' as status;