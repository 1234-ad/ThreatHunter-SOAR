# ThreatHunter-SOAR Deployment Guide

Complete deployment guide for the ThreatHunter-SOAR platform in production environments.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Security Hardening](#security-hardening)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)
- [Scaling](#scaling)

## 🔧 Prerequisites

### System Requirements

**Minimum Requirements:**
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 100GB SSD
- **Network**: 1Gbps

**Recommended for Production:**
- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Storage**: 500GB+ SSD
- **Network**: 10Gbps

### Software Dependencies

- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Git**: 2.30+
- **OpenSSL**: 1.1.1+
- **curl**: 7.68+

### Network Requirements

**Inbound Ports:**
- `80/tcp` - HTTP (redirects to HTTPS)
- `443/tcp` - HTTPS
- `3000/tcp` - Frontend (development)
- `8000/tcp` - API (development)

**Outbound Ports:**
- `80/tcp, 443/tcp` - Threat intelligence feeds
- `53/tcp, 53/udp` - DNS resolution
- `25/tcp, 587/tcp` - Email notifications

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/1234-ad/ThreatHunter-SOAR.git
cd ThreatHunter-SOAR
```

### 2. Run Setup Script

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 3. Access the Platform

- **Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Grafana**: http://localhost:3001

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

⚠️ **Change default passwords immediately!**

## 🏭 Production Deployment

### 1. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### 2. SSL Certificate Setup

**Option A: Let's Encrypt (Recommended)**

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem
```

**Option B: Self-Signed (Development)**

```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/ssl/key.pem \
    -out nginx/ssl/cert.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

### 3. Production Configuration

**Update `.env` file:**

```bash
# Security
SECRET_KEY=your-super-secure-secret-key-32-chars-minimum
JWT_SECRET_KEY=your-jwt-secret-key-32-chars-minimum
DEBUG=false
ENVIRONMENT=production

# Database
DB_PASSWORD=your-secure-database-password

# Redis
REDIS_PASSWORD=your-secure-redis-password

# Domain
CORS_ORIGINS=https://your-domain.com

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key

# Email
SMTP_HOST=your-smtp-server.com
SMTP_USER=your-email@domain.com
SMTP_PASSWORD=your-email-password

# Notifications
SLACK_WEBHOOK_URL=your-slack-webhook-url
```

### 4. Deploy Services

```bash
# Build and start services
docker-compose -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose ps
```

### 5. Initialize Database

```bash
# Run database migrations
docker-compose exec backend alembic upgrade head

# Create admin user
docker-compose exec backend python scripts/create_admin.py
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Application secret key | - | ✅ |
| `DATABASE_URL` | PostgreSQL connection string | - | ✅ |
| `REDIS_URL` | Redis connection string | - | ✅ |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | - | ❌ |
| `SMTP_HOST` | SMTP server hostname | - | ❌ |
| `DEBUG` | Enable debug mode | `false` | ❌ |

### Threat Intelligence Configuration

**VirusTotal Setup:**
1. Register at https://www.virustotal.com/
2. Get API key from account settings
3. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key`

**AbuseIPDB Setup:**
1. Register at https://www.abuseipdb.com/
2. Generate API key
3. Add to `.env`: `ABUSEIPDB_API_KEY=your_key`

### Email Notifications

**Gmail Setup:**
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password  # Use App Password, not regular password
SMTP_TLS=true
```

**Office 365 Setup:**
```bash
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=your-email@company.com
SMTP_PASSWORD=your-password
SMTP_TLS=true
```

### Slack Integration

1. Create Slack App at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Create webhook for your channel
4. Add to `.env`: `SLACK_WEBHOOK_URL=your_webhook_url`

## 🔒 Security Hardening

### 1. System Security

**Update System:**
```bash
sudo apt update && sudo apt upgrade -y
```

**Configure Firewall:**
```bash
# Install UFW
sudo apt install ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow ssh

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

### 2. Docker Security

**Secure Docker Daemon:**
```bash
# Create docker group
sudo groupadd docker
sudo usermod -aG docker $USER

# Secure docker socket
sudo chmod 660 /var/run/docker.sock
```

**Container Security:**
```bash
# Run containers as non-root
USER 1000:1000

# Read-only root filesystem
--read-only

# No new privileges
--security-opt=no-new-privileges
```

### 3. Application Security

**Strong Passwords:**
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Use password manager

**API Security:**
- Enable rate limiting
- Use HTTPS only
- Implement proper authentication
- Regular security audits

### 4. Database Security

**PostgreSQL Hardening:**
```sql
-- Change default passwords
ALTER USER postgres PASSWORD 'strong_password';

-- Restrict connections
-- Edit postgresql.conf:
listen_addresses = 'localhost'

-- Edit pg_hba.conf:
local   all             all                                     md5
host    all             all             127.0.0.1/32            md5
```

### 5. Network Security

**Nginx Security Headers:**
```nginx
# Security headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header Content-Security-Policy "default-src 'self'";
```

## 📊 Monitoring & Maintenance

### Health Checks

**System Health:**
```bash
# Check service status
docker-compose ps

# Check logs
docker-compose logs -f

# Check resource usage
docker stats
```

**Application Health:**
```bash
# API health check
curl -f http://localhost:8000/health

# Database connectivity
docker-compose exec postgres pg_isready
```

### Log Management

**Log Rotation:**
```bash
# Configure logrotate
sudo nano /etc/logrotate.d/threathunter-soar

/app/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 soar soar
}
```

**Centralized Logging:**
- Elasticsearch for log storage
- Kibana for log visualization
- Filebeat for log shipping

### Backup Strategy

**Database Backup:**
```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec postgres pg_dump -U soar_user threathunter_soar > backup_$DATE.sql
gzip backup_$DATE.sql

# Keep last 30 days
find . -name "backup_*.sql.gz" -mtime +30 -delete
```

**Configuration Backup:**
```bash
# Backup configuration
tar -czf config_backup_$(date +%Y%m%d).tar.gz .env docker-compose.yml nginx/
```

### Updates

**Application Updates:**
```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose build --no-cache

# Update services
docker-compose up -d

# Run migrations
docker-compose exec backend alembic upgrade head
```

**Security Updates:**
```bash
# Update base images
docker-compose pull

# Rebuild with latest base images
docker-compose build --pull
```

## 🔧 Troubleshooting

### Common Issues

**1. Services Won't Start**
```bash
# Check logs
docker-compose logs service_name

# Check disk space
df -h

# Check memory usage
free -h
```

**2. Database Connection Issues**
```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready

# Check connection string
echo $DATABASE_URL

# Test connection
docker-compose exec backend python -c "from core.database import test_connection; test_connection()"
```

**3. High Memory Usage**
```bash
# Check container memory usage
docker stats

# Restart services
docker-compose restart

# Scale down if needed
docker-compose up -d --scale ml-trainer=0
```

**4. SSL Certificate Issues**
```bash
# Check certificate validity
openssl x509 -in nginx/ssl/cert.pem -text -noout

# Renew Let's Encrypt certificate
sudo certbot renew
```

### Performance Issues

**Database Performance:**
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Analyze table statistics
ANALYZE;

-- Reindex if needed
REINDEX DATABASE threathunter_soar;
```

**Application Performance:**
```bash
# Enable profiling
DEBUG=true
ENABLE_PROFILING=true

# Monitor API response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/health
```

### Log Analysis

**Error Patterns:**
```bash
# Find errors in logs
docker-compose logs | grep -i error

# Count error types
docker-compose logs | grep -i error | sort | uniq -c

# Monitor real-time errors
docker-compose logs -f | grep -i error
```

## 📈 Scaling

### Horizontal Scaling

**Load Balancer Setup:**
```nginx
upstream backend {
    server backend1:8000;
    server backend2:8000;
    server backend3:8000;
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

**Database Scaling:**
- Read replicas for analytics
- Connection pooling
- Query optimization

### Vertical Scaling

**Resource Limits:**
```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

### Auto-Scaling

**Docker Swarm:**
```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml threathunter

# Scale services
docker service scale threathunter_backend=3
```

**Kubernetes:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threathunter-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threathunter-backend
  template:
    spec:
      containers:
      - name: backend
        image: threathunter/backend:latest
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

## 📞 Support

### Getting Help

- **Documentation**: Check this guide and README.md
- **Issues**: Create GitHub issue with logs and configuration
- **Community**: Join our Discord/Slack community
- **Professional Support**: Contact enterprise support team

### Reporting Issues

When reporting issues, include:
1. System information (OS, Docker version)
2. Configuration (sanitized .env file)
3. Error logs
4. Steps to reproduce
5. Expected vs actual behavior

### Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request
5. Follow code review process

---

## 📝 Changelog

### v1.0.0 (2024-01-15)
- Initial release
- Core threat detection engine
- Incident response automation
- ML-powered classification
- Real-time dashboard

---

**Need help?** Contact us at support@threathunter-soar.com