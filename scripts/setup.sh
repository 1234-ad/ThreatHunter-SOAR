#!/bin/bash

# ThreatHunter-SOAR Setup Script
# Automated setup and deployment script for the SOC platform

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="ThreatHunter-SOAR"
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    ThreatHunter-SOAR                         ║"
    echo "║              Advanced SOC Platform Setup                    ║"
    echo "║                                                              ║"
    echo "║  🛡️  Real-time Threat Intelligence                          ║"
    echo "║  🤖  ML-powered Threat Detection                            ║"
    echo "║  ⚡  Automated Incident Response                            ║"
    echo "║  📊  Advanced Analytics Dashboard                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Git is installed
    if ! command -v git &> /dev/null; then
        log_error "Git is not installed. Please install Git first."
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    log_info "All prerequisites met ✓"
}

setup_environment() {
    log_info "Setting up environment configuration..."
    
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f "$ENV_EXAMPLE" ]; then
            cp "$ENV_EXAMPLE" "$ENV_FILE"
            log_info "Created .env file from template"
            log_warn "Please edit .env file with your actual configuration values"
        else
            log_error ".env.example file not found"
            exit 1
        fi
    else
        log_info ".env file already exists"
    fi
}

generate_secrets() {
    log_info "Generating secure secrets..."
    
    # Generate random secrets
    SECRET_KEY=$(openssl rand -hex 32)
    JWT_SECRET=$(openssl rand -hex 32)
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    # Update .env file with generated secrets
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" "$ENV_FILE"
        sed -i '' "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" "$ENV_FILE"
        sed -i '' "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" "$ENV_FILE"
        sed -i '' "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" "$ENV_FILE"
    else
        # Linux
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" "$ENV_FILE"
        sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" "$ENV_FILE"
        sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" "$ENV_FILE"
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" "$ENV_FILE"
    fi
    
    log_info "Secrets generated and updated in .env file"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    # Create data directories
    mkdir -p data/postgres
    mkdir -p data/redis
    mkdir -p data/elasticsearch
    mkdir -p data/grafana
    mkdir -p data/prometheus
    mkdir -p logs
    mkdir -p backups
    mkdir -p models
    mkdir -p intel_data
    mkdir -p evidence
    
    # Set permissions
    chmod 755 data logs backups models intel_data evidence
    
    log_info "Directories created successfully"
}

setup_ssl() {
    log_info "Setting up SSL certificates..."
    
    mkdir -p nginx/ssl
    
    if [ ! -f "nginx/ssl/cert.pem" ] || [ ! -f "nginx/ssl/key.pem" ]; then
        log_info "Generating self-signed SSL certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        log_warn "Self-signed certificate generated. Replace with proper SSL certificate in production."
    else
        log_info "SSL certificates already exist"
    fi
}

build_images() {
    log_info "Building Docker images..."
    
    # Build images
    docker-compose build --no-cache
    
    log_info "Docker images built successfully"
}

start_services() {
    log_info "Starting services..."
    
    # Start core services first
    docker-compose up -d postgres redis
    
    # Wait for database to be ready
    log_info "Waiting for database to be ready..."
    sleep 30
    
    # Start remaining services
    docker-compose up -d
    
    log_info "All services started successfully"
}

wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for backend API
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:8000/health &> /dev/null; then
            log_info "Backend API is ready ✓"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "Backend API failed to start"
            exit 1
        fi
        
        log_info "Waiting for backend API... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
    
    # Wait for frontend
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:3000 &> /dev/null; then
            log_info "Frontend is ready ✓"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "Frontend failed to start"
            exit 1
        fi
        
        log_info "Waiting for frontend... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
}

setup_initial_data() {
    log_info "Setting up initial data..."
    
    # Create initial admin user and sample data
    docker-compose exec backend python -c "
import asyncio
from backend.core.database import init_sample_data
asyncio.run(init_sample_data())
"
    
    log_info "Initial data setup completed"
}

run_health_checks() {
    log_info "Running health checks..."
    
    # Check all services
    services=("postgres" "redis" "backend" "frontend" "elasticsearch" "grafana")
    
    for service in "${services[@]}"; do
        if docker-compose ps "$service" | grep -q "Up"; then
            log_info "$service: ✓ Running"
        else
            log_warn "$service: ⚠ Not running"
        fi
    done
}

print_access_info() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 SETUP COMPLETE! 🎉                    ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo "║  📊 ThreatHunter Dashboard: http://localhost:3000           ║"
    echo "║  🔧 API Documentation:     http://localhost:8000/docs       ║"
    echo "║  📈 Grafana Monitoring:    http://localhost:3001            ║"
    echo "║  🔍 Kibana Logs:           http://localhost:5601            ║"
    echo "║  ⚡ Prometheus Metrics:    http://localhost:9090            ║"
    echo "║                                                              ║"
    echo "║  Default Login:                                              ║"
    echo "║  Username: admin                                             ║"
    echo "║  Password: admin123                                          ║"
    echo "║                                                              ║"
    echo "║  🔒 IMPORTANT: Change default passwords in production!      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_logs() {
    log_info "Showing service logs..."
    docker-compose logs -f --tail=50
}

cleanup() {
    log_info "Cleaning up..."
    docker-compose down -v
    docker system prune -f
    log_info "Cleanup completed"
}

backup_data() {
    log_info "Creating backup..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    backup_dir="backups/backup_$timestamp"
    
    mkdir -p "$backup_dir"
    
    # Backup database
    docker-compose exec postgres pg_dump -U soar_user threathunter_soar > "$backup_dir/database.sql"
    
    # Backup configuration
    cp .env "$backup_dir/"
    
    # Create archive
    tar -czf "$backup_dir.tar.gz" "$backup_dir"
    rm -rf "$backup_dir"
    
    log_info "Backup created: $backup_dir.tar.gz"
}

show_help() {
    echo "ThreatHunter-SOAR Setup Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup     - Full setup and deployment (default)"
    echo "  start     - Start all services"
    echo "  stop      - Stop all services"
    echo "  restart   - Restart all services"
    echo "  logs      - Show service logs"
    echo "  status    - Show service status"
    echo "  backup    - Create data backup"
    echo "  cleanup   - Clean up containers and volumes"
    echo "  help      - Show this help message"
    echo ""
}

# Main execution
main() {
    print_banner
    
    case "${1:-setup}" in
        "setup")
            check_prerequisites
            setup_environment
            generate_secrets
            create_directories
            setup_ssl
            build_images
            start_services
            wait_for_services
            setup_initial_data
            run_health_checks
            print_access_info
            ;;
        "start")
            log_info "Starting ThreatHunter-SOAR..."
            docker-compose up -d
            wait_for_services
            run_health_checks
            print_access_info
            ;;
        "stop")
            log_info "Stopping ThreatHunter-SOAR..."
            docker-compose down
            log_info "Services stopped"
            ;;
        "restart")
            log_info "Restarting ThreatHunter-SOAR..."
            docker-compose restart
            wait_for_services
            log_info "Services restarted"
            ;;
        "logs")
            show_logs
            ;;
        "status")
            docker-compose ps
            run_health_checks
            ;;
        "backup")
            backup_data
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"