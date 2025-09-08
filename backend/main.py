"""
ThreatHunter-SOAR Backend API
Main FastAPI application with threat intelligence and incident response capabilities
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import asyncio
from datetime import datetime
from typing import List, Dict, Optional
import logging

from api.routes import threats, incidents, playbooks, intel, hunting
from core.threat_engine import ThreatDetectionEngine
from core.incident_manager import IncidentManager
from core.threat_intel import ThreatIntelligenceAggregator
from core.ml_detector import MLThreatDetector
from core.database import init_db, get_db_session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="ThreatHunter-SOAR API",
    description="Advanced SOC Platform for Threat Intelligence & Incident Response",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global instances
threat_engine = ThreatDetectionEngine()
incident_manager = IncidentManager()
threat_intel = ThreatIntelligenceAggregator()
ml_detector = MLThreatDetector()

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("Starting ThreatHunter-SOAR API...")
    
    # Initialize database
    await init_db()
    
    # Start background threat intelligence collection
    asyncio.create_task(threat_intel.start_collection())
    
    # Initialize ML models
    await ml_detector.load_models()
    
    logger.info("ThreatHunter-SOAR API started successfully!")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down ThreatHunter-SOAR API...")
    await threat_intel.stop_collection()

# Health check endpoint
@app.get("/health")
async def health_check():
    """API health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "threat_engine": threat_engine.is_healthy(),
            "incident_manager": incident_manager.is_healthy(),
            "threat_intel": threat_intel.is_healthy(),
            "ml_detector": ml_detector.is_healthy()
        }
    }

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate JWT token and return user info"""
    # TODO: Implement JWT validation
    return {"user_id": "analyst_001", "role": "soc_analyst"}

# Include API routes
app.include_router(threats.router, prefix="/api/v1/threats", tags=["Threats"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(playbooks.router, prefix="/api/v1/playbooks", tags=["Playbooks"])
app.include_router(intel.router, prefix="/api/v1/intel", tags=["Intelligence"])
app.include_router(hunting.router, prefix="/api/v1/hunting", tags=["Threat Hunting"])

# Real-time threat detection endpoint
@app.post("/api/v1/detect")
async def detect_threats(
    log_data: Dict,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Real-time threat detection from log data"""
    try:
        # Process through threat detection engine
        detection_result = await threat_engine.analyze_log(log_data)
        
        # If threat detected, trigger incident response
        if detection_result.get("threat_detected"):
            background_tasks.add_task(
                incident_manager.create_incident,
                detection_result,
                current_user["user_id"]
            )
        
        return detection_result
    
    except Exception as e:
        logger.error(f"Threat detection error: {str(e)}")
        raise HTTPException(status_code=500, detail="Threat detection failed")

# Bulk IOC enrichment endpoint
@app.post("/api/v1/enrich")
async def enrich_iocs(
    iocs: List[str],
    current_user: dict = Depends(get_current_user)
):
    """Enrich IOCs with threat intelligence"""
    try:
        enriched_data = await threat_intel.enrich_iocs(iocs)
        return {
            "enriched_iocs": enriched_data,
            "timestamp": datetime.utcnow().isoformat(),
            "analyst": current_user["user_id"]
        }
    
    except Exception as e:
        logger.error(f"IOC enrichment error: {str(e)}")
        raise HTTPException(status_code=500, detail="IOC enrichment failed")

# ML-based anomaly detection
@app.post("/api/v1/ml/detect")
async def ml_threat_detection(
    network_data: Dict,
    current_user: dict = Depends(get_current_user)
):
    """ML-powered threat detection"""
    try:
        prediction = await ml_detector.predict_threat(network_data)
        
        return {
            "threat_probability": prediction["probability"],
            "threat_type": prediction["threat_type"],
            "confidence": prediction["confidence"],
            "features_analyzed": prediction["features"],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"ML detection error: {str(e)}")
        raise HTTPException(status_code=500, detail="ML threat detection failed")

# WebSocket endpoint for real-time updates
@app.websocket("/ws/threats")
async def websocket_endpoint(websocket):
    """WebSocket for real-time threat updates"""
    await websocket.accept()
    try:
        while True:
            # Send real-time threat updates
            threat_update = await threat_engine.get_latest_threats()
            await websocket.send_json(threat_update)
            await asyncio.sleep(5)  # Update every 5 seconds
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        await websocket.close()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )