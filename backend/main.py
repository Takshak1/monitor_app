"""
TrustPulse API — Zero-Friction Adaptive Identity Trust Engine
BOB Hackathon 2026 | IIT Gandhinagar

Run:
    pip install -r requirements.txt
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Docs:
    http://localhost:8000/docs
"""

import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

try:
    from backend.risk_engine import TrustScorer, AuditLogger
except ImportError:
    from risk_engine import TrustScorer, AuditLogger

app = FastAPI(
    title="TrustPulse Risk Engine",
    description="Privacy-first, risk-based Identity Trust framework for Bank of Baroda.",
    version="1.1.0",
    contact={"name": "TrustPulse Team", "email": "trustpulse@bobhackathon.in"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scorer = TrustScorer()
auditor = AuditLogger()


class SignalPayload(BaseModel):
    """Risk signal payload — all behavioral data processed on-device,
    only derived scores transmitted (DPDP Act 2023 compliant)."""

    session_id: str = Field(default_factory=lambda: "sess_" + uuid.uuid4().hex[:12])
    user_id: str

    # -- Device Trust ---------------------------------------------------------
    device_id: str
    is_known_device: bool = True
    device_health_score: float = Field(1.0, ge=0.0, le=1.0,
        description="0.0 = compromised/rooted, 1.0 = healthy and up-to-date")
    vpn_detected: bool = False
    network_type: str = Field("wifi",
        description="wifi | 4g | 5g | 3g | unknown | vpn | tor")
    ip_reputation: str = Field("clean",
        description="clean | suspicious | sanctioned — sourced from RBI/TRAI threat intel")

    # -- Behavioural Biometrics (on-device derived scores only) ---------------
    keystroke_anomaly: float = Field(0.0, ge=0.0, le=1.0,
        description="Deviation from user's baseline typing pattern (0=normal, 1=anomalous)")
    touch_anomaly: float = Field(0.0, ge=0.0, le=1.0,
        description="Touch pressure / gesture deviation from baseline")
    gait_anomaly: float = Field(0.0, ge=0.0, le=1.0,
        description="Accelerometer gait pattern deviation (mobile native SDK only)")

    # -- Context --------------------------------------------------------------
    location_anomaly: float = Field(0.0, ge=0.0, le=1.0,
        description="Distance/deviation from user's historical location centroid")
    time_anomaly: float = Field(0.0, ge=0.0, le=1.0,
        description="0=normal hours, 1=highly unusual access time")
    trusted_network_context: bool = Field(True,
        description="Whether the network matches a known trusted context (home/corporate)")

    # -- Event Semantics ------------------------------------------------------
    event_type: str = Field("login",
        description="login | transfer | beneficiary_add | account_recovery | admin_access | sim_activity")
    transaction_amount: Optional[float] = Field(None, gt=0,
        description="Transaction amount in INR (for transfer events)")
    is_new_beneficiary: bool = False
    sim_swap_detected: bool = Field(False,
        description="SIM swap confirmed via TRAI API — triggers mandatory escalation")

    # -- Session History ------------------------------------------------------
    failed_attempts_last_hour: int = Field(0, ge=0, le=20)
    concurrent_sessions: int = Field(1, ge=1, le=10,
        description="Number of active sessions for this user at this moment")

    @field_validator("network_type")
    @classmethod
    def validate_network(cls, v: str) -> str:
        valid = {"wifi", "4g", "5g", "3g", "unknown", "vpn", "tor"}
        if v not in valid:
            raise ValueError(f"network_type must be one of {valid}")
        return v

    @field_validator("event_type")
    @classmethod
    def validate_event(cls, v: str) -> str:
        valid = {"login", "transfer", "beneficiary_add", "account_recovery",
                 "admin_access", "sim_activity"}
        if v not in valid:
            raise ValueError(f"event_type must be one of {valid}")
        return v

    @field_validator("ip_reputation")
    @classmethod
    def validate_ip_reputation(cls, v: str) -> str:
        valid = {"clean", "suspicious", "sanctioned"}
        if v not in valid:
            raise ValueError(f"ip_reputation must be one of {valid}")
        return v


class ScoreResponse(BaseModel):
    session_id: str
    trust_score: int = Field(..., ge=0, le=100,
        description="0 = fully trusted, 100 = maximum risk")
    risk_level: str
    required_action: str
    latency_ms: float
    explanation: list[str]
    breakdown: dict
    audit_ref: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    uptime_ms: float


_start_time = time.time()


@app.post("/v1/score", response_model=ScoreResponse,
          summary="Compute real-time trust score",
          description="Accepts multi-dimensional risk signals and returns an adaptive "
                      "authentication decision in <80 ms.")
async def compute_trust_score(
    payload: SignalPayload,
    x_api_key: Optional[str] = Header(None, description="API key for production use"),  # noqa: ARG001
):
    t0 = time.perf_counter()
    result = scorer.score(payload.model_dump())
    latency = round((time.perf_counter() - t0) * 1000, 2)
    audit_ref = auditor.log(payload.user_id, payload.session_id, result, latency)

    return ScoreResponse(
        session_id=payload.session_id,
        trust_score=result["score"],
        risk_level=result["level"],
        required_action=result["action"],
        latency_ms=latency,
        explanation=result["explanation"],
        breakdown=result["breakdown"],
        audit_ref=audit_ref,
    )


@app.get("/v1/audit/{session_id}",
         summary="Retrieve audit record for a specific session")
async def get_audit(session_id: str):
    record = auditor.get(session_id)
    if not record:
        raise HTTPException(status_code=404, detail="Session not found in audit log")
    return record


@app.get("/v1/audit",
         summary="List recent audit records")
async def list_audit(limit: int = Query(20, ge=1, le=100)):
    return {"records": auditor.list_recent(limit), "total": auditor.total_requests}


@app.get("/v1/stats",
         summary="System statistics and risk distribution")
async def get_stats():
    stats = auditor.stats()
    stats["uptime_ms"] = round((time.time() - _start_time) * 1000, 0)
    stats["service"] = "TrustPulse Risk Engine v1.1.0"
    return stats


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        service="TrustPulse Risk Engine",
        version="1.1.0",
        uptime_ms=round((time.time() - _start_time) * 1000, 0),
    )


# --- Serve the demo frontend -------------------------------------------------
# Resolves demo/index.html relative to the project root (one level above backend/)
_DEMO_DIR = Path(__file__).parent.parent / "demo"

if _DEMO_DIR.exists():
    app.mount("/demo", StaticFiles(directory=str(_DEMO_DIR), html=True), name="demo")

    @app.get("/", include_in_schema=False)
    async def serve_demo():
        return FileResponse(str(_DEMO_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
