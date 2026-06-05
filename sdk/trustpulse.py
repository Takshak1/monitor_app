"""
TrustPulse Python SDK
─────────────────────
Drop-in client for server-side integrations (Django, Flask, FastAPI middleware).

pip install trustpulse-sdk   # or: pip install httpx

Usage
─────
from trustpulse import TrustPulseClient, Event

client = TrustPulseClient(endpoint="http://localhost:8000/v1")

result = client.score(
    user_id="user_123",
    device_id="dev_abc",
    event=Event.TRANSFER,
    transaction_amount=85000,
    is_known_device=True,
)

if result.action == "silent_pass":
    pass   # proceed transparently
elif result.action == "biometric_prompt":
    trigger_biometric_flow()
elif result.action == "step_up_auth":
    trigger_otp_flow()
else:  # block_and_alert
    raise PermissionError("Session blocked by TrustPulse.")
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    import urllib.request, json as _json
    _HAS_HTTPX = False


# ─── Enumerations ─────────────────────────────────────────────────────────────

class Event(str, Enum):
    LOGIN             = "login"
    TRANSFER          = "transfer"
    BENEFICIARY_ADD   = "beneficiary_add"
    ACCOUNT_RECOVERY  = "account_recovery"
    ADMIN_ACCESS      = "admin_access"
    SIM_ACTIVITY      = "sim_activity"


class NetworkType(str, Enum):
    WIFI    = "wifi"
    G4      = "4g"
    G5      = "5g"
    G3      = "3g"
    VPN     = "vpn"
    TOR     = "tor"
    UNKNOWN = "unknown"


class Action(str, Enum):
    SILENT_PASS      = "silent_pass"
    BIOMETRIC_PROMPT = "biometric_prompt"
    STEP_UP_AUTH     = "step_up_auth"
    BLOCK_AND_ALERT  = "block_and_alert"


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ScoreRequest:
    user_id:                    str
    device_id:                  str
    event:                      Event           = Event.LOGIN
    session_id:                 Optional[str]   = None

    # Device trust
    is_known_device:            bool            = True
    device_health_score:        float           = 1.0
    vpn_detected:               bool            = False
    network_type:               NetworkType     = NetworkType.WIFI

    # Behavioural (on-device derived scores only)
    keystroke_anomaly:          float           = 0.0
    touch_anomaly:              float           = 0.0
    gait_anomaly:               float           = 0.0

    # Context
    location_anomaly:           float           = 0.0
    time_anomaly:               float           = 0.0

    # Event semantics
    transaction_amount:         Optional[float] = None
    is_new_beneficiary:         bool            = False
    failed_attempts_last_hour:  int             = 0

    def __post_init__(self):
        if self.session_id is None:
            self.session_id = f"sess_{uuid.uuid4().hex[:12]}"

    def to_dict(self) -> Dict:
        return {
            "session_id":                  self.session_id,
            "user_id":                     self.user_id,
            "device_id":                   self.device_id,
            "event_type":                  self.event.value,
            "is_known_device":             self.is_known_device,
            "device_health_score":         self.device_health_score,
            "vpn_detected":                self.vpn_detected,
            "network_type":                self.network_type.value,
            "keystroke_anomaly":           self.keystroke_anomaly,
            "touch_anomaly":               self.touch_anomaly,
            "gait_anomaly":                self.gait_anomaly,
            "location_anomaly":            self.location_anomaly,
            "time_anomaly":                self.time_anomaly,
            "transaction_amount":          self.transaction_amount,
            "is_new_beneficiary":          self.is_new_beneficiary,
            "failed_attempts_last_hour":   self.failed_attempts_last_hour,
        }


@dataclass
class ScoreResult:
    session_id:      str
    trust_score:     int
    risk_level:      str
    action:          Action
    latency_ms:      float
    explanation:     List[str]
    breakdown:       Dict[str, int]
    audit_ref:       str

    @classmethod
    def from_dict(cls, data: Dict) -> "ScoreResult":
        return cls(
            session_id=  data["session_id"],
            trust_score= data["trust_score"],
            risk_level=  data["risk_level"],
            action=      Action(data["required_action"]),
            latency_ms=  data.get("latency_ms", 0.0),
            explanation= data.get("explanation", []),
            breakdown=   data.get("breakdown", {}),
            audit_ref=   data.get("audit_ref", ""),
        )

    @property
    def is_blocked(self) -> bool:
        return self.action == Action.BLOCK_AND_ALERT

    @property
    def needs_verification(self) -> bool:
        return self.action in (
            Action.BIOMETRIC_PROMPT, Action.STEP_UP_AUTH
        )


# ─── Client ───────────────────────────────────────────────────────────────────

class TrustPulseClient:
    """
    Synchronous TrustPulse API client.

    Args:
        endpoint:  TrustPulse API base URL (e.g. 'https://api.trustpulse.io/v1')
        api_key:   API key for authenticated requests
        timeout:   Request timeout in seconds (default: 2.0)
        fail_open: If True, return 'silent_pass' on API errors instead of raising.
                   Recommended for production to avoid auth outages.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:8000/v1",
        api_key: Optional[str] = None,
        timeout: float = 2.0,
        fail_open: bool = True,
    ):
        self.endpoint  = endpoint.rstrip("/")
        self.api_key   = api_key
        self.timeout   = timeout
        self.fail_open = fail_open
        self._headers  = {
            "Content-Type": "application/json",
            **({"X-API-Key": api_key} if api_key else {}),
        }

    def score(
        self,
        user_id: str,
        device_id: str,
        event: Event = Event.LOGIN,
        **kwargs,
    ) -> ScoreResult:
        """
        Compute a trust score.

        Returns a ScoreResult. Check .action to decide the authentication path.
        On network errors, behaviour depends on fail_open setting.
        """
        req = ScoreRequest(
            user_id=user_id,
            device_id=device_id,
            event=event,
            **kwargs,
        )
        return self._post(req)

    def _post(self, req: ScoreRequest) -> ScoreResult:
        url     = f"{self.endpoint}/score"
        payload = req.to_dict()

        try:
            if _HAS_HTTPX:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, json=payload, headers=self._headers)
                    resp.raise_for_status()
                    return ScoreResult.from_dict(resp.json())
            else:
                import json
                data = json.dumps(payload).encode()
                request = urllib.request.Request(
                    url, data=data,
                    headers={**self._headers, "Content-Length": str(len(data))},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=self.timeout) as r:
                    return ScoreResult.from_dict(json.loads(r.read()))

        except Exception as exc:
            if self.fail_open:
                # Fail open: allow the session through rather than block all users
                return ScoreResult(
                    session_id=  req.session_id or "",
                    trust_score= 0,
                    risk_level=  "low",
                    action=      Action.SILENT_PASS,
                    latency_ms=  0.0,
                    explanation= [f"Fallback: API unreachable ({exc})"],
                    breakdown=   {},
                    audit_ref=   "fallback",
                )
            raise


class AsyncTrustPulseClient(TrustPulseClient):
    """Async version for use with FastAPI / asyncio."""

    async def score_async(
        self,
        user_id: str,
        device_id: str,
        event: Event = Event.LOGIN,
        **kwargs,
    ) -> ScoreResult:
        import httpx as _httpx
        req     = ScoreRequest(user_id=user_id, device_id=device_id, event=event, **kwargs)
        url     = f"{self.endpoint}/score"
        payload = req.to_dict()

        try:
            async with _httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers)
                resp.raise_for_status()
                return ScoreResult.from_dict(resp.json())
        except Exception as exc:
            if self.fail_open:
                return ScoreResult(
                    session_id=req.session_id or "", trust_score=0,
                    risk_level="low", action=Action.SILENT_PASS,
                    latency_ms=0.0, explanation=[f"Fallback: {exc}"],
                    breakdown={}, audit_ref="fallback",
                )
            raise


# ─── Django middleware example ────────────────────────────────────────────────

DJANGO_MIDDLEWARE_EXAMPLE = """
# settings.py
TRUSTPULSE_ENDPOINT = "https://api.trustpulse.io/v1"
TRUSTPULSE_API_KEY  = os.environ["TRUSTPULSE_KEY"]
TRUSTPULSE_FAIL_OPEN = True

# middleware.py
from trustpulse import TrustPulseClient, Event
from django.conf import settings

_tp = TrustPulseClient(
    endpoint=settings.TRUSTPULSE_ENDPOINT,
    api_key=settings.TRUSTPULSE_API_KEY,
    fail_open=settings.TRUSTPULSE_FAIL_OPEN,
)

class TrustPulseMiddleware:
    PROTECTED_PATHS = {
        '/api/transfer/':          Event.TRANSFER,
        '/api/beneficiary/add/':   Event.BENEFICIARY_ADD,
        '/api/account/recover/':   Event.ACCOUNT_RECOVERY,
        '/admin/':                 Event.ADMIN_ACCESS,
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        event = next(
            (e for p, e in self.PROTECTED_PATHS.items() if request.path.startswith(p)),
            None
        )
        if event and request.user.is_authenticated:
            result = _tp.score(
                user_id=str(request.user.id),
                device_id=request.META.get('HTTP_X_DEVICE_ID', 'unknown'),
                event=event,
            )
            request.trust_result = result
            if result.is_blocked:
                from django.http import JsonResponse
                return JsonResponse(
                    {"error": "Session blocked", "audit_ref": result.audit_ref},
                    status=403,
                )
        return self.get_response(request)
"""