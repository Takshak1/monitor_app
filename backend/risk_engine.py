"""
TrustPulse Risk Scoring Engine
===============================
Computes a trust score (0-100) from multi-dimensional identity signals.

Score interpretation:
  0-30   -> Low Risk      -> Silent pass (zero friction)
  31-60  -> Medium Risk   -> Biometric confirmation
  61-85  -> High Risk     -> Step-up auth (OTP + face liveness)
  86-100 -> Critical Risk -> Block + SOC alert

Privacy contract:
  - Raw behavioural data is processed on-device (TF Lite).
  - Only derived anomaly scores (floats) are transmitted to this engine.
  - No biometric templates, no raw sensor data, no PII stored post-session.
  - DPDP Act 2023 compliant. RBI Cybersecurity Framework aligned.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# --- Risk Level Definitions --------------------------------------------------

RISK_LEVELS: Dict[str, Dict[str, Any]] = {
    "low": {
        "range": (0, 30),
        "action": "silent_pass",
        "action_label": "Silent pass",
        "description": "Session continues with zero additional friction.",
        "ux_impact": "No interruption to user journey.",
    },
    "medium": {
        "range": (31, 60),
        "action": "biometric_prompt",
        "action_label": "Biometric prompt",
        "description": "Soft biometric confirmation — fingerprint or face ID.",
        "ux_impact": "One-tap confirmation, typically <3 seconds.",
    },
    "high": {
        "range": (61, 85),
        "action": "step_up_auth",
        "action_label": "Step-up authentication",
        "description": "OTP (6-digit, 90-second TTL) + face liveness check.",
        "ux_impact": "30-60 second verification flow.",
    },
    "critical": {
        "range": (86, 100),
        "action": "block_and_alert",
        "action_label": "Block + alert",
        "description": "Session terminated. SOC notified. Customer contacted.",
        "ux_impact": "Session blocked. Customer support pathway offered.",
    },
}

EVENT_BASE_SCORES: Dict[str, int] = {
    "login": 0,
    "transfer": 10,
    "beneficiary_add": 20,
    "account_recovery": 25,
    "admin_access": 30,
    "sim_activity": 35,
}

NETWORK_RISK_SCORES: Dict[str, int] = {
    "wifi": 0,
    "5g": 0,
    "4g": 0,
    "3g": 3,
    "unknown": 8,
    "vpn": 12,
    "tor": 28,
}

IP_REPUTATION_SCORES: Dict[str, int] = {
    "clean": 0,
    "suspicious": 15,
    "sanctioned": 25,
}


# --- Scorer ------------------------------------------------------------------

class TrustScorer:
    """
    Multi-signal trust scorer.

    Each dimension is scored independently, then summed and clamped to 0-100.
    SIM-swap detection carries an out-of-cap bonus applied after dimension caps,
    ensuring it always forces escalation regardless of other signal values.
    """

    MAX_SCORES = {
        "device":   50,
        "behavior": 25,
        "context":  28,
        "event":    35,
        "history":  24,
    }

    def score(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        device_score,   device_reasons   = self._score_device(signals)
        behavior_score, behavior_reasons = self._score_behavior(signals)
        context_score,  context_reasons  = self._score_context(signals)
        event_score,    event_reasons    = self._score_event(signals)
        history_score,  history_reasons  = self._score_history(signals)

        # SIM-swap detected: out-of-cap mandatory escalation (+15)
        sim_bonus = 0
        sim_reasons: List[Tuple[int, str]] = []
        if signals.get("sim_swap_detected", False):
            sim_bonus = 15
            sim_reasons.append((15, "+15: SIM swap activity confirmed — mandatory escalation"))

        raw_total = (device_score + behavior_score + context_score
                     + event_score + history_score + sim_bonus)
        final_score = min(100, max(0, round(raw_total)))

        level_key, level_data = self._get_level(final_score)

        all_reasons = (device_reasons + behavior_reasons + context_reasons
                       + event_reasons + history_reasons + sim_reasons)
        top_reasons = sorted(
            [r for r in all_reasons if r[0] > 0],
            key=lambda x: x[0],
            reverse=True,
        )
        explanation = [r[1] for r in top_reasons[:5]]
        if not explanation:
            explanation = ["No elevated risk factors detected."]

        return {
            "score": final_score,
            "level": level_key,
            "action": level_data["action"],
            "action_label": level_data["action_label"],
            "description": level_data["description"],
            "ux_impact": level_data["ux_impact"],
            "explanation": explanation,
            "breakdown": {
                "device":   round(device_score),
                "behavior": round(behavior_score),
                "context":  round(context_score),
                "event":    round(event_score),
                "history":  round(history_score),
                "sim_swap_bonus": sim_bonus,
            },
        }

    # -- Dimension Scorers ----------------------------------------------------

    def _score_device(self, s: Dict[str, Any]) -> Tuple[float, List[Tuple[int, str]]]:
        """Device trust signals (max: 50 points)."""
        score: float = 0.0
        reasons: List[Tuple[int, str]] = []

        if not s.get("is_known_device", True):
            score += 30
            reasons.append((30, "+30: Login from unrecognized device fingerprint"))

        health = float(s.get("device_health_score", 1.0))
        if health < 0.9:
            delta = round((1.0 - health) * 20)
            score += delta
            reasons.append((delta, f"+{delta}: Device health degraded ({health:.0%})"))

        if s.get("vpn_detected", False):
            score += 12
            reasons.append((12, "+12: VPN or anonymizing proxy detected"))

        net = s.get("network_type", "wifi")
        net_score = NETWORK_RISK_SCORES.get(net, 5)
        if net_score > 0:
            score += net_score
            reasons.append((net_score, f"+{net_score}: Elevated-risk network ({net.upper()})"))

        ip_rep = s.get("ip_reputation", "clean")
        ip_score = IP_REPUTATION_SCORES.get(ip_rep, 0)
        if ip_score > 0:
            score += ip_score
            reasons.append((ip_score,
                f"+{ip_score}: IP reputation — {ip_rep} "
                f"({'RBI/OFAC blacklist match' if ip_rep == 'sanctioned' else 'threat intelligence hit'})"))

        return min(self.MAX_SCORES["device"], score), reasons

    def _score_behavior(self, s: Dict[str, Any]) -> Tuple[float, List[Tuple[int, str]]]:
        """Behavioural biometric signals (max: 25 points).
        On-device derived anomaly scores only — raw biometrics never leave the device."""
        score: float = 0.0
        reasons: List[Tuple[int, str]] = []

        ks = float(s.get("keystroke_anomaly", 0.0))
        ta = float(s.get("touch_anomaly", 0.0))
        ga = float(s.get("gait_anomaly", 0.0))

        combined = max(ks, ta, ga)
        if combined > 0.05:
            delta = round(combined * 25)
            modality = "keystroke" if ks >= max(ta, ga) else ("touch" if ta >= ga else "gait")
            score += delta
            reasons.append((delta,
                f"+{delta}: Behavioural biometric anomaly ({modality}, "
                f"{combined:.0%} deviation from enrolled baseline)"))

        return min(self.MAX_SCORES["behavior"], score), reasons

    def _score_context(self, s: Dict[str, Any]) -> Tuple[float, List[Tuple[int, str]]]:
        """Contextual signals: location, time, network context (max: 28 points)."""
        score: float = 0.0
        reasons: List[Tuple[int, str]] = []

        loc = float(s.get("location_anomaly", 0.0))
        if loc > 0.2:
            delta = round(loc * 15)
            score += delta
            reasons.append((delta, f"+{delta}: Unusual access location ({loc:.0%} anomaly score)"))

        time_a = float(s.get("time_anomaly", 0.0))
        if time_a > 0.5:
            score += 8
            reasons.append((8, "+8: Access outside normal operating hours"))

        if not s.get("trusted_network_context", True):
            score += 5
            reasons.append((5, "+5: Unrecognized / public network context"))

        return min(self.MAX_SCORES["context"], score), reasons

    def _score_event(self, s: Dict[str, Any]) -> Tuple[float, List[Tuple[int, str]]]:
        """Event semantic signals (max: 35 points)."""
        score: float = 0.0
        reasons: List[Tuple[int, str]] = []

        event = s.get("event_type", "login")
        base = EVENT_BASE_SCORES.get(event, 0)
        if base > 0:
            score += base
            reasons.append((base, f"+{base}: High-sensitivity event ({event.replace('_', ' ')})"))

        if s.get("is_new_beneficiary", False):
            score += 10
            reasons.append((10, "+10: First-time beneficiary addition"))

        amount = s.get("transaction_amount")
        if amount and float(amount) > 100_000:
            magnitude = math.log10(float(amount) / 100_000)
            extra = min(8, round(magnitude * 4))
            if extra > 0:
                score += extra
                reasons.append((extra, f"+{extra}: High-value transaction (Rs {float(amount):,.0f})"))

        return min(self.MAX_SCORES["event"], score), reasons

    def _score_history(self, s: Dict[str, Any]) -> Tuple[float, List[Tuple[int, str]]]:
        """Session history signals (max: 24 points)."""
        score: float = 0.0
        reasons: List[Tuple[int, str]] = []

        fails = int(s.get("failed_attempts_last_hour", 0))
        if fails > 0:
            delta = min(24, fails * 8)
            score += delta
            reasons.append((delta,
                f"+{delta}: {fails} failed auth attempt{'s' if fails > 1 else ''} in last hour"))

        concurrent = int(s.get("concurrent_sessions", 1))
        if concurrent == 2:
            score += 3
            reasons.append((3, "+3: 2 concurrent sessions detected"))
        elif concurrent >= 3:
            score += 10
            reasons.append((10, f"+10: {concurrent} concurrent sessions — possible credential sharing"))

        return min(self.MAX_SCORES["history"], score), reasons

    # -- Level Resolution -----------------------------------------------------

    def _get_level(self, score: int) -> Tuple[str, Dict[str, Any]]:
        for level_key, data in RISK_LEVELS.items():
            lo, hi = data["range"]
            if lo <= score <= hi:
                return level_key, data
        return "critical", RISK_LEVELS["critical"]


# --- Audit Logger ------------------------------------------------------------

class AuditLogger:
    """
    In-memory audit log for session risk decisions.
    Production target: Hyperledger Besu for immutable, tamper-evident logs
    per RBI IT Examination Framework requirements.
    """

    def __init__(self, max_records: int = 10_000):
        self._log: Dict[str, Any] = {}
        self._ordered: list = []
        self._max = max_records
        self.total_requests = 0
        self.level_counts: Dict[str, int] = {
            "low": 0, "medium": 0, "high": 0, "critical": 0
        }
        self.total_latency_ms = 0.0

    def log(self, user_id: str, session_id: str, result: Dict[str, Any],
            latency_ms: float = 0.0) -> str:
        audit_ref = f"aud_{uuid.uuid4().hex[:16]}"
        record = {
            "audit_ref": audit_ref,
            "session_id": session_id,
            "user_id": user_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "trust_score": result["score"],
            "risk_level": result["level"],
            "action_taken": result["action"],
            "top_factors": result.get("explanation", []),
            "latency_ms": round(latency_ms, 2),
        }
        if len(self._log) >= self._max:
            oldest = self._ordered.pop(0)
            self._log.pop(oldest, None)
        self._log[session_id] = record
        self._ordered.append(session_id)
        self.total_requests += 1
        self.level_counts[result["level"]] = self.level_counts.get(result["level"], 0) + 1
        self.total_latency_ms += latency_ms
        return audit_ref

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._log.get(session_id)

    def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        keys = self._ordered[-limit:]
        return [self._log[k] for k in reversed(keys) if k in self._log]

    def stats(self) -> Dict[str, Any]:
        avg_lat = (self.total_latency_ms / self.total_requests
                   if self.total_requests else 0)
        return {
            "total_requests": self.total_requests,
            "distribution": dict(self.level_counts),
            "avg_latency_ms": round(avg_lat, 2),
        }
