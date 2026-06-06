# TrustPulse

Zero-Friction Adaptive Identity Trust Engine — BOB Hackathon 2026 · IIT Gandhinagar

Privacy-first · Risk-based · Continuous · Friction-optimized

---

## Project Layout

```
bob/
├── backend/
│   ├── main.py          # FastAPI app — all API endpoints
│   ├── risk_engine.py   # Trust scoring engine + audit logger
│   └── requirements.txt # Python dependencies
├── demo/
│   └── index.html       # Interactive web demo (served by backend at /)
├── sdk/
│   ├── trustpulse.js    # Browser / React Native SDK
│   └── trustpulse.py    # Python client SDK (Django / Flask middleware)
├── Procfile             # Render deployment
├── render.yaml          # Render service config
└── runtime.txt          # Python version pin (3.11)
```

---

## Requirements

- Python 3.11 or later
- pip

---

## Setup

### 1. Create a virtual environment

**Windows (PowerShell)**
```powershell
python -m venv .venv
```

**macOS / Linux**
```bash
python3.11 -m venv .venv
```

### 2. Activate the virtual environment

**Windows (PowerShell)**
```powershell
.venv\Scripts\activate
```

**macOS / Linux**
```bash
source .venv/bin/activate
```

You will see `(.venv)` appear at the start of your terminal prompt — that means it is active.

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

---

## Running the app

### Start the backend (also serves the demo)

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

> The `--reload` flag auto-restarts the server whenever you edit a file. Remove it for production.

### Open the demo

Once the server is running, open your browser at:

```
http://localhost:8000
```

The interactive demo loads automatically. No separate frontend server needed.

---

## API Reference

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/score` | Compute real-time trust score |
| `GET` | `/v1/audit` | List recent audit records |
| `GET` | `/v1/audit/{session_id}` | Get audit record for a session |
| `GET` | `/v1/stats` | Risk distribution + system stats |
| `GET` | `/health` | Service health check |
| `GET` | `/docs` | Interactive Swagger UI |

### POST /v1/score — example

```bash
curl -X POST http://localhost:8000/v1/score \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_123",
    "device_id": "device_abc",
    "is_known_device": true,
    "device_health_score": 1.0,
    "vpn_detected": false,
    "network_type": "wifi",
    "ip_reputation": "clean",
    "keystroke_anomaly": 0.0,
    "touch_anomaly": 0.0,
    "gait_anomaly": 0.0,
    "location_anomaly": 0.0,
    "time_anomaly": 0.0,
    "trusted_network_context": true,
    "event_type": "transfer",
    "transaction_amount": 45000,
    "is_new_beneficiary": false,
    "sim_swap_detected": false,
    "failed_attempts_last_hour": 0,
    "concurrent_sessions": 1
  }'
```

**Windows PowerShell** — use double quotes and escape inner quotes:
```powershell
curl -X POST http://localhost:8000/v1/score `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"user_123\",\"device_id\":\"d1\",\"event_type\":\"login\"}'
```

### Response

```json
{
  "session_id": "sess_abc123",
  "trust_score": 12,
  "risk_level": "low",
  "required_action": "silent_pass",
  "latency_ms": 0.45,
  "explanation": ["No elevated risk factors detected."],
  "breakdown": {
    "device": 0,
    "behavior": 0,
    "context": 0,
    "event": 0,
    "history": 0
  },
  "audit_ref": "aud_f3a9b1c2d4e5f6a7"
}
```

### Risk tiers

| Score | Level | Action |
|-------|-------|--------|
| 0 – 30 | Low | Silent pass — zero friction |
| 31 – 60 | Medium | Biometric prompt (fingerprint / face) |
| 61 – 85 | High | Step-up auth — OTP + face liveness |
| 86 – 100 | Critical | Block + SOC alert |

### Signal fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `is_known_device` | bool | `true` | Unknown device adds +30 |
| `device_health_score` | float 0–1 | `1.0` | Degraded health adds up to +20 |
| `vpn_detected` | bool | `false` | +12 |
| `network_type` | string | `"wifi"` | `wifi/5g/4g` = 0, `3g` = +3, `unknown` = +8, `vpn` = +12, `tor` = +28 |
| `ip_reputation` | string | `"clean"` | `clean` = 0, `suspicious` = +15, `sanctioned` = +25 |
| `keystroke_anomaly` | float 0–1 | `0.0` | On-device derived score — raw data never transmitted |
| `touch_anomaly` | float 0–1 | `0.0` | On-device derived score |
| `gait_anomaly` | float 0–1 | `0.0` | Mobile native SDK only |
| `location_anomaly` | float 0–1 | `0.0` | Adds up to +15 |
| `time_anomaly` | float 0–1 | `0.0` | >0.5 adds +8 |
| `trusted_network_context` | bool | `true` | Untrusted adds +5 |
| `event_type` | string | `"login"` | `login`=0, `transfer`=+10, `beneficiary_add`=+20, `account_recovery`=+25, `admin_access`=+30, `sim_activity`=+35 |
| `transaction_amount` | float | `null` | Adds up to +8 for amounts above ₹1,00,000 |
| `is_new_beneficiary` | bool | `false` | +10 |
| `sim_swap_detected` | bool | `false` | +15 mandatory escalation (out-of-cap) |
| `failed_attempts_last_hour` | int | `0` | Each attempt adds +8 (max +24) |
| `concurrent_sessions` | int | `1` | 2 sessions = +3, 3+ sessions = +10 |

---

## Stopping the server

Press `Ctrl + C` in the terminal where uvicorn is running.

---

## Deactivating the virtual environment

```bash
deactivate
```

---

## Deployment (Render)

The repo includes `Procfile`, `render.yaml`, and `runtime.txt` for one-click deployment to [Render](https://render.com).

Set the start command to:
```
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

After deploying, the demo will be live at your Render URL (e.g. `https://your-app.onrender.com`).
