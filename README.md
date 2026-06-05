# TrustPulse

TrustPulse is a privacy-first, risk-based identity trust framework for digital banking flows. It scores risk in real time and triggers verification only when needed.

## Project Layout

- `backend/main.py` - FastAPI app exposing the scoring API
- `backend/risk_engine.py` - Trust scoring rules and in-memory audit log
- `sdk/trustpulse.js` - Browser and React Navigation SDK
- `sdk/trustpulse.py` - Python client SDK
- `demo/index.html` - Interactive local demo

## Requirements

- Python 3.11

## Run the backend

From the repo root:

```bash
source .venv/Scripts/activate
python backend/main.py
```

Or run it as a module:

```bash
source .venv/Scripts/activate
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`

## Run the demo

In a second terminal:

```bash
python -m http.server 8080 -d demo
```

Then open:

- `http://127.0.0.1:8080/`

## API Endpoint

`POST /v1/score`

Example payload:

```json
{
  "session_id": "sess_demo_123",
  "user_id": "user_123",
  "device_id": "device_abc",
  "event_type": "transfer",
  "is_known_device": true,
  "device_health_score": 1.0,
  "vpn_detected": false,
  "network_type": "wifi",
  "keystroke_anomaly": 0.0,
  "touch_anomaly": 0.0,
  "gait_anomaly": 0.0,
  "location_anomaly": 0.0,
  "time_anomaly": 0.0,
  "transaction_amount": 45000,
  "is_new_beneficiary": false,
  "failed_attempts_last_hour": 0
}
```

## Notes

- The backend is compatible with Python 3.11.
- `scikit-learn` installs cleanly on Python 3.11 in this repo.
- The backend currently uses in-memory audit storage for the demo.
