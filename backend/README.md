# TruthSeeker Backend

Backend foundation for the TruthSeeker project using FastAPI.

## Setup

1. Create and activate a Python virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the server:

```bash
uvicorn app.main:app --reload
```

## Health Check

Visit:

```text
http://127.0.0.1:8000/health
```

Expected response:

```json
{
  "status": "TruthSeeker backend running"
}
```
