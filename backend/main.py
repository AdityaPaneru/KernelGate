from datetime import datetime, timezone
from typing import List, Optional

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(title="KernelGate Mock UEM Control Plane")

received_incidents = []


class IncidentUpload(BaseModel):
    device_id: str
    run_id: str
    incident_id: str
    pid: int
    process_name: str
    process_path: str
    chain_summary: str
    risk_score: int
    verdict: str
    first_seen: str
    last_seen: str
    matched_rule_ids: List[str]


@app.get("/")
def root():
    return {
        "service": "kernelgate-mock-uem-control-plane",
        "status": "running",
        "incidents_received": len(received_incidents),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/incident")
def receive_incident(incident: IncidentUpload):
    record = incident.model_dump()
    record["received_at"] = datetime.now(timezone.utc).isoformat()
    received_incidents.append(record)

    return {
        "received": True,
        "incident_id": incident.incident_id,
        "verdict": incident.verdict,
        "risk_score": incident.risk_score,
        "total_received": len(received_incidents),
    }


@app.get("/incidents")
def list_incidents():
    return {
        "count": len(received_incidents),
        "incidents": received_incidents,
    }


@app.post("/reset")
def reset_incidents():
    received_incidents.clear()
    return {
        "reset": True,
        "incidents_received": len(received_incidents),
    }


@app.get("/fleet/summary")
def fleet_summary():
    high_risk_count = sum(
        1 for incident in received_incidents
        if incident["verdict"] in {"HIGH", "CRITICAL"}
    )

    return {
        "total_incidents": len(received_incidents),
        "high_risk_incidents": high_risk_count,
        "status": "HIGH_RISK" if high_risk_count > 0 else "HEALTHY",
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
