"""
FastAPI Server for AegisGraph Incident Commander
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import os
from backend.agent import AegisAgent
from backend.seed_graph import seed_graph

app = FastAPI(title="AegisGraph SecOps API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = AegisAgent()

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

class InvestigateRequest(BaseModel):
    pod_id: Optional[str] = "pod-ingress-7b4d"

@app.get("/")
def root():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "ok", "service": "AegisGraph SecOps Incident Commander"}

@app.get("/api/graph")
def get_graph():
    """Retrieve full infrastructure graph with nodes and relationships."""
    try:
        return agent.get_full_graph_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/reset-graph")
def reset_graph():
    """Reset graph to the initial breach state."""
    try:
        seed_graph()
        return {"status": "reset_success", "graph": agent.get_full_graph_data()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/investigate")
def run_investigation(req: InvestigateRequest):
    """Trigger autonomous agent multi-hop analysis and remediation."""
    try:
        result = agent.run_autonomous_investigation(alert_node=req.pod_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
