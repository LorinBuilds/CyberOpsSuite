"""Local-only API. Start with: uvicorn threat_guard.api.main:app --host 127.0.0.1"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from threat_guard.engine.scanner import ThreatScanner
from threat_guard.engine.audit import local_security_audit
from threat_guard.engine.integrity import create_baseline, compare_baseline
from threat_guard.engine.rootkit import rootkit_indicators
from threat_guard.engine.hardening import server_hardening_checks
from threat_guard.engine.log_analyzer import analyze_log_file

app = FastAPI(title="ThreatGuard API", version="0.2.0")


class ScanRequest(BaseModel):
    path: str
    hash_db: str | None = None
    yara: str | None = None
    signatures: str | None = None
    use_clamav: bool = True


class BaselineCreate(BaseModel):
    target: str
    output: str


class BaselineCompare(BaseModel):
    target: str
    baseline: str


class LogAnalyze(BaseModel):
    path: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "mode": "read-only"}


@app.get("/audit")
def audit() -> dict:
    return {"checks": local_security_audit()}


@app.get("/rootkit")
def rootkit() -> dict:
    return {"checks": rootkit_indicators()}


@app.get("/hardening")
def hardening() -> dict:
    return {"checks": server_hardening_checks()}


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    try:
        scanner = ThreatScanner(
            hash_db=req.hash_db and __import__("pathlib").Path(req.hash_db),
            yara_rules=req.yara and __import__("pathlib").Path(req.yara),
            use_clamav=req.use_clamav,
            signature_db=req.signatures and __import__("pathlib").Path(req.signatures),
        )
        return scanner.scan(req.path).to_dict()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/baseline/create")
def baseline_create(req: BaselineCreate) -> dict:
    try:
        return create_baseline(req.target, req.output)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/baseline/compare")
def baseline_compare(req: BaselineCompare) -> dict:
    try:
        return compare_baseline(req.target, req.baseline)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/log/analyze")
def log_analyze(req: LogAnalyze) -> dict:
    try:
        return analyze_log_file(req.path)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc