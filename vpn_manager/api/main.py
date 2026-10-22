"""HTTP API for the CyberOpsSuite VPN Manager.

Run from the project root::

    python -m vpn_manager.api.main

Environment variables
---------------------
* ``VPN_API_HOST`` — bind address (default: ``127.0.0.1``)
* ``VPN_API_PORT`` — bind port (default: ``8010``)

The API is intentionally bound to localhost by default: it has no
authentication and controls a local Xray process.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from vpn_manager.core.xray_manager import (
    DEFAULT_SOCKS_PORT,
    VPNError,
    XrayManager,
)


#: Default API version (kept in sync with the module version).
API_VERSION = "1.0.0"

#: Loopback addresses treated as safe by default.
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

#: Maximum length of an import payload.
MAX_IMPORT_BYTES = 256 * 1024


app = FastAPI(
    title="CyberOpsSuite VPN Manager API",
    description=(
        "Manage VLESS/VMess profiles and control a local Xray-core "
        "process. Read the profiles, import new ones, connect or "
        "disconnect, and query the current status."
    ),
    version=API_VERSION,
)

#: Shared manager instance. Created lazily on first use so that simply
#: importing this module does not touch the user's config directory.
_manager: XrayManager | None = None


def get_manager() -> XrayManager:
    """Return the shared :class:`XrayManager`, creating it on first use."""
    global _manager
    if _manager is None:
        _manager = XrayManager()
    return _manager


# ------------------------------------------------------------- models

class ImportRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        description="A VLESS/VMess link, base64 blob, or subscription URL.",
    )


class ProfileModel(BaseModel):
    id: str
    name: str
    protocol: str
    address: str
    port: int
    params: dict[str, Any] = Field(default_factory=dict)


class ConnectRequest(BaseModel):
    profile_id: str = Field(..., min_length=1)
    local_port: int = Field(
        default=DEFAULT_SOCKS_PORT, ge=1, le=65535,
        description="Local SOCKS5 port; HTTP uses port + 1.",
    )


class StatusModel(BaseModel):
    connected: bool
    detail: str = ""


# ------------------------------------------------------------- helpers

def _profile_to_model(profile: dict) -> ProfileModel:
    """Strip the raw ``uri`` field before exposing a profile."""
    return ProfileModel(
        id=str(profile.get("id") or ""),
        name=str(profile.get("name") or ""),
        protocol=str(profile.get("protocol") or ""),
        address=str(profile.get("address") or ""),
        port=int(profile.get("port") or 0),
        params=dict(profile.get("params") or {}),
    )


# ------------------------------------------------------------- endpoints

@app.get("/health", tags=["Status"])
def health() -> dict[str, str]:
    """Return API status and version."""
    return {
        "status": "ok",
        "service": "vpn-manager",
        "version": API_VERSION,
    }


@app.get("/profiles", response_model=list[ProfileModel], tags=["Profiles"])
def list_profiles() -> list[ProfileModel]:
    """Return every saved profile (without the raw URI)."""
    manager = get_manager()
    return [_profile_to_model(p) for p in manager.profiles]


@app.post(
    "/profiles/import",
    response_model=list[ProfileModel],
    tags=["Profiles"],
)
def import_profiles(req: ImportRequest) -> list[ProfileModel]:
    """Import one or more profiles from a link, blob, or subscription URL."""
    if len(req.text.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Import payload exceeds {MAX_IMPORT_BYTES} bytes.",
        )
    manager = get_manager()
    try:
        added = manager.import_text(req.text)
    except VPNError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [_profile_to_model(p) for p in added]


@app.delete("/profiles/{profile_id}", tags=["Profiles"])
def remove_profile(profile_id: str) -> dict[str, str]:
    """Remove a saved profile by id."""
    manager = get_manager()
    match = next(
        (p for p in manager.profiles if p.get("id") == profile_id), None
    )
    if match is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    manager.remove(profile_id)
    return {"status": "removed", "id": profile_id}


@app.get("/status", response_model=StatusModel, tags=["Connection"])
def status() -> StatusModel:
    """Return whether Xray is currently running."""
    manager = get_manager()
    connected = manager.connected()
    detail = ""
    if connected:
        ok, msg = manager.test_connection(timeout=6.0)
        detail = msg if ok else f"unverified — {msg}"
    return StatusModel(connected=connected, detail=detail)


@app.post("/connect", response_model=StatusModel, tags=["Connection"])
def connect(req: ConnectRequest) -> StatusModel:
    """Start Xray with the given profile."""
    manager = get_manager()
    profile = next(
        (p for p in manager.profiles if p.get("id") == req.profile_id), None
    )
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    try:
        manager.connect(profile, local_port=req.local_port)
    except VPNError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    ok, msg = manager.test_connection(timeout=8.0)
    return StatusModel(connected=ok, detail=msg)


@app.post("/disconnect", response_model=StatusModel, tags=["Connection"])
def disconnect() -> StatusModel:
    """Stop the running Xray process."""
    manager = get_manager()
    try:
        manager.disconnect()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return StatusModel(connected=False, detail="Disconnected.")


# ------------------------------------------------------------- runner

def main() -> None:
    """Run the API with uvicorn, bound to localhost by default."""
    host = os.environ.get("VPN_API_HOST", "127.0.0.1")
    port = int(os.environ.get("VPN_API_PORT", "8010"))
    if host not in LOOPBACK_HOSTS:
        print(
            f"WARNING: binding to {host} exposes this unauthenticated API "
            f"to the network.",
            file=sys.stderr,
        )
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()