"""Tool runners: APKLeaks, JADX, MobSF.

Each tool returns a ToolResult. New tools only need to implement the same signature
and be added to run_all(). Failures are isolated — the pipeline continues.
"""

import asyncio
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx



@dataclass
class ToolResult:
    name: str
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0


async def run_all(apk: Path, workdir: Path, mobsf_url: str, mobsf_key: str) -> list[ToolResult]:
    jadx_dir = workdir / "jadx"
    jadx_dir.mkdir()

    tasks: list[asyncio.Task] = [
        asyncio.create_task(_apkleaks(apk, workdir), name="apkleaks"),
        asyncio.create_task(_jadx(apk, jadx_dir), name="jadx"),
    ]
    if mobsf_url and mobsf_key:
        tasks.append(asyncio.create_task(_mobsf(apk, mobsf_url, mobsf_key), name="mobsf"))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [
        r if isinstance(r, ToolResult) else ToolResult(name="unknown", ok=False, error=str(r))
        for r in results
    ]


# ── individual runners ────────────────────────────────────────────────────────

def _apkleaks_bin() -> str:
    # Prefer the binary in the same venv as the running Python.
    # Falls back to PATH if not found (e.g. system install).
    candidate = Path(sys.executable).parent / "apkleaks"
    return str(candidate) if candidate.exists() else "apkleaks"


async def _apkleaks(apk: Path, workdir: Path) -> ToolResult:
    out = workdir / "apkleaks.json"
    t0 = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            _apkleaks_bin(), "-f", str(apk), "-o", str(out),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(name="apkleaks", ok=False, error="timed out after 600s",
                              elapsed=time.monotonic() - t0)

        findings: dict = {}
        if out.exists():
            try:
                findings = json.loads(out.read_text())
            except json.JSONDecodeError:
                findings = {"raw": out.read_text()}
        category_count = len(findings) if isinstance(findings, dict) else 0
        finding_count = sum(len(v) for v in findings.values() if isinstance(v, list))
        return ToolResult(
            name="apkleaks", ok=bool(findings), elapsed=time.monotonic() - t0,
            data={"findings": findings, "stdout": stdout.decode(errors="replace"),
                  "categories": category_count, "findings_total": finding_count},
        )
    except Exception as exc:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return ToolResult(name="apkleaks", ok=False, error=str(exc), elapsed=time.monotonic() - t0)


async def _jadx(apk: Path, output_dir: Path) -> ToolResult:
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "jadx", "-d", str(output_dir), "--show-bad-code", str(apk),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        java_count = sum(1 for _ in output_dir.rglob("*.java"))
        return ToolResult(
            name="jadx", ok=java_count > 0, elapsed=time.monotonic() - t0,
            data={"output_dir": str(output_dir), "java_files": java_count,
                  "stderr_tail": stderr.decode(errors="replace")[-1000:]},
        )
    except Exception as exc:
        return ToolResult(name="jadx", ok=False, error=str(exc), elapsed=time.monotonic() - t0)


async def _mobsf(apk: Path, url: str, key: str) -> ToolResult:
    url = url.rstrip("/")
    headers = {"Authorization": key}
    t0 = time.monotonic()
    stages: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            upload_resp = await client.post(
                f"{url}/api/v1/upload",
                headers=headers,
                files={"file": (apk.name, apk.open("rb"), "application/vnd.android.package-archive")},
            )
            upload_resp.raise_for_status()
            upload = upload_resp.json()
            stages.append(f"upload {time.monotonic()-t0:.0f}s")

            file_hash = upload["hash"]
            t1 = time.monotonic()
            scan_resp = await client.post(
                f"{url}/api/v1/scan", headers=headers,
                data={"hash": file_hash, "scan_type": "apk", "file_name": apk.name},
            )
            scan_resp.raise_for_status()
            stages.append(f"scan {time.monotonic()-t1:.0f}s")

            t2 = time.monotonic()
            report_resp = await client.post(
                f"{url}/api/v1/report_json", headers=headers,
                data={"hash": file_hash},
            )
            report_resp.raise_for_status()
            stages.append(f"report {time.monotonic()-t2:.0f}s")

            report = report_resp.json()
            # Try known field names across MobSF versions
            score = (report.get("security_score")
                     or report.get("appsec_score")
                     or (report.get("appsec") or {}).get("security_score")
                     or "?")
            cvss = report.get("average_cvss")  # None is valid (no CVEs found)
            return ToolResult(
                name="mobsf", ok=True, elapsed=time.monotonic() - t0,
                data={"report": report, "hash": file_hash, "stages": stages,
                      "score": score, "cvss": cvss,
                      "report_keys": list(report.keys())[:20]},
            )
    except Exception as exc:
        return ToolResult(name="mobsf", ok=False, error=str(exc),
                          elapsed=time.monotonic() - t0, data={"stages": stages})
