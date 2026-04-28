"""Tool runners: APKLeaks, JADX, MobSF.

Each tool returns a ToolResult. New tools only need to implement the same signature
and be added to run_all(). Failures are isolated — the pipeline continues.
"""

import asyncio
import json
import os
import signal
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


def _killpg(proc) -> None:
    """Kill the entire process group so child processes (e.g. jadx spawned by apkleaks)
    don't keep stdout pipes open and cause communicate() to hang indefinitely."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except Exception:
            pass


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


def _parse_apkleaks_text(text: str) -> dict[str, list[str]]:
    """Parse apkleaks native text format: [Category] headers + '- item' lines."""
    result: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]") and len(s) > 2:
            current = s[1:-1]
            result[current] = []
        elif s.startswith("- ") and current is not None:
            result[current].append(s[2:])
    return {k: v for k, v in result.items() if v}


async def _apkleaks(apk: Path, workdir: Path) -> ToolResult:
    out = workdir / "apkleaks_raw.txt"
    t0 = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            _apkleaks_bin(), "-f", str(apk), "-o", str(out),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HOME": "/tmp"},
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=900)
        except asyncio.TimeoutError:
            _killpg(proc)
            return ToolResult(name="apkleaks", ok=False, error="timed out after 900s",
                              elapsed=time.monotonic() - t0)

        raw = out.read_text(errors="replace") if out.exists() else stdout.decode(errors="replace")
        stderr_out = stderr.decode(errors="replace") if stderr else ""

        # Try JSON first (future versions), fall back to native text parser
        try:
            findings = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            findings = _parse_apkleaks_text(raw)

        category_count = len(findings)
        finding_count = sum(len(v) for v in findings.values() if isinstance(v, list))
        if not findings:
            # Show whatever the process actually printed so the failure is diagnosable
            diag = (stderr_out or raw or "no output").strip()
            error = diag[:300]
        else:
            error = ""
        return ToolResult(
            name="apkleaks", ok=bool(findings), elapsed=time.monotonic() - t0,
            error=error,
            data={"findings": findings, "raw": raw,
                  "categories": category_count, "findings_total": finding_count},
        )
    except Exception as exc:
        if proc:
            _killpg(proc)
        return ToolResult(name="apkleaks", ok=False, error=str(exc), elapsed=time.monotonic() - t0)


async def _jadx(apk: Path, output_dir: Path) -> ToolResult:
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "jadx", "-d", str(output_dir), "--show-bad-code", str(apk),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HOME": "/tmp"},
            start_new_session=True,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=600)
        stdout_text = stdout_bytes.decode(errors="replace")
        stderr_text = stderr_bytes.decode(errors="replace")
        java_count = sum(1 for _ in output_dir.rglob("*.java"))
        if java_count == 0:
            diag = (stderr_text or stdout_text or "no output").strip()
            error = diag[:300]
        else:
            error = ""
        return ToolResult(
            name="jadx", ok=java_count > 0, elapsed=time.monotonic() - t0,
            error=error,
            data={"output_dir": str(output_dir), "java_files": java_count,
                  "stderr_tail": stderr_text[-1000:]},
        )
    except asyncio.TimeoutError:
        _killpg(proc)
        return ToolResult(name="jadx", ok=False, error="timed out after 600s",
                          elapsed=time.monotonic() - t0)
    except Exception as exc:
        return ToolResult(name="jadx", ok=False, error=str(exc), elapsed=time.monotonic() - t0)


def _mobsf_score(report: dict) -> tuple[Any, Any]:
    score = (report.get("security_score")
             or report.get("appsec_score")
             or (report.get("appsec") or {}).get("security_score")
             or "?")
    return score, report.get("average_cvss")


def _mobsf_result(report: dict, file_hash: str, stages: list, t0: float) -> ToolResult:
    score, cvss = _mobsf_score(report)
    return ToolResult(
        name="mobsf", ok=True, elapsed=time.monotonic() - t0,
        data={"report": report, "hash": file_hash, "stages": stages,
              "score": score, "cvss": cvss, "report_keys": list(report.keys())[:20]},
    )


async def _mobsf(apk: Path, url: str, key: str) -> ToolResult:
    url = url.rstrip("/")
    headers = {"Authorization": key}
    t0 = time.monotonic()
    stages: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            # Upload (fast — MobSF deduplicates by hash internally)
            upload_resp = await client.post(
                f"{url}/api/v1/upload",
                headers=headers,
                files={"file": (apk.name, apk.open("rb"), "application/vnd.android.package-archive")},
            )
            upload_resp.raise_for_status()
            file_hash = upload_resp.json()["hash"]
            stages.append(f"upload {time.monotonic()-t0:.0f}s")

            # Try fetching an existing report before triggering a scan.
            # If this APK was scanned before, MobSF already has the results.
            t1 = time.monotonic()
            try:
                cached = await client.post(
                    f"{url}/api/v1/report_json", headers=headers,
                    data={"hash": file_hash},
                )
                if cached.status_code == 200:
                    report = cached.json()
                    if report.get("app_name") or report.get("package_name"):
                        stages.append(f"cached {time.monotonic()-t1:.0f}s")
                        return _mobsf_result(report, file_hash, stages, t0)
            except Exception:
                pass

            # Cache miss — run full scan (slow for new APKs)
            t2 = time.monotonic()
            scan_resp = await client.post(
                f"{url}/api/v1/scan", headers=headers,
                data={"hash": file_hash, "scan_type": "apk", "file_name": apk.name},
            )
            scan_resp.raise_for_status()
            stages.append(f"scan {time.monotonic()-t2:.0f}s")

            t3 = time.monotonic()
            report_resp = await client.post(
                f"{url}/api/v1/report_json", headers=headers,
                data={"hash": file_hash},
            )
            report_resp.raise_for_status()
            stages.append(f"report {time.monotonic()-t3:.0f}s")

            return _mobsf_result(report_resp.json(), file_hash, stages, t0)

    except Exception as exc:
        return ToolResult(name="mobsf", ok=False, error=str(exc),
                          elapsed=time.monotonic() - t0, data={"stages": stages})
