"""Tool runners: APKLeaks, JADX, MobSF.

Each tool returns a ToolResult. New tools only need to implement the same signature
and be added to run_all(). Failures are isolated — the pipeline continues.
"""

import asyncio
import json
import subprocess
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

async def _apkleaks(apk: Path, workdir: Path) -> ToolResult:
    out = workdir / "apkleaks.json"
    try:
        proc = await asyncio.create_subprocess_exec(
            "apkleaks", "-f", str(apk), "-o", str(out),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        findings: dict = {}
        if out.exists():
            try:
                findings = json.loads(out.read_text())
            except json.JSONDecodeError:
                findings = {"raw": out.read_text()}
        return ToolResult(
            name="apkleaks", ok=bool(findings),
            data={"findings": findings, "stdout": stdout.decode(errors="replace")},
        )
    except Exception as exc:
        return ToolResult(name="apkleaks", ok=False, error=str(exc))


async def _jadx(apk: Path, output_dir: Path) -> ToolResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            "jadx", "-d", str(output_dir), "--show-bad-code", str(apk),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        java_count = sum(1 for _ in output_dir.rglob("*.java"))
        return ToolResult(
            name="jadx", ok=java_count > 0,
            data={"output_dir": str(output_dir), "java_files": java_count,
                  "stderr_tail": stderr.decode(errors="replace")[-1000:]},
        )
    except Exception as exc:
        return ToolResult(name="jadx", ok=False, error=str(exc))


async def _mobsf(apk: Path, url: str, key: str) -> ToolResult:
    url = url.rstrip("/")
    headers = {"Authorization": key}
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            # upload
            async with await client.stream(
                "POST", f"{url}/api/v1/upload",
                headers=headers,
                files={"file": (apk.name, apk.open("rb"), "application/vnd.android.package-archive")},
            ) as resp:
                resp.raise_for_status()
                upload = resp.json()

            file_hash = upload["hash"]

            # scan (synchronous on server side)
            scan_resp = await client.post(
                f"{url}/api/v1/scan", headers=headers,
                data={"hash": file_hash, "scan_type": "apk", "file_name": apk.name},
            )
            scan_resp.raise_for_status()

            # full JSON report
            report_resp = await client.get(
                f"{url}/api/v1/report_json", headers=headers,
                params={"hash": file_hash},
            )
            report_resp.raise_for_status()
            return ToolResult(
                name="mobsf", ok=True,
                data={"report": report_resp.json(), "hash": file_hash},
            )
    except Exception as exc:
        return ToolResult(name="mobsf", ok=False, error=str(exc))
