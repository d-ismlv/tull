#!/usr/bin/env python3
"""APK Security Analyzer — entry point.

Usage:
    python analyze.py app.apk -o ./reports
    python analyze.py app.apk --model claude-opus-4-7

Environment variables (or --flags):
    ANTHROPIC_API_KEY   required
    MOBSF_URL           optional, e.g. http://mobsf:8000
    MOBSF_API_KEY       optional
    CLAUDE_MODEL        optional, default claude-sonnet-4-6
"""

import asyncio
import argparse
import os
import sys
import time
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path


_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


@asynccontextmanager
async def spinning(label: str):
    """Single-line braille spinner. Clears itself on exit."""
    stop = asyncio.Event()
    t0 = time.monotonic()

    async def _run():
        i = 0
        while not stop.is_set():
            elapsed = int(time.monotonic() - t0)
            sys.stdout.write(f"\r  {_FRAMES[i % len(_FRAMES)]}  {label}  {elapsed}s")
            sys.stdout.flush()
            await asyncio.sleep(0.1)
            i += 1
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    task = asyncio.create_task(_run())
    try:
        yield
    finally:
        stop.set()
        await task


def _args():
    p = argparse.ArgumentParser(description="APK Security Analyzer")
    p.add_argument("apk", help="Path to APK file")
    p.add_argument("-o", "--output", default=".", help="Report output directory (default: .)")
    p.add_argument("--mobsf-url", default=os.getenv("MOBSF_URL", ""))
    p.add_argument("--mobsf-key", default=os.getenv("MOBSF_API_KEY", ""))
    p.add_argument(
        "--model",
        default=os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"),
        choices=["claude-sonnet-4-6", "claude-opus-4-7"],
    )
    return p.parse_args()


async def main():
    args = _args()

    if not os.getenv("ANTHROPIC_API_KEY"):
        sys.exit("Error: ANTHROPIC_API_KEY is not set.")

    apk = Path(args.apk).resolve()
    if not apk.exists():
        sys.exit(f"Error: APK not found: {apk}")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[{datetime.now():%H:%M:%S}] APK Security Analyzer")
    print(f"      File  : {apk.name} ({apk.stat().st_size // 1_048_576} MB)")
    print(f"      Model : {args.model}")
    if args.mobsf_url:
        print(f"      MobSF : {args.mobsf_url}")

    with tempfile.TemporaryDirectory(prefix="apkanalyze_") as tmp:
        workdir = Path(tmp)

        # ── 1. Run tools ──────────────────────────────────────────────────
        from tools import run_all
        async with spinning("running tools  (apkleaks · jadx · mobsf)"):
            tool_results = await run_all(apk, workdir, args.mobsf_url, args.mobsf_key)

        _log("1/4", "tools done")
        for r in tool_results:
            status = "ok" if r.ok else f"FAILED  {r.error[:70]}"
            print(f"       ↳ {r.name}: {status}")

        # ── 2. Filter noise ───────────────────────────────────────────────
        from filter import build_context
        ctx = build_context(apk, workdir, tool_results)
        ctx.metadata["model"] = args.model
        _log("2/4", f"filtered  ·  package: {ctx.package_name}  ·  {len(ctx.snippets)} interesting patterns")

        # ── 3. AI investigation ───────────────────────────────────────────
        # investigate() uses the sync Anthropic client; run in a thread so
        # the event loop (and spinner) stay responsive during API calls.
        from analyst import investigate
        async with spinning(f"investigating  ({args.model})"):
            analysis_md = await asyncio.to_thread(investigate, ctx, workdir, args.model)
        _log("3/4", "analysis complete")

        # ── 4. Render report ──────────────────────────────────────────────
        from report import render
        report = render(apk.name, ctx.metadata, analysis_md, tool_results)

        out_file = output_dir / f"{apk.stem}_security_report.md"
        out_file.write_text(report, encoding="utf-8")

    print(f"\n[+] Report: {out_file}")
    for line in report.splitlines()[5:15]:
        if "Risk Level" in line:
            print(f"    {line.strip()}")
            break


def _log(step: str, msg: str):
    print(f"[{datetime.now():%H:%M:%S}] [{step}] {msg}")


if __name__ == "__main__":
    asyncio.run(main())
