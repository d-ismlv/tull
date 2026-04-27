#!/usr/bin/env python3
"""APK Security Analyzer — entry point."""

import asyncio
import argparse
import json
import os
import sys
import time
import tempfile
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

_BANNER = """
             
 _       _ _ 
| |_ _ _| | |
|  _| | | | |
|_| |___|_|_|
             
"""

@asynccontextmanager
async def spinning(label: str, action: list[str] | None = None):
    """Single-line braille spinner. Truncates to terminal width — no line wrapping."""
    stop = asyncio.Event()
    t0 = time.monotonic()

    async def _run():
        i = 0
        while not stop.is_set():
            elapsed = int(time.monotonic() - t0)
            detail = f"  ←  {action[0]}" if action and action[0] else ""
            line = f"  {_FRAMES[i % len(_FRAMES)]}  {label}{detail}  {elapsed:3d}s"
            try:
                cols = os.get_terminal_size().columns - 1
            except OSError:
                cols = 119
            sys.stdout.write(f"\r{line[:cols]}")
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
    p.add_argument(
        "--max-patterns", type=int, default=0, metavar="N",
        help="Cap total patterns fed to AI, highest-priority first (0 = no limit)",
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
    stem = apk.stem

    print(_BANNER)
    _log("init", f"{apk.name}  ({apk.stat().st_size // 1_048_576} MB)")
    _log("init", f"model: {args.model}")
    if args.mobsf_url:
        _log("init", f"mobsf: {args.mobsf_url}")
    else:
        _log("warn", "MOBSF_URL not set — MobSF will be skipped")
    if args.max_patterns:
        _log("init", f"max-patterns: {args.max_patterns}")

    with tempfile.TemporaryDirectory(prefix="apkanalyze_") as tmp:
        workdir = Path(tmp)

        # ── 1. Run all tools concurrently ─────────────────────────────────
        from tools import run_all
        tools_label = "apkleaks · jadx" + (" · mobsf" if args.mobsf_url else "")
        async with spinning(f"[1/4] tools  ({tools_label})"):
            tool_results = await run_all(apk, workdir, args.mobsf_url, args.mobsf_key)

        _log("1/4", "tools done")
        for r in tool_results:
            _print_tool_result(r)

        # Save apkleaks findings immediately
        for r in tool_results:
            if r.name == "apkleaks" and r.ok and r.data.get("findings"):
                p = output_dir / f"{stem}_apkleaks.json"
                p.write_text(json.dumps(r.data["findings"], indent=2))
                _log("1/4", f"apkleaks saved → {p.name}")

        # ── 2. Filter noise ───────────────────────────────────────────────
        from filter import build_context, _PRIORITY
        ctx = build_context(apk, workdir, tool_results)
        ctx.metadata["model"] = args.model

        if args.max_patterns > 0 and len(ctx.snippets) > args.max_patterns:
            ctx.snippets.sort(key=lambda s: _PRIORITY.get(s.label, 3))
            ctx.snippets = ctx.snippets[:args.max_patterns]

        counts = Counter(s.label for s in ctx.snippets)
        _log("2/4", f"package: {ctx.package_name}  ·  {len(ctx.snippets)} patterns")
        for label, n in sorted(counts.items(), key=lambda x: -x[1])[:8]:
            print(f"            {n:>4}  {label}")
        if len(counts) > 8:
            print(f"                  … +{len(counts) - 8} more categories")

        # ── 3. AI investigation ───────────────────────────────────────────
        from analyst import investigate
        action: list[str] = [""]
        async with spinning(f"[3/4] investigating  ({args.model})", action):
            analysis_md = await asyncio.to_thread(
                investigate, ctx, workdir, args.model,
                lambda msg: action.__setitem__(0, msg),
            )
        _log("3/4", "analysis complete")

        # Save raw analysis before rendering (crash recovery)
        analysis_path = output_dir / f"{stem}_analysis.md"
        analysis_path.write_text(analysis_md, encoding="utf-8")
        _log("3/4", f"analysis saved → {analysis_path.name}")

        # ── 4. Render final report ────────────────────────────────────────
        from report import render
        report = render(apk.name, ctx.metadata, analysis_md, tool_results)

        report_path = output_dir / f"{stem}_security_report.md"
        report_path.write_text(report, encoding="utf-8")

    print(f"\n[+] {report_path}")
    for line in report.splitlines()[5:15]:
        if "Risk Level" in line:
            print(f"    {line.strip()}")
            break


def _log(step: str, msg: str):
    print(f"[{datetime.now():%H:%M:%S}] [{step}] {msg}")


def _print_tool_result(r):
    t = f"  ({r.elapsed:3.0f}s)"
    if not r.ok:
        print(f"       ↳ {r.name}: FAILED{t}  {r.error[:80]}")
        return

    if r.name == "apkleaks":
        n = r.data.get("findings_total", 0)
        c = r.data.get("categories", 0)
        print(f"       ↳ apkleaks: ok{t}  {n} findings across {c} categories")

    elif r.name == "jadx":
        n = r.data.get("java_files", 0)
        print(f"       ↳ jadx: ok{t}  {n:,} Java files decompiled")

    elif r.name == "mobsf":
        stages = "  ·  ".join(r.data.get("stages", []))
        score = r.data.get("score", "?")
        cvss = r.data.get("cvss", "N/A")
        print(f"       ↳ mobsf: ok{t}  score {score}/100  cvss {cvss}  [{stages}]")
        if score == "?":
            keys = r.data.get("report_keys", [])
            print(f"              (score field not found — report keys: {keys})")
    else:
        print(f"       ↳ {r.name}: ok{t}")


if __name__ == "__main__":
    asyncio.run(main())
