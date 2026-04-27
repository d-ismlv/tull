# tull

Containerised Android APK static analysis pipeline. Orchestrates APKLeaks, JADX, and MobSF into a single run, filters third-party library noise, then drives a Claude AI agent to triage findings and produce a structured markdown security report.

No runtime dependencies beyond Docker and an Anthropic API key.

---

## Prerequisites

**Required**

| Requirement | Notes |
|---|---|
| Docker | Any recent version |
| `ANTHROPIC_API_KEY` | Claude Sonnet 4.6 by default; Opus 4.7 available via `CLAUDE_MODEL` |

**Optional**

| Requirement | Notes |
|---|---|
| MobSF | Self-hosted or via the bundled `docker-compose.yml` sidecar. Adds SAST score, permission analysis, manifest findings, and tracker detection. APKLeaks and JADX still run without it. |
| `MOBSF_API_KEY` | Found in MobSF → REST API. Required only if MobSF is configured. |

---

## Setup

**With Docker Compose (MobSF included)**

```bash
cp .env.example .env
# fill ANTHROPIC_API_KEY and MOBSF_API_KEY

docker compose up mobsf          # wait for healthy (≈60 s on first boot)
```

**Standalone container**

```bash
docker build -t tull .
```

**Without Docker (Python 3.12+)**

```bash
pip install -r requirements.txt
# also requires: jadx on PATH, apkleaks on PATH
```

---

## Usage

```bash
# Docker Compose (MobSF sidecar)
mkdir -p input output
cp target.apk input/
docker compose run analyzer /data/input/target.apk -o /data/output

# Standalone container
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e MOBSF_URL=http://mobsf:8000 \
  -e MOBSF_API_KEY=$MOBSF_API_KEY \
  -v ./input:/data/input:ro \
  -v ./output:/data/output \
  tull /data/input/target.apk -o /data/output

# Use Opus for deeper analysis
docker run ... -e CLAUDE_MODEL=claude-opus-4-7 tull target.apk

# Python directly
python analyze.py target.apk -o ./output
```

---

## Output

A single markdown report is written to the output directory:

```
output/
  target_security_report.md
```

Report structure:

```
# APK Security Report: AppName

| Field   | Value        |
| File    | target.apk   |
| Package | com.example  |
| SHA256  | …            |
| Risk    | HIGH         |
| Score   | 45/100       |

## Executive Summary
## Findings
   ### 🔴 Critical   [C-01] Hardcoded API key …
   ### 🟠 High       [H-01] WebView JS bridge exposed …
   ### 🟡 Medium     [M-01] ECB cipher mode …
   ### 🟢 Low / Informational
## Attack Surface
   ### Permissions
   ### Exported Components
   ### Network Endpoints
## Recommendations (Priority Order)
## Tool Status
```

Each finding includes severity, category, file path with line number, code evidence, impact, and recommendation.

---

## Notes

**APKLeaks** — scans the APK for leaked secrets, keys, and tokens using a rule-based pattern library. Output is formatted and passed verbatim to the analyst. Runs in parallel with JADX.

**JADX** — decompiles the APK to Java source. The filter stage strips all third-party and standard library packages (Android, AndroidX, Kotlin, OkHttp, Firebase, Retrofit, and ~20 other prefixes), leaving only app-package code. The analyst receives the filtered file tree and pre-scanned interesting patterns; it requests specific files via tool calls rather than receiving a full dump.

**MobSF** — static analysis via REST API. Upload → scan → report JSON. The summary passed to the analyst covers: security score, CVSS, dangerous permissions, manifest findings, HIGH/WARNING SAST results, discovered URLs, and tracker count. The full raw report is not forwarded. Gracefully skipped if `MOBSF_URL` is not set.

**Analyst (Claude)** — runs an agentic investigation loop with three tools: `read_file` (read a specific decompiled Java file), `grep_source` (regex search across app sources), `list_files` (directory listing). Claude decides which files to examine based on APKLeaks findings, MobSF issues, and pre-scanned patterns, then writes the final report directly. Maximum 12 tool-call rounds before the report is requested. Prompt caching is active on the shared system prompt across rounds.

---

## Extending

Adding a new tool requires three small changes:

1. Add `async def _mytool(apk, workdir) -> ToolResult` to `tools.py`
2. Append `asyncio.create_task(_mytool(...))` in `run_all()`
3. Surface relevant output in `_build_initial_prompt()` in `analyst.py`

The analyst loop benefits from additional context automatically — no other changes needed.

---

## License

MIT — see [LICENSE](LICENSE)
