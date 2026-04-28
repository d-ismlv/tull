# tull

APK security tools produce useful but noisy output — tracing pattern matches to actually exploitable code still requires reading decompiled source. tull runs APKLeaks, JADX, and MobSF in parallel, then drives a Claude agent to read decompiled Java, confirm or dismiss findings, and write a severity-ranked report. It does not replace a skilled mobile security engineer, but it closes the gap between raw scanner output and a first actionable assessment.

A pipeline that connects three specialist tools through an AI synthesis layer: findings go in, a structured report with code evidence comes out. → [example report](example/acme_bank_security_report.md)

![tull — APK security analysis pipeline](assets/tull.png)

---

## Architecture

```mermaid
flowchart LR
    APK([APK file])

    subgraph tools["Tools  (parallel)"]
        AL[APKLeaks\nSecrets & keys]
        JD[JADX\nDecompile → Java]
        MF[MobSF\nSAST · permissions\nmanifest · trackers]
    end

    subgraph filter["Filter"]
        F[Strip stdlib / third-party\nPriority-ranked snippets\nManifest · file tree]
    end

    subgraph analyst["AI Analyst  (Claude)"]
        direction TB
        AG[Agentic loop\nup to 12 rounds]
        subgraph atools["Tools"]
            RF[read_file]
            GS[grep_source]
            LF[list_files]
        end
        AG --> atools
    end

    RPT[/Markdown report/]

    APK --> tools
    tools --> filter
    filter --> analyst
    analyst --> RPT
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker | Any recent version |
| `ANTHROPIC_API_KEY` | Claude Sonnet 4.6 by default; Opus 4.7 available via `--model` |
| MobSF | Self-hosted instance required |
| `MOBSF_API_KEY` | Found in MobSF → REST API page |

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
# also requires: jadx on PATH
```

APKLeaks is installed automatically via `requirements.txt`.

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
docker run ... tull target.apk --model claude-opus-4-7

# Cap patterns fed to AI (useful for very large apps)
python analyze.py target.apk --max-patterns 150

# Python directly
python analyze.py target.apk -o ./output
```

---

## Output

All files are written to the output directory (default: `output/`):

```
output/
  target_security_report.md   ← final report
  target_apkleaks.txt         ← verbatim APKLeaks output
  target_apkleaks.json        ← APKLeaks findings as JSON
  target_mobsf_report.json    ← full MobSF report JSON
  target_sources/             ← decompiled Java source (app package only)
```

A summary is printed at the end of every run:

```
[+] 4 files saved to output/
       target_security_report.md                         18 KB
       target_apkleaks.txt                               14 KB
       ...

    tokens  42,310 in · 3,891 out  (claude-sonnet-4-6)
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

Each finding includes severity, category, file path with line number, code evidence, impact, and recommendation. HIGH and CRITICAL findings must be backed by exact code — the analyst is instructed to downgrade rather than speculate.

---

## Options

```
usage: analyze.py [-h] [-o OUTPUT] [--mobsf-url URL] [--mobsf-key KEY]
                  [--model MODEL] [--max-patterns N]
                  apk

positional arguments:
  apk                   Path to APK file

options:
  -o, --output DIR      Report output directory (default: output/)
  --mobsf-url URL       MobSF base URL (env: MOBSF_URL)
  --mobsf-key KEY       MobSF API key (env: MOBSF_API_KEY)
  --model MODEL         claude-sonnet-4-6 | claude-opus-4-7
  --max-patterns N      Cap patterns fed to AI, highest-priority first (0 = no limit)
```

---

## How it works

**APKLeaks** scans the APK for leaked secrets, keys, and tokens using a rule-based pattern library. Output is formatted and passed verbatim to the analyst. Runs in parallel with JADX.

**JADX** decompiles the APK to Java source. The filter stage strips all third-party and standard library packages (Android, AndroidX, Kotlin, OkHttp, Firebase, Retrofit, and ~20 other prefixes), leaving only app-package code.

**MobSF** provides static analysis via REST API: upload → scan → report JSON. The summary passed to the analyst covers security score, CVSS, dangerous permissions, manifest findings, HIGH/WARNING SAST results, discovered URLs, and tracker count. A running MobSF instance with `MOBSF_URL` and `MOBSF_API_KEY` set is required.

**Filter** builds a token-efficient `AppContext`: priority-ranked code snippets (credentials uncapped, URLs capped at 20), filtered file tree, parsed AndroidManifest.xml. Use `--max-patterns` to limit total snippets on very large apps.

**Analyst (Claude)** runs an agentic investigation loop with three tools: `read_file` (read a specific decompiled Java file), `grep_source` (regex search across app sources), `list_files` (directory listing). Claude decides which files to examine based on APKLeaks findings, MobSF issues, and pre-scanned patterns, then writes the final report. Maximum 12 tool-call rounds. Severity is applied strictly — CRITICAL and HIGH require exact file path, line number, and code snippet as evidence.

---

## Security

This tool analyses untrusted input — APK files sourced from unknown parties. The decompiled code and strings extracted from those APKs are fed directly into an AI agent that has file-system tools (`read_file`, `grep_source`, `list_files`). A malicious APK could embed content designed to manipulate the agent's behaviour (a.k.a [indirect prompt injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)).

**Running inside the provided Docker container is strongly recommended.** The container limits the blast radius: the agent's file tools are scoped to the temporary JADX working directory, and the container has no access to the host filesystem beyond the explicitly mounted `input/` and `output/` volumes.

Avoid running `python analyze.py` directly on a host that has access to sensitive files or credentials beyond `ANTHROPIC_API_KEY`.

---

## License

MIT — see [LICENSE](LICENSE)
