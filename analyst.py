"""AI-powered agentic analysis.

Claude investigates the APK using read_file / grep_source / list_files tools,
then produces the final markdown security report.
"""

import json
import re
import subprocess
from pathlib import Path

import anthropic

from filter import AppContext

MAX_ROUNDS = 12  # max tool-use iterations before forcing report

_SYSTEM = """\
You are a senior Android application security researcher conducting a focused security audit.

Methodology:
1. Review APKLeaks secrets and MobSF HIGH/CRITICAL findings first.
2. Use tools to verify issues and find additional vulnerabilities in app code.
3. Prioritize: hardcoded secrets › auth bypass › sensitive data exposure › \
injection › unsafe crypto › dangerous component exposure › privacy.
4. Ignore: third-party SDK internals, standard library code, low-signal INFO findings.
5. Be efficient: 8–12 tool calls. Chase confirmed issues, not theoretical ones.

Severity — apply strictly, default DOWN not up:
- CRITICAL: You have read the exact code, the exploit path is clear and directly actionable
  (e.g. hardcoded private key in app code, authentication bypass with no further conditions).
- HIGH: Clear vulnerability present in code you read, exploitable with realistic attacker access,
  impact is significant. Do NOT use for theoretical or conditional issues.
- MEDIUM: Real weakness but requires specific conditions, partial access, or chained steps.
- LOW / INFO: Best-practice violations, defence-in-depth gaps, or observations without exploit.

Do NOT escalate severity based on pattern matches, tool output alone, or category names.
Every HIGH or CRITICAL finding must include the exact file path, line number, and the
specific code snippet that constitutes the evidence. If you cannot show the code, downgrade.
"""

_REPORT_REQUEST = """\
Investigation complete.

Write the full security report now in this exact markdown structure:

---
## Executive Summary
[3–5 sentences: app purpose, overall risk posture, most critical issues]

## Findings

### 🔴 Critical
[if none, write "None identified."]

#### [C-01] Title
- **Category**: e.g. Hardcoded Credential
- **Location**: `path/to/File.java:42`
**Evidence:**
```java
[exact code snippet]
```
**Impact**: …
**Recommendation**: …

### 🟠 High
[same structure, H-01, H-02 …]

### 🟡 Medium
[same structure, M-01, M-02 …]

### 🟢 Low / Informational
[same structure, L-01 … or "None identified."]

---
## Attack Surface

### Permissions
[table: Permission | Type | Risk]

### Exported Components
[list with risks]

### Network Endpoints
[list of discovered endpoints]

---
## Recommendations (Priority Order)
1. **[Immediate]** …
2. **[Short-term]** …
3. **[Long-term]** …
---

Be precise. Include only verified findings backed by code you have read.
"""

_ANALYST_TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read a decompiled Java source file. "
            "Path is relative to the JADX sources/ directory, e.g. 'com/example/app/MainActivity.java'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "grep_source",
        "description": (
            "Search across all decompiled app source files with a regex. "
            "Returns matching lines with ±2 lines of context. "
            "Keep patterns specific to avoid noise."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "max_results": {"type": "integer", "default": 20},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "list_files",
        "description": "List Java files under a package sub-directory, e.g. 'com/example/app/network'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "package_path": {"type": "string"},
            },
            "required": ["package_path"],
        },
    },
]


def investigate(ctx: AppContext, workdir: Path, model: str,
                on_action=None) -> tuple[str, dict]:
    """Returns (analysis_markdown, token_stats).
    on_action(msg) is called before each tool dispatch for live CLI updates."""
    client = anthropic.Anthropic()
    jadx_sources = workdir / "jadx" / "sources"
    tokens = {"input": 0, "output": 0}

    def _track(resp):
        tokens["input"] += resp.usage.input_tokens
        tokens["output"] += resp.usage.output_tokens

    messages = [{"role": "user", "content": _build_initial_prompt(ctx)}]

    for _round in range(MAX_ROUNDS):
        resp = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM,
            tools=_ANALYST_TOOLS,
            messages=messages,
        )
        _track(resp)
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason != "tool_use":
            break

        tool_results = []
        for block in resp.content:
            if block.type == "tool_use":
                arg = str(next(iter(block.input.values()), ""))[:55]
                if on_action:
                    on_action(
                        f"round {_round + 1}/{MAX_ROUNDS}  "
                        f"{block.name}({arg})  "
                        f"[{tokens['input']//1000}k/{tokens['output']//1000}k tok]"
                    )
                result = _dispatch(block.name, block.input, jadx_sources, ctx.package_name)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
        messages.append({"role": "user", "content": tool_results})

    # Final report — no tools offered so Claude writes prose
    messages.append({"role": "user", "content": _REPORT_REQUEST})
    final = client.messages.create(
        model=model,
        max_tokens=8192,
        system=_SYSTEM,
        messages=messages,
    )
    _track(final)
    return _extract_text(final), tokens


# ── tool dispatch ─────────────────────────────────────────────────────────────

def _dispatch(name: str, inputs: dict, sources: Path, package: str) -> str:
    try:
        if name == "read_file":
            return _read_file(sources, inputs["path"])
        if name == "grep_source":
            return _grep(sources, inputs["pattern"], inputs.get("max_results", 20), package)
        if name == "list_files":
            return _list_files(sources, inputs["package_path"])
    except Exception as exc:
        return f"[tool error] {exc}"
    return "[unknown tool]"


def _read_file(sources: Path, rel_path: str) -> str:
    # Sanitize: no directory traversal
    safe = (sources / rel_path).resolve()
    if not str(safe).startswith(str(sources.resolve())):
        return "[access denied]"
    if not safe.exists():
        # fuzzy: try case-insensitive search
        matches = list(sources.rglob(Path(rel_path).name))
        if matches:
            safe = matches[0]
        else:
            return f"[file not found: {rel_path}]"
    lines = safe.read_text(errors="replace").splitlines()
    numbered = "\n".join(f"{i+1:4d}  {l}" for i, l in enumerate(lines))
    return numbered[:12000]  # cap at ~200 lines equivalent


def _grep(sources: Path, pattern: str, max_results: int, package: str) -> str:
    if not sources.exists():
        return "[no sources]"
    try:
        # Restrict to app package if known
        search_root = sources
        if package:
            pkg_dir = sources / Path(*package.split("."))
            if pkg_dir.exists():
                search_root = pkg_dir

        result = subprocess.run(
            ["grep", "-rn", "--include=*.java", "-E", pattern, str(search_root)],
            capture_output=True, text=True, timeout=30,
        )
        lines = result.stdout.splitlines()[:max_results]
        # make paths relative to sources
        cleaned = [l.replace(str(sources) + "/", "") for l in lines]
        return "\n".join(cleaned) or "[no matches]"
    except subprocess.TimeoutExpired:
        return "[grep timed out]"
    except Exception as exc:
        return f"[grep error: {exc}]"


def _list_files(sources: Path, pkg_path: str) -> str:
    target = sources / pkg_path
    if not target.exists():
        return f"[not found: {pkg_path}]"
    files = sorted(str(f.relative_to(sources)) for f in target.rglob("*.java"))
    return "\n".join(files[:100]) or "[empty]"


# ── prompt builders ───────────────────────────────────────────────────────────

def _build_initial_prompt(ctx: AppContext) -> str:
    snippets_text = ""
    if ctx.snippets:
        groups: dict[str, list] = {}
        for s in ctx.snippets:
            groups.setdefault(s.label, []).append(s)
        parts = []
        for label, items in groups.items():
            parts.append(f"**{label}** ({len(items)} hits)")
            for item in items[:3]:
                parts.append(f"  {item.file}:{item.line}\n  ```\n{item.context}\n  ```")
        snippets_text = "\n".join(parts)
    else:
        snippets_text = "None detected."

    return f"""\
# APK Under Analysis: {ctx.apk_name}
Package: `{ctx.package_name}`
SHA256: `{ctx.metadata.get('sha256', 'N/A')}`

---
## APKLeaks Findings
{ctx.apkleaks_text}

---
## MobSF Analysis
{ctx.mobsf_summary}

---
## AndroidManifest.xml
```xml
{ctx.manifest_xml[:4000]}
```

---
## App Package File Tree (filtered — stdlib excluded)
```
{ctx.file_tree[:3000]}
```

---
## Pre-scanned Interesting Patterns
{snippets_text[:4000]}

---
Begin your investigation. Use tools to read files and verify findings.
"""


def _extract_text(resp) -> str:
    for block in resp.content:
        if hasattr(block, "text"):
            return block.text
    return ""
