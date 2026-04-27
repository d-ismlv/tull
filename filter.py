"""Noise reduction: strip third-party libs, surface interesting code patterns.

Produces AppContext — the structured, token-efficient input fed to the AI analyst.
"""

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from tools import ToolResult


# Packages that are third-party or standard library — never interesting to audit
_STDLIB_PREFIXES = (
    "android.", "androidx.", "dalvik.", "libcore.",
    "java.", "javax.", "sun.", "com.sun.",
    "kotlin.", "kotlinx.",
    "com.google.android.", "com.android.",
    "com.google.gson.", "com.google.common.", "com.google.protobuf.",
    "com.google.firebase.", "com.google.gms.", "com.google.ads.",
    "okhttp3.", "okio.", "retrofit2.", "com.squareup.",
    "io.reactivex.", "rx.", "io.reactivex3.",
    "dagger.", "javax.inject.", "com.google.inject.",
    "com.facebook.", "com.twitter.", "com.linkedin.",
    "com.amazonaws.", "com.microsoft.", "com.huawei.",
    "org.json.", "org.xmlpull.", "org.apache.",
    "com.bumptech.glide.", "com.squareup.picasso.", "io.coil.",
    "com.airbnb.lottie.", "io.flutter.", "com.reactnative.",
    "com.facebook.react.", "org.jetbrains.",
)

# Patterns worth surfacing to the analyst before full agentic investigation
_INTERESTING: list[tuple[str, str]] = [
    (r"https?://[^\s\"'<>]{10,}", "URL"),
    (r"jdbc:[^\s\"']+", "JDBC connection string"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{4,}", "Hardcoded credential"),
    (r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[\"'][^\"']{8,}", "API key"),
    (r"(?i)(secret|token|bearer)\s*[=:]\s*[\"'][^\"']{8,}", "Secret/token"),
    (r"BEGIN (RSA |EC |DSA )?PRIVATE KEY", "Private key material"),
    (r"(?i)setJavaScriptEnabled\s*\(\s*true", "WebView JS enabled"),
    (r"(?i)addJavascriptInterface\s*\(", "WebView JS bridge"),
    (r"(?i)setAllowFileAccess\s*\(\s*true", "WebView file access"),
    (r"(?i)(Runtime\.getRuntime\(\)|ProcessBuilder|\.exec\s*\()", "Command execution"),
    (r"MODE_WORLD_(READABLE|WRITABLE)", "World-accessible file"),
    (r'Cipher\.getInstance\s*\(\s*"[^"]*ECB', "ECB cipher mode"),
    (r"(?i)(checkServerTrusted|ALLOW_ALL_HOSTNAME|TrustAll)", "SSL bypass"),
    (r"(?i)(getSharedPreferences|openFileOutput).{0,80}(?i)(password|secret|token|key)", "Sensitive SharedPrefs"),
    (r"(?i)Log\.[dviwef]\s*\([^)]{0,60}(?i)(password|token|key|secret)", "Sensitive data logged"),
    (r"(?i)getExternalStorage|EXTERNAL_STORAGE", "External storage"),
    (r"content://[a-zA-Z0-9._/]+", "Content provider URI"),
    (r"(?i)(AES|DES|RSA|MD5|SHA-?1)\b", "Crypto algorithm"),
]


@dataclass
class Snippet:
    file: str
    line: int
    label: str
    context: str


@dataclass
class AppContext:
    apk_name: str
    metadata: dict
    package_name: str
    apkleaks_text: str
    mobsf_summary: str
    file_tree: str
    snippets: list[Snippet]
    manifest_xml: str


def build_context(apk: Path, workdir: Path, results: list[ToolResult]) -> AppContext:
    by_name = {r.name: r for r in results}
    jadx_dir = workdir / "jadx"

    metadata = _apk_metadata(apk)
    package_name, manifest_xml = _parse_manifest(jadx_dir)
    metadata["package"] = package_name

    mobsf_result = by_name.get("mobsf")
    if mobsf_result and mobsf_result.ok:
        mobsf_report = mobsf_result.data["report"]
        metadata.update({
            "app_name": mobsf_report.get("app_name", apk.stem),
            "version": mobsf_report.get("version_name", ""),
            "security_score": mobsf_report.get("security_score", "N/A"),
            "average_cvss": mobsf_report.get("average_cvss", "N/A"),
        })
        mobsf_summary = _summarize_mobsf(mobsf_report)
    else:
        err = mobsf_result.error if mobsf_result else "not configured"
        mobsf_summary = f"*MobSF unavailable: {err}*"

    apkleaks_result = by_name.get("apkleaks")
    apkleaks_text = _format_apkleaks(apkleaks_result) if apkleaks_result else "*APKLeaks unavailable*"

    file_tree = _build_file_tree(jadx_dir, package_name)
    snippets = _scan_interesting(jadx_dir, package_name)

    return AppContext(
        apk_name=apk.name,
        metadata=metadata,
        package_name=package_name,
        apkleaks_text=apkleaks_text,
        mobsf_summary=mobsf_summary,
        file_tree=file_tree,
        snippets=snippets,
        manifest_xml=manifest_xml,
    )


# ── helpers ───────────────────────────────────────────────────────────────────

def _apk_metadata(apk: Path) -> dict:
    data = apk.read_bytes()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_mb": round(len(data) / 1_048_576, 2),
    }


def _parse_manifest(jadx_dir: Path) -> tuple[str, str]:
    for candidate in [
        jadx_dir / "resources" / "AndroidManifest.xml",
        jadx_dir / "AndroidManifest.xml",
    ]:
        if candidate.exists():
            text = candidate.read_text(errors="replace")
            try:
                root = ET.fromstring(text)
                pkg = root.get("package", "")
                return pkg, text[:8000]
            except ET.ParseError:
                pass
    return "", ""


def _is_stdlib(java_path: Path, sources_root: Path) -> bool:
    rel = java_path.relative_to(sources_root)
    dotted = ".".join(rel.parts[:-1])  # drop filename
    return dotted.startswith(_STDLIB_PREFIXES)


def _build_file_tree(jadx_dir: Path, package_name: str) -> str:
    sources = jadx_dir / "sources"
    if not sources.exists():
        return "*No decompiled sources found*"

    pkg_path = sources / Path(*package_name.split(".")) if package_name else sources
    if not pkg_path.exists():
        pkg_path = sources

    lines: list[str] = []
    for f in sorted(pkg_path.rglob("*.java")):
        if not _is_stdlib(f, sources):
            lines.append(str(f.relative_to(sources)))

    if not lines:
        # Fall back to everything non-stdlib
        for f in sorted(sources.rglob("*.java")):
            if not _is_stdlib(f, sources):
                lines.append(str(f.relative_to(sources)))

    return "\n".join(lines[:500]) or "*No app-package Java files found*"


def _scan_interesting(jadx_dir: Path, package_name: str) -> list[Snippet]:
    sources = jadx_dir / "sources"
    if not sources.exists():
        return []

    snippets: list[Snippet] = []
    compiled = [(re.compile(pat, re.MULTILINE), label) for pat, label in _INTERESTING]

    for java_file in sorted(sources.rglob("*.java")):
        if _is_stdlib(java_file, sources):
            continue
        try:
            lines = java_file.read_text(errors="replace").splitlines()
        except OSError:
            continue

        for lineno, line in enumerate(lines, 1):
            for rx, label in compiled:
                if rx.search(line):
                    start = max(0, lineno - 2)
                    ctx = "\n".join(lines[start: lineno + 1])
                    snippets.append(Snippet(
                        file=str(java_file.relative_to(sources)),
                        line=lineno,
                        label=label,
                        context=ctx,
                    ))
                    break  # one label per line is enough

        if len(snippets) > 300:
            break

    return snippets


def _format_apkleaks(r: ToolResult) -> str:
    if not r.ok:
        return f"*APKLeaks failed: {r.error}*"
    findings = r.data.get("findings", {})
    if not findings:
        return "No findings."
    lines = []
    for category, items in findings.items():
        if isinstance(items, list) and items:
            lines.append(f"**{category}** ({len(items)})")
            for item in items[:10]:
                lines.append(f"  - {item}")
            if len(items) > 10:
                lines.append(f"  … and {len(items) - 10} more")
    return "\n".join(lines) or "No meaningful findings."


def _summarize_mobsf(r: dict) -> str:
    parts: list[str] = []

    score = r.get("security_score", "?")
    cvss = r.get("average_cvss", "?")
    parts.append(f"**Score**: {score}/100  |  **CVSS**: {cvss}")

    # Dangerous permissions
    perms = r.get("permissions", {})
    dangerous = [p for p, v in perms.items() if isinstance(v, dict) and v.get("status") == "dangerous"]
    if dangerous:
        parts.append(f"\n**Dangerous permissions** ({len(dangerous)}): " + ", ".join(dangerous[:15]))

    # Manifest issues
    manifest = r.get("manifest_analysis", {})
    issues = manifest.get("manifest_findings", []) if isinstance(manifest, dict) else []
    high_manifest = [i for i in issues if isinstance(i, dict) and i.get("stat") in ("high", "warning")]
    if high_manifest:
        parts.append(f"\n**Manifest issues** (HIGH/WARNING):")
        for i in high_manifest[:10]:
            parts.append(f"  - [{i.get('stat','?').upper()}] {i.get('title','')}: {i.get('desc','')[:120]}")

    # SAST code findings
    code = r.get("code_analysis", {})
    if isinstance(code, dict):
        for sev in ("high", "warning"):
            group = code.get(sev, {})
            items = group.get("findings", []) if isinstance(group, dict) else []
            if items:
                parts.append(f"\n**Code analysis — {sev.upper()}** ({len(items)}):")
                for item in items[:8]:
                    if isinstance(item, dict):
                        parts.append(f"  - {item.get('title', '')} → {str(item.get('files', ''))[:100]}")

    # Network endpoints
    urls = r.get("urls", [])
    if urls:
        parts.append(f"\n**URLs found** ({len(urls)}): " + ", ".join(str(u) for u in urls[:8]))

    # Trackers
    trackers = r.get("trackers", {})
    detected = trackers.get("trackers_count", 0) if isinstance(trackers, dict) else 0
    if detected:
        parts.append(f"\n**Trackers detected**: {detected}")

    return "\n".join(parts)
