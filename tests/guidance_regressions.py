#!/usr/bin/env python3
"""Phrase and rubric checks for the skill text.

A fixture passes when this file's small classifier, or a required phrase, still
matches the rule written in SKILL.md. That is not a running detector, not an
assistant, and not evidence that an audit would find the bug. Installer
boundaries are checked by test.sh. ShellCheck is a separate command.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "vibesec" / "SKILL.md"
README = ROOT / "README.md"
PLUGIN = ROOT / ".claude-plugin" / "plugin.json"
MARKET = ROOT / ".claude-plugin" / "marketplace.json"
INSTALL = ROOT / "install.sh"
CASES = ROOT / "tests" / "fixtures" / "cases.json"

REQUIRED_PHRASES = [
    "49 vulnerability classes",
    "is not access control",
    "does not list every subdomain",
    "passive DNS",
    "Passwordless accounts stay passwordless",
    "Do not require 401",
    "Do not launch the command",
    "That is not proof of malware",
    "not proof the server is malicious",
    "ALTER DEFAULT PRIVILEGES",
    "ADMIN_EMAIL",
    "cookieCache",
    "secondaryStorage",
    "stripeCustomerId",
    "GHSA-fvxx-76fc-893x",
    "GHSA-x8j7-xh58-rv6x",
    "GHSA-9hm7-xhfp-cx58",
    "GHSA-hwq2-v29r-p69r",
    "GHSA-mfr8-8qww-v76h",
    "GHSA-vc7v-qv4w-wrv8",
    "GHSA-rhh4-g77r-r9qj",
    "GHSA-f3mh-rxg3-f5g2",
    "1.7.16",
    "1.8.0-beta.5",
    "16.4.5",
    "15.5.29",
    "16.3.0",
    "x-middleware-set-cookie",
    "AGENTS.md",
    ".mcp.json",
    ".claude/settings.local.json",
    "Needs manual check",
    "rotate first",
    "Refuse an absolute path",
    "directory inside it",
    "that same project root",
    "Do not follow a symlink",
    "operator's HOME",
    "another repository",
    "credential files outside this project root",
]

FORBIDDEN_PHRASES = [
    "48 vulnerability",
    "all @modelcontextprotocol",
    "upgrade to the latest",
    "Upgrade to latest",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def unguarded_secret_literal(src: str) -> bool:
    """True when a fallback literal is not inside the preceding development check."""
    patterns = (
        re.compile(r"""process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*['"]"""),
        re.compile(r"""os\.environ\.get\(\s*['"][A-Z0-9_]+['"]\s*,\s*['"]"""),
    )
    for pattern in patterns:
        for match in pattern.finditer(src):
            window = src[max(0, match.start() - 200) : match.start()]
            if 'NODE_ENV === "development"' not in window:
                return True
    return False


def classify(name: str, src: str) -> str:
    if name.startswith("rate_limit_"):
        joined = bool(re.search(r"""\bip\s*\+\s*['"]\|['"]\s*\+\s*email\b""", src)) or bool(
            re.search(r"""\$\{ip\}\s*\|\s*\$\{email\}""", src)
        ) or bool(re.search(r"""\{ip\}\s*\|\s*\{email\}""", src))
        split = "limitIp" in src and "limitAccount" in src
        if joined and not split:
            return "finding"
        if split and not joined:
            return "ok"
        return "unknown"

    if name.startswith("secret_"):
        literal = bool(
            re.search(r"""process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*['"]""", src)
        ) or bool(
            re.search(r"""os\.environ\.get\(\s*['"][A-Z0-9_]+['"]\s*,\s*['"]""", src)
        )
        dev_guard = 'NODE_ENV === "development"' in src
        fail_closed = "throw new Error" in src and "is required" in src
        if unguarded_secret_literal(src):
            return "finding"
        if fail_closed and (not literal or dev_guard):
            return "ok"
        return "unknown"

    if name.startswith("org_"):
        write = re.search(r"member\.(upsert|create|insert)", src)
        invite = re.search(r"invite\.find", src)
        denies = "status: 403" in src
        if write and invite and write.start() < invite.start():
            return "finding"
        if write and invite and invite.start() < write.start() and denies:
            return "ok"
        return "unknown"

    if name.startswith("admin_email"):
        if "ADMIN_EMAIL" in src and 'role = "admin"' in src:
            return "finding"
        return "unknown"

    if name.startswith("seed_admin"):
        if re.search(r"password\)\s*values\s*\([^)]*'password'", src, re.I):
            return "finding"
        return "unknown"

    if name.startswith("setup_"):
        if "base64 -d" in src and "bash" in src:
            return "finding"
        piped = re.search(r"(?:curl|wget)\b.*\|\s*(?:bash|sh|iex)\b", src)
        if piped:
            pinned = re.search(r"\bv?\d+\.\d+\.\d+\b", src) or re.search(
                r"\b[0-9a-f]{40}\b", src
            )
            return "review" if pinned else "finding"
        return "unknown"

    if name.startswith("mcp_"):
        if "@latest" in src:
            return "review"
        if "@modelcontextprotocol/server-" in src and re.search(r"@\d+\.\d+\.\d+", src):
            return "ok"
        return "unknown"

    if name.startswith("grants_"):
        lowered = src.lower()
        if "using (true)" in lowered and "invoices" in lowered and "to anon" in lowered:
            return "finding"
        if "published = true" in lowered and "posts" in lowered:
            return "ok"
        return "unknown"

    if name.startswith("function_"):
        lowered = src.lower()
        if "security definer" not in lowered:
            return "unknown"
        scoped = "auth.uid()" in lowered and "search_path" in lowered
        if scoped and "to authenticated" in lowered:
            return "ok"
        if "grant execute" in lowered and "to anon" in lowered and not scoped:
            return "finding"
        return "unknown"

    if name.startswith("preview_"):
        if "invoice.findMany" in src and "session" not in src and "getUser" not in src:
            return "finding"
        if "Welcome" in src and "invoice" not in src:
            return "ok"
        return "unknown"

    return "unknown"


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def content_revision(text: str) -> str:
    normalized = re.sub(r"(?m)^revision:.*$", "revision:", text, count=1)
    return hashlib.sha256(normalized.encode()).hexdigest()


def check_recorded_sha(install: str) -> None:
    match = re.search(
        r'^VIBESEC_SHA="\$\{VIBESEC_SHA:-([0-9a-f]{40})\}"',
        install,
        re.M,
    )
    if not match:
        fail("installer is missing a 40-hex VIBESEC_SHA default")
    sha = match.group(1)
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if sha == head:
        fail("VIBESEC_SHA pins the commit that contains the installer")
    kind = subprocess.check_output(
        ["git", "cat-file", "-t", sha], cwd=ROOT, text=True
    ).strip()
    if kind != "commit":
        fail(f"VIBESEC_SHA {sha} is {kind}, expected a commit")
    subprocess.check_call(
        ["git", "merge-base", "--is-ancestor", sha, "HEAD"], cwd=ROOT
    )
    pinned = subprocess.check_output(
        ["git", "show", f"{sha}:install.sh"], cwd=ROOT, text=True
    )
    if f"VIBESEC_SHA:-{sha}" in pinned or f'VIBESEC_SHA="{sha}"' in pinned:
        fail("recorded SHA appears as the pin inside that same commit")
    tag = subprocess.check_output(
        ["git", "rev-parse", "v1.3.0^{commit}"], cwd=ROOT, text=True
    ).strip()
    if tag != sha:
        fail(f"VIBESEC_SHA {sha} is not tag v1.3.0 ({tag})")


def main() -> None:
    skill = SKILL.read_text()
    readme = README.read_text()
    plugin = json.loads(PLUGIN.read_text())
    market = json.loads(MARKET.read_text())
    install = INSTALL.read_text()
    skill_flat = squash(skill)

    for label, text in ("skill", skill), ("readme", readme):
        if "\u2014" in text or "\u2013" in text:
            fail(f"{label} contains an em or en dash")
        for phrase in FORBIDDEN_PHRASES:
            if phrase in text:
                fail(f"{label} contains forbidden phrase: {phrase}")

    headings = [int(n) for n in re.findall(r"^### (\d+)\. ", skill, re.M)]
    if headings != list(range(1, 50)):
        fail(f"skill headings are {headings}, expected 1..49")

    checks = readme.split("## What it checks", 1)[1].split("## Sample report", 1)[0]
    readme_rows = [int(n) for n in re.findall(r"^\| (\d+) \|", checks, re.M)]
    if readme_rows != list(range(1, 50)):
        fail(f"README rows are {readme_rows}, expected 1..49")

    for phrase in REQUIRED_PHRASES:
        if phrase not in skill_flat:
            fail(f"skill is missing: {phrase}")

    if "49 vulnerabilities" not in readme or "49 checks" not in readme:
        fail("README count was not updated")
    if "49 vulnerability classes" not in plugin["description"]:
        fail("plugin.json description count was not updated")
    if plugin.get("version") != "1.3.0":
        fail("plugin version changed; this branch does not cut a release")
    market_description = market["plugins"][0]["description"]
    if "49 vulnerability classes" not in market_description:
        fail("marketplace description count was not updated")
    if 'VIBESEC_REF="${VIBESEC_REF:-v1.3.0}"' not in install:
        fail("installer pin changed; this branch does not cut a release")
    check_recorded_sha(install)
    revision_match = re.search(r"(?m)^revision:\s*([0-9a-f]{64})\s*$", skill)
    if not revision_match:
        fail("skill front matter is missing a content revision")
    if revision_match.group(1) != content_revision(skill):
        fail("skill revision does not match the skill text")

    cases = json.loads(CASES.read_text())
    if len(cases) < 20:
        fail("expected a full fixture set")
    for case in cases:
        got = classify(case["name"], case["body"])
        if got != case["expect"]:
            fail(f"{case['name']}: expected {case['expect']}, got {got}")

    print(f"guidance OK ({len(cases)} fixtures, checks 1-49)")


if __name__ == "__main__":
    main()
