#!/usr/bin/env python3
"""Regression checks for vibeSec guidance.

Confirms the skill, README, and plugin stay in sync, and that small fixtures
match the version rules written in the skill. These fixtures are guidance
validation. This file is not a security scanner and does not install, download,
or execute packages.
"""

import json
import re
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
    "PYSEC-2026-4388",
    "agent-framework",
    "1.26.1",
    "1.26.2",
    "1.26.0",
    "GHSA-5jgj-4vhf-8v76",
    "4.1.26",
    "2.17.18",
    "@clerk/astro",
    "clerkMiddleware",
    "will not receive a patch",
    "newest safe release forever",
    "It does not change these rules",
    "agent_framework",
    "agent-framework-client",
    "npm:@clerk/astro@4.1.25",
    "One text-only page does not make the package Safe",
    "GHSA-f82v-jwr5-mffw",
    "does not name a patched 11.x release",
    "1.20.10",
    "GHSA-jhv4-f7mr-xx76",
    "GHSA-2xp3-57p7-qf4v",
    "GHSA-9v8j-x534-2fx3",
    "1.18.1",
]

FORBIDDEN_PHRASES = [
    "48 vulnerability",
    "all @modelcontextprotocol",
    "upgrade to the latest",
    "Upgrade to latest",
    "webhook.site",
    "11.1.4 to 15.2.2",
    "Vulnerable before: Node",
    "nginx 1.25.3",
    "ruby-saml` before 1.18.0",
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def classify(name: str, src: str) -> str:
    if name.startswith("rate_limit_"):
        joined = bool(re.search(r"""\bip\s*\+\s*['"]\|['"]\s*\+\s*email\b""", src))
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
        if literal and not dev_guard:
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
        if re.search(r"curl\b.*\|\s*bash", src):
            return "review"
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

    # Guidance validation for check 46. Not a dependency scanner.
    if name.startswith("pkg_agent_"):
        return agent_framework_status(src)
    if name.startswith("pkg_clerk_"):
        return clerk_astro_status(src)

    return "unknown"


def version_tuple(spec: str):
    base = spec.split("-", 1)[0].split("+", 1)[0]
    parts = base.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def agent_framework_status(src: str) -> str:
    """Rubric for the PyPI name rules in check 46. Not a package installer."""
    bad = False
    other = False
    named = False
    pin = re.compile(
        r"(?im)^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*(\d+\.\d+\.\d+)\s*$"
    )
    for match in pin.finditer(src):
        if normalize_pypi(match.group(1)) != "agent-framework":
            continue
        named = True
        if match.group(2) in {"1.26.1", "1.26.2"}:
            bad = True
        else:
            other = True
    lock = re.compile(
        r'(?is)name\s*=\s*"([^"]+)"\s+version\s*=\s*"(\d+\.\d+\.\d+)"'
    )
    for match in lock.finditer(src):
        if normalize_pypi(match.group(1)) != "agent-framework":
            continue
        named = True
        if match.group(2) in {"1.26.1", "1.26.2"}:
            bad = True
        else:
            other = True
    if bad:
        return "finding"
    if other:
        return "ok"
    if named or re.search(r"(?i)(?<![A-Za-z0-9])agent[-_.]+framework(?![-_.A-Za-z0-9])", src):
        return "unknown"
    return "ok"


def clerk_affected(spec: str):
    """Published ranges: <2.17.18, and >=3.0.0 <4.1.26. Prereleases are unknown."""
    if "-" in spec or "+" in spec:
        return None
    version = version_tuple(spec)
    if version is None:
        return None
    if version < (2, 17, 18):
        return True
    if (3, 0, 0) <= version < (4, 1, 26):
        return True
    return False


def clerk_astro_status(src: str) -> str:
    if "@clerk/astro" not in src:
        return "ok"
    resolved = re.findall(r"@clerk/astro@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)", src)
    if not resolved:
        return "unknown"
    affected = [clerk_affected(version) for version in resolved]
    if any(item is None for item in affected):
        return "unknown"
    in_range = any(affected)
    if not in_range:
        return "ok"
    uses_middleware = "clerkMiddleware" in src
    attribute = bool(re.search(r"\b(?:value|content|alt|title)=", src))
    text_only = "TEXT_CONTENT_ONLY" in src and not attribute
    if uses_middleware and attribute:
        return "finding"
    # One text-only page does not clear an in-range package.
    if uses_middleware and text_only:
        return "unknown"
    return "unknown"


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text)


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
