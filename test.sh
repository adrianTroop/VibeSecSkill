#!/usr/bin/env bash
# Installer self-check: install into a temp dir, assert the files, uninstall, assert gone.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
cd "$d"
bash "$here/install.sh" --project >/dev/null
test -f .claude/skills/vibesec/SKILL.md
bash "$here/install.sh" --uninstall --project >/dev/null
test ! -e .claude/skills/vibesec
echo "OK"
