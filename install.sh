#!/usr/bin/env bash
# vibeSec installer. Idempotent, no sudo.
#
#   ./install.sh               install for all projects (~/.claude/skills)
#   ./install.sh --project     install into ./.claude of the current repo only
#   ./install.sh --uninstall   remove (combine with --project for the project copy)
#
# Piped from GitHub, it clones tag v1.3.0 (override with VIBESEC_REF):
#   curl -fsSL https://raw.githubusercontent.com/adrianTroop/VibeSecSkill/v1.3.0/install.sh | bash
#   gh api "repos/adrianTroop/VibeSecSkill/contents/install.sh?ref=v1.3.0" -H "Accept: application/vnd.github.raw" | bash
set -euo pipefail

REPO_URL="https://github.com/adrianTroop/VibeSecSkill"
# Pinned checkout for piped installs. Override for another tag or branch.
VIBESEC_REF="${VIBESEC_REF:-v1.3.0}"
MODE="user"
UNINSTALL=0

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || true
  echo "Usage: install.sh [--project] [--uninstall] [--help]"
}

for arg in "$@"; do
  case "$arg" in
    --project) MODE="project" ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

if [ "$MODE" = "project" ]; then
  TARGET="$(pwd)/.claude"
else
  TARGET="${HOME}/.claude"
fi

SKILL_DST="$TARGET/skills/vibesec"
LEGACY_CMD="$TARGET/commands/vibeSec.md"  # shipped by v1.0.0, now part of the skill

if [ "$UNINSTALL" = "1" ]; then
  rm -rf "$SKILL_DST"
  rm -f "$LEGACY_CMD"
  echo "Removed vibeSec from $TARGET"
  exit 0
fi

# Locate the source files: beside this script, or a shallow clone of VIBESEC_REF when piped.
SRC=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/skills/vibesec/SKILL.md" ]; then
  SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  command -v git >/dev/null 2>&1 || { echo "git is required to fetch vibeSec" >&2; exit 1; }
  case "$VIBESEC_REF" in
    ""|-*|*[!A-Za-z0-9._/-]*)
      echo "Invalid VIBESEC_REF" >&2
      exit 2
      ;;
  esac
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  # gh is an optional one-shot credential helper. It does not change git config.
  # Plain git clone is enough for this public repo.
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    git -c "credential.helper=!gh auth git-credential" clone --quiet --depth 1 --branch "$VIBESEC_REF" "$REPO_URL" "$TMP/vibesec"
  else
    git clone --quiet --depth 1 --branch "$VIBESEC_REF" "$REPO_URL" "$TMP/vibesec"
  fi
  SRC="$TMP/vibesec"
fi

[ -f "$SRC/skills/vibesec/SKILL.md" ] || { echo "SKILL.md not found under $SRC" >&2; exit 1; }

mkdir -p "$TARGET/skills"
rm -rf "$SKILL_DST"
rm -f "$LEGACY_CMD"
cp -R "$SRC/skills/vibesec" "$SKILL_DST"

echo "Installed vibeSec:"
echo "  skill  $SKILL_DST/SKILL.md"
echo "Run it in Claude Code with: /vibesec   (or /vibesec src/ to scope it)"
