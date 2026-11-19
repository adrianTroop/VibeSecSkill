#!/usr/bin/env bash
# vibeSec installer. Idempotent, no sudo.
#
#   ./install.sh               install files beside this script (~/.claude/skills)
#   ./install.sh --project     install those files into ./.claude
#   ./install.sh --uninstall   remove (combine with --project for the project copy)
#
# A checkout installs the files beside this script. It does not clone.
# A piped run of this script clones VIBESEC_REF and requires VIBESEC_SHA.
#   curl -fsSL https://raw.githubusercontent.com/adrianTroop/VibeSecSkill/v1.3.0/install.sh | bash
#   gh api "repos/adrianTroop/VibeSecSkill/contents/install.sh?ref=v1.3.0" -H "Accept: application/vnd.github.raw" | bash
set -euo pipefail

REPO_URL="https://github.com/adrianTroop/VibeSecSkill"
# Default piped revision. Tag v1.3.0 already exists. That commit does not
# record this SHA, so the default is not a pin of the commit that added it.
VIBESEC_REF="${VIBESEC_REF:-v1.3.0}"
VIBESEC_SHA="${VIBESEC_SHA:-c090c9a70adf62949076e2108fbdec2c60fc9541}"
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

content_revision() {
  local file="$1"
  local value
  value="$(sed -n 's/^revision:[[:space:]]*//p' "$file" | head -n 1)"
  if [ -n "$value" ]; then
    printf '%s' "$value"
  else
    printf '%s' "unavailable"
  fi
}

git_revision() {
  local dir="$1"
  if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$dir" rev-parse HEAD
  else
    printf '%s' "unavailable"
  fi
}

# Locate the source files: beside this script, or a shallow clone when piped.
SRC=""
SOURCE_KIND="checkout"
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
  if [[ ! "$VIBESEC_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid VIBESEC_SHA" >&2
    exit 2
  fi
  CLONE_URL="$REPO_URL"
  if [ -n "${VIBESEC_REPO_URL:-}" ]; then
    case "$VIBESEC_REPO_URL" in
      /*)
        if [ ! -d "$VIBESEC_REPO_URL" ]; then
          echo "VIBESEC_REPO_URL is not a local directory" >&2
          exit 2
        fi
        CLONE_URL="$VIBESEC_REPO_URL"
        ;;
      *)
        echo "VIBESEC_REPO_URL must be a local absolute path" >&2
        exit 2
        ;;
    esac
  fi
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  # gh is an optional one-shot credential helper for the public GitHub URL.
  # It is not used for a local path, and it does not change git config.
  if [ "$CLONE_URL" = "$REPO_URL" ] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    git -c "credential.helper=!gh auth git-credential" clone --quiet --depth 1 --branch "$VIBESEC_REF" "$CLONE_URL" "$TMP/vibesec"
  elif [ "$CLONE_URL" = "$REPO_URL" ]; then
    git clone --quiet --depth 1 --branch "$VIBESEC_REF" "$CLONE_URL" "$TMP/vibesec"
  else
    # Local test clones ignore --depth, so omit it and avoid that warning.
    git clone --quiet --branch "$VIBESEC_REF" "$CLONE_URL" "$TMP/vibesec"
  fi
  CLONED_SHA="$(git -C "$TMP/vibesec" rev-parse HEAD)"
  if [ "$CLONED_SHA" != "$VIBESEC_SHA" ]; then
    echo "Cloned revision $CLONED_SHA does not match required $VIBESEC_SHA" >&2
    exit 1
  fi
  SRC="$TMP/vibesec"
  SOURCE_KIND="clone"
fi

[ -f "$SRC/skills/vibesec/SKILL.md" ] || { echo "SKILL.md not found under $SRC" >&2; exit 1; }

mkdir -p "$TARGET/skills"
rm -rf "$SKILL_DST"
rm -f "$LEGACY_CMD"
cp -R "$SRC/skills/vibesec" "$SKILL_DST"

CONTENT_REV="$(content_revision "$SKILL_DST/SKILL.md")"
GIT_REV="$(git_revision "$SRC")"

if [ "$SOURCE_KIND" = "clone" ]; then
  echo "Installed vibeSec from a verified clone:"
  echo "  ref    $VIBESEC_REF"
  echo "  git    $GIT_REV"
else
  echo "Installed vibeSec from the files beside this script."
  echo "This did not clone a release and did not check out the recorded release SHA."
  echo "  git    $GIT_REV"
fi
echo "  content-revision  $CONTENT_REV"
echo "  skill  $SKILL_DST/SKILL.md"
echo "Run it in Claude Code with: /vibesec   (or /vibesec src/ to scope it)"
