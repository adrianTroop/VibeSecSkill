#!/usr/bin/env bash
# Checkout install, offline clone SHA check, and guidance regressions.
# Disposable directories only. Does not call GitHub.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
here="$(cd "$(dirname "$0")" && pwd)"
lab="$(mktemp -d)"
trap 'rm -rf "$lab"' EXIT

assert_fail() {
  local name="$1"
  shift
  set +e
  "$@" >"$lab/fail-out.txt" 2>&1
  local code=$?
  set -e
  if [ "$code" -eq 0 ]; then
    echo "expected failure: $name" >&2
    cat "$lab/fail-out.txt" >&2
    exit 1
  fi
}

# Checkout install copies the sibling skill and says so.
proj="$lab/project"
mkdir -p "$proj"
(cd "$proj" && bash "$here/install.sh" --project >"$lab/checkout.txt")
test -f "$proj/.claude/skills/vibesec/SKILL.md"
grep -q -F "files beside this script" "$lab/checkout.txt"
grep -q -F "did not clone a release" "$lab/checkout.txt"
grep -q -F "content-revision" "$lab/checkout.txt"
git_head="$(git -C "$here" rev-parse HEAD)"
grep -q -F "$git_head" "$lab/checkout.txt"
rev="$(sed -n 's/^revision:[[:space:]]*//p' "$here/skills/vibesec/SKILL.md" | head -n 1)"
test -n "$rev"
grep -q -F "$rev" "$proj/.claude/skills/vibesec/SKILL.md"
grep -q -F "$rev" "$lab/checkout.txt"
(cd "$proj" && bash "$here/install.sh" --uninstall --project >/dev/null)
test ! -e "$proj/.claude/skills/vibesec"

# A copied tree that is not a git checkout must not invent a commit SHA.
loose="$lab/loose"
mkdir -p "$loose/skills/vibesec" "$lab/loose-home"
cp "$here/install.sh" "$loose/install.sh"
cp "$here/skills/vibesec/SKILL.md" "$loose/skills/vibesec/SKILL.md"
env HOME="$lab/loose-home" bash "$loose/install.sh" >"$lab/loose.txt"
grep -q -F "files beside this script" "$lab/loose.txt"
grep -q -F "git    unavailable" "$lab/loose.txt"
grep -q -F "$rev" "$lab/loose.txt"

# Offline clone. VIBESEC_REPO_URL is a local directory, never a remote URL.
origin="$lab/origin"
mkdir -p "$origin/skills/vibesec"
printf '%s\n' '---' 'name: vibesec' 'revision: fixture' '---' '# local-fixture' > "$origin/skills/vibesec/SKILL.md"
git -C "$origin" init -q
git -C "$origin" config user.email "vibe-test@example.com"
git -C "$origin" config user.name "vibe-test"
git -C "$origin" add skills/vibesec/SKILL.md
git -C "$origin" commit -q -m fixture
sha="$(git -C "$origin" rev-parse HEAD)"
git -C "$origin" branch -q release-pin
runner="$lab/runner"
mkdir -p "$runner" "$lab/clone-home"
cp "$here/install.sh" "$runner/install.sh"
env HOME="$lab/clone-home" VIBESEC_REPO_URL="$origin" VIBESEC_REF=release-pin VIBESEC_SHA="$sha" \
  bash "$runner/install.sh" >"$lab/clone.txt"
grep -q -F "verified clone" "$lab/clone.txt"
grep -q -F "$sha" "$lab/clone.txt"
grep -q -F "local-fixture" "$lab/clone-home/.claude/skills/vibesec/SKILL.md"

mkdir -p "$lab/bad-home"
assert_fail sha-mismatch env HOME="$lab/bad-home" VIBESEC_REPO_URL="$origin" VIBESEC_REF=release-pin \
  VIBESEC_SHA=0123456789abcdef0123456789abcdef01234567 bash "$runner/install.sh"
test ! -e "$lab/bad-home/.claude/skills/vibesec/SKILL.md"

assert_fail remote-repo-url env HOME="$lab/clone-home" VIBESEC_REPO_URL="https://example.invalid/repo" \
  VIBESEC_SHA="$sha" bash "$runner/install.sh"
grep -q -F "local absolute path" "$lab/fail-out.txt"

python3 "$here/tests/guidance_regressions.py"
echo "OK"
