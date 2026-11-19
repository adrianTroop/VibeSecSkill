#!/usr/bin/env bash
# Installer behavior plus guidance regressions. Uses disposable directories only.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lab="$(mktemp -d)"
trap 'rm -rf "$lab"' EXIT

assert_fail() {
  local name="$1"
  shift
  set +e
  "$@" >/tmp/vibesec-test-out 2>&1
  local code=$?
  set -e
  if [ "$code" -eq 0 ]; then
    echo "expected failure: $name" >&2
    cat /tmp/vibesec-test-out >&2
    exit 1
  fi
}

# Happy path: spaces in the path, second install, sibling file kept, uninstall.
proj="$lab/my project"
mkdir -p "$proj/.claude/skills/other-skill"
echo keep > "$proj/.claude/skills/other-skill/keep.txt"
(cd "$proj" && bash "$here/install.sh" --project >/dev/null)
(cd "$proj" && bash "$here/install.sh" --project >/dev/null)
test -f "$proj/.claude/skills/vibesec/SKILL.md"
test -f "$proj/.claude/skills/other-skill/keep.txt"
(cd "$proj" && bash "$here/install.sh" --uninstall --project >/dev/null)
test ! -e "$proj/.claude/skills/vibesec"
test -f "$proj/.claude/skills/other-skill/keep.txt"

# A .claude symlink must not receive the skill outside the project.
outside="$lab/outside"
mkdir -p "$outside"
echo marker > "$outside/marker"
proj_link="$lab/link-parent"
mkdir -p "$proj_link"
ln -s "$outside" "$proj_link/.claude"
assert_fail symlink-parent bash -c "cd \"$proj_link\" && bash \"$here/install.sh\" --project"
test ! -e "$outside/skills/vibesec/SKILL.md"
test -f "$outside/marker"

# A symlinked skills directory is the same class of escape.
skills_out="$lab/skills-out"
mkdir -p "$skills_out" "$lab/link-skills/.claude"
ln -s "$skills_out" "$lab/link-skills/.claude/skills"
assert_fail symlink-skills bash -c "cd \"$lab/link-skills\" && bash \"$here/install.sh\" --project"
test ! -e "$skills_out/vibesec/SKILL.md"

# Uninstall must not delete the target of a symlinked skill directory.
victim="$lab/victim"
mkdir -p "$victim" "$lab/link-leaf/.claude/skills"
echo keep > "$victim/keep.txt"
ln -s "$victim" "$lab/link-leaf/.claude/skills/vibesec"
assert_fail symlink-leaf bash -c "cd \"$lab/link-leaf\" && bash \"$here/install.sh\" --uninstall --project"
test -f "$victim/keep.txt"
test -L "$lab/link-leaf/.claude/skills/vibesec"

# User install stays inside a fake HOME and keeps neighboring files.
home="$lab/home space"
mkdir -p "$home"
env HOME="$home" bash "$here/install.sh" >/dev/null
env HOME="$home" bash "$here/install.sh" >/dev/null
test -f "$home/.claude/skills/vibesec/SKILL.md"
echo other > "$home/.claude/skills/other.txt"
env HOME="$home" bash "$here/install.sh" --uninstall >/dev/null
test ! -e "$home/.claude/skills/vibesec"
test -f "$home/.claude/skills/other.txt"
rm -rf "$home/.claude"
ln -s "$outside" "$home/.claude"
assert_fail symlink-home env HOME="$home" bash "$here/install.sh"
test ! -e "$outside/skills/vibesec/SKILL.md"

bash -n "$here/install.sh"
bash -n "$here/test.sh"
python3 "$here/tests/guidance_regressions.py"
echo "OK"
