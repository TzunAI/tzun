#!/usr/bin/env bash
# Self-tests for scripts/check-public-hygiene.sh and .githooks/commit-msg:
# text each rule must catch, text no rule may catch, and each of the three
# modes and the hook run against a scratch repository.
#
# Every string that must be caught is assembled at run time from pieces, so
# this file passes the check it tests.
set -euo pipefail
cd "$(dirname "$0")/.."

guard="$PWD/scripts/check-public-hygiene.sh"
hook="$PWD/.githooks/commit-msg"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
count=0

# The pieces.
org=TzunAI
lc_org=tzunai
t=tzun
T=TZUN
tz=tzun.ai
ai=claude.ai
tmp=tmp
home=home
mnt=mnt
root=root
req=REQ
w=widgets
ref="${w}#9"
# The project that builds spec.tzun.ai.
sp="$t-spec"
# The line Dependabot signs off its commits with, GitHub's support address
# on its own, and Dependabot as a commit's author.
signoff="Signed-off-by: dependabot[bot] <support@""github.com>"
support="support@""github.com"
dependabot='dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>'

check_text() { # check_text <text>: the guard's text mode on <text>; sets out and rc
  rc=0
  out="$(printf '%s\n' "$1" | "$guard" text case 2>/dev/null)" || rc=$?
}

catches() { # catches <rule> <text>
  count=$((count + 1))
  check_text "$2"
  if [[ "$rc" -ne 1 ]]; then
    echo "FAIL [$1] exit $rc, want 1: $2"
    fail=1
  elif ! grep -q ": $1: " <<<"$out"; then
    echo "FAIL [$1] not reported for: $2"
    echo "     got: $out"
    fail=1
  fi
}

passes() { # passes <text>
  count=$((count + 1))
  check_text "$1"
  if [[ "$rc" -ne 0 ]]; then
    echo "FAIL flagged (exit $rc): $1"
    echo "     got: $out"
    fail=1
  fi
}

# Text every rule must catch.
catches org-repo "see $org/widgets for the code"
catches org-repo "https://github.com/$org/widgets/pull/3"
catches org-repo "git@github.com:$org/widgets.git"
catches org-repo "npm install @$lc_org/widgets"
# The repository that builds spec.tzun.ai, which a reader outside Tzun cannot
# open, in each form; its bare name passes (below).
catches org-repo "see $org/$sp for the source"
catches org-repo "https://github.com/$org/$sp/blob/main/README.md"
catches org-repo "git@github.com:$org/$sp.git"
catches org-repo "https://github.com/${lc_org}/${T}-SPEC/pull/14"
catches org-repo "- Senders follow the rules ($org/${sp}#14)."
catches cross-ref "as ${sp}#3 says"
catches prefixed-name "the $t-widgets repository"
catches prefixed-name "the T""zun-widgets service"
# Full-width letters read as ASCII once normalized.
catches prefixed-name "the "$'\xef\xbd\x94\xef\xbd\x9a\xef\xbd\x95\xef\xbd\x8e'"-widgets repository"
catches cross-ref "fixed in ${w}#12"
catches cross-ref "(see gad${w:3}#3 and more)"
catches session "https://$ai/code/abc"
catches session "https://$ai/chat/abc"
catches local-path "written to /$tmp/build/out"
catches local-path "cloned in /$home/someone/src"
catches local-path "mounted at /$mnt/cache"
catches local-path "built in /$root/work"
catches local-path "cd ~/rep""os/widgets"
catches local-path 'C:\Us''ers\someone\src'
catches email "ask someone@""widgets.io"
catches email "Signed-off-by: A Person <a.person@""gmail.com>"
catches email "mail x@""notexample.com"
# Dependabot's sign-off is refused in text mode, which the commit hook and
# the pull request check use; only commits mode allows it (below).
catches email "$signoff"
catches email "write to $support"
catches host "https://console.$tz/login"
catches host "https://a.b.console.$tz/"
catches requirement "meets $req-ZZ-99"
catches requirement "tracked as $req-AB-01 in the plan"
catches private-status "this repository is still pri""vate"
# A phrase wrapped across two lines of a paragraph.
catches private-status "the widgets live in the repo that is not public; the repo is"$'\n'"pri""vate for now"

# Text no rule may catch.
passes "github.com/$org/tzun-verify/internal/report"
passes "https://github.com/$org/$t and https://github.com/$org/$t.git"
passes "npm install @$t/sdk @$t/engine; pip install $t-sdk; import $t""_sdk"
passes "export $T""_TSA_URL=1 and the $t""_envelopes table"
passes "$t-mandate/1, $t-agent/2, $t-assertion-v1, $t-cmt-salt-v1 and the Tzun-Signature header"
passes "x-$t-api-key, x-$t-admin-token, @$t-omit-when-unset, @$t-hashed-fields, $t-test-active-chain-"
passes "security@$tz, hello@$tz and oss@$tz; https://api.$tz/v1"
passes "see ${t}#12 and ${t}-verify#3"
passes "the $sp project builds spec.$tz"
passes "https://github.com/$org/tzun-verify.git"
passes "Merge pull request #5 from $org/feat/corpus"
passes "an anchor under $t-anchor/1 and a $t-verify-report/1 report"
passes "the $t-signoff-v1 and $t-decision-v1 domains; $t-merkle-vector-3"
passes "$org is the organisation; Tzun-specific terms are fine"
passes "see tzun-verify#12"
passes "Merge pull request #7; step #3; (#12)"
passes "Co-Authored-By: A Bot <noreply@anthropic.com>"
passes "123+someone@users.noreply.github.com and ops@example.com and a@b.test"
passes "git@github.com"
passes "$tz, demo.$tz, log.$tz, test.log.$tz, staging.log.$tz"
passes "https://spec.$tz/record/1.0/ and Record §3.2"
passes "session_signoff_not_expected and statementDigest"
passes "mktemp -d; /usr/bin/env; ./tmp/x; golang.org/x/mod@v0.41.0; /var/lib"
passes "a private key signs; the repository keeps it out"
passes "the first line"$'\n'"and the second line"
# What Dependabot writes in a pull request: the upstream project's issues as
# owner/name#N or a linked bare #N, a package@version, the compatibility
# score badge, its commands.
passes "made their first contribution in <a href=\"https://redirect.github.com/jestjs/jest/pull/16345\">jestjs/jest#16345</a> (<a href=\"https://redirect.github.com/pypa/hatch/issues/2426\">#2426</a>)"
passes "<h2>pg@8.23.0</h2> and update to typescript@5.2; Update hatch requirement from >=1.12 to >=1.18.1 in /python"
passes "[![Dependabot compatibility score](https://dependabot-badges.githubapp.com/badges/compatibility_score?dependency-name=pkijs&package-manager=npm_and_yarn&previous-version=3.4.0&new-version=3.4.1)](https://docs.github.com/en/github/managing-security-vulnerabilities/about-dependabot-security-updates#about-compatibility-scores)"
passes "- \`@dependabot rebase\` will rebase this PR"

# The three modes and the hook, in a scratch repository holding the guard,
# the hook and this file.
repo="$work/repo"
git init -q "$repo"
mkdir -p "$repo/scripts" "$repo/.githooks"
cp "$guard" "$PWD/scripts/test-public-hygiene.sh" "$repo/scripts/"
cp "$hook" "$repo/.githooks/"
g() { git -C "$repo" -c user.name=test -c user.email=test@example.com -c core.hooksPath=/dev/null "$@"; }
printf 'clean text\n' > "$repo/notes.txt"
g add -A
g commit -q -m "Add the notes"
first="$(g rev-parse HEAD)"
g commit -q --allow-empty -m "Follow up" -m "As discussed in ${w}#4."
second="$(g rev-parse HEAD)"

expect() { # expect <want exit> <what> <command...>
  local want="$1" what="$2" got=0
  shift 2
  count=$((count + 1))
  "$@" > "$work/out" 2>&1 || got=$?
  if [[ "$got" -ne "$want" ]]; then
    echo "FAIL $what: exit $got, want $want"
    sed 's/^/     /' "$work/out"
    fail=1
  fi
}

expect 0 "tree mode, a clean tree holding the guard and its tests" "$repo/scripts/check-public-hygiene.sh" tree
expect 0 "commits mode, a clean commit" "$repo/scripts/check-public-hygiene.sh" commits "$first"
expect 1 "commits mode, a range with a cross-reference" "$repo/scripts/check-public-hygiene.sh" commits "$first..$second"
expect 2 "commits mode, no range" "$repo/scripts/check-public-hygiene.sh" commits
expect 2 "an unknown mode" "$repo/scripts/check-public-hygiene.sh" everything
printf 'see /%s/x\n' "$tmp" > "$repo/leak.txt"
g add leak.txt
expect 1 "tree mode, a tracked file with a local path" "$repo/scripts/check-public-hygiene.sh" tree
rm "$repo/leak.txt"
g rm -q --cached leak.txt
# Tree mode allows Dependabot's sign-off line nowhere.
printf '%s\n' "$signoff" > "$repo/signoff.txt"
g add signoff.txt
expect 1 "tree mode, Dependabot's sign-off in a tracked file" "$repo/scripts/check-public-hygiene.sh" tree
rm "$repo/signoff.txt"
g rm -q --cached signoff.txt
printf '## [1.0.0]\n\n- Fixed the parser (#%s).\n' 4 > "$repo/CHANGELOG.md"
g add CHANGELOG.md
expect 1 "tree mode, a bare #N in CHANGELOG.md" "$repo/scripts/check-public-hygiene.sh" tree
printf '## [1.0.0]\n\n- Fixed the parser (%s/%s#%s).\n' "$org" "$sp" 4 > "$repo/CHANGELOG.md"
g add CHANGELOG.md
expect 1 "tree mode, an owner/repo#N in CHANGELOG.md naming the source of spec.$tz" "$repo/scripts/check-public-hygiene.sh" tree
printf '## [1.0.0]\n\n- Fixed the parser (%s/%s#%s).\n' "$org" "$t" 4 > "$repo/CHANGELOG.md"
g add CHANGELOG.md
expect 0 "tree mode, an owner/repo#N in CHANGELOG.md" "$repo/scripts/check-public-hygiene.sh" tree
printf 'introduced in commit %s\n' "${first:0:12}" > "$repo/history.txt"
g add history.txt
expect 0 "tree mode, a commit of this repository" "$repo/scripts/check-public-hygiene.sh" tree
printf 'introduced in commit %s\n' 0123abc4567d > "$repo/history.txt"
g add history.txt
expect 1 "tree mode, a commit this repository does not have" "$repo/scripts/check-public-hygiene.sh" tree
g rm -q -f history.txt CHANGELOG.md

# Dependabot's sign-off line, in commits mode: allowed, exactly, in a commit
# Dependabot authored, and refused anywhere else.
bot_body="Bumps [pkijs](https://github.com/PeculiarVentures/PKI.js) from 3.4.0 to 3.4.1.
- [Release notes](https://github.com/PeculiarVentures/PKI.js/releases)
- [Commits](https://github.com/PeculiarVentures/PKI.js/compare/v3.4.0...v3.4.1)

---
updated-dependencies:
- dependency-name: pkijs
  dependency-version: 3.4.1
  dependency-type: direct:production
  update-type: version-update:semver-patch
..."
commit_as() { # commit_as <author> <body> <sign-off line>: an empty commit; prints its id
  g commit -q --allow-empty --author="$1" -m "Bump pkijs from 3.4.0 to 3.4.1" -m "$2" -m "$3"
  g rev-parse HEAD
}
c="$(commit_as "$dependabot" "$bot_body" "$signoff")"
expect 0 "commits mode, Dependabot's sign-off in a commit Dependabot authored" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "test <test@example.com>" "$bot_body" "$signoff")"
expect 1 "commits mode, Dependabot's sign-off in a commit someone else authored" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "dependabot[bot] <test@example.com>" "$bot_body" "$signoff")"
expect 1 "commits mode, Dependabot's sign-off with Dependabot's name but another address" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "someone <49699333+dependabot[bot]@users.noreply.github.com>" "$bot_body" "$signoff")"
expect 1 "commits mode, Dependabot's sign-off with Dependabot's address but another name" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "$dependabot" "Questions go to $support." "$signoff")"
expect 1 "commits mode, GitHub's support address outside the sign-off, Dependabot the author" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "$dependabot" "$bot_body" "$signoff and more")"
expect 1 "commits mode, the sign-off line with more text, Dependabot the author" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "$dependabot" "$bot_body" "someone@""widgets.io $signoff")"
expect 1 "commits mode, an address before the sign-off on its line, Dependabot the author" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"
c="$(commit_as "$dependabot" "As discussed in ${w}#4." "$signoff")"
expect 1 "commits mode, a cross-reference beside the sign-off, Dependabot the author" "$repo/scripts/check-public-hygiene.sh" commits "$c^!"

msg="$work/COMMIT_EDITMSG"
# A comment line is checked too: git keeps comment lines in a message made
# with --cleanup=verbatim or --cleanup=whitespace.
printf 'Fix the parser\n\n# %s is only a comment\n' "$ref" > "$msg"
expect 1 "hook, a leak in a comment line" bash -c 'cd "$1" && .githooks/commit-msg "$2"' _ "$repo" "$msg"
printf 'Fix the parser\n\nSee %s.\n' "$ref" > "$msg"
expect 1 "hook, a leak in the body" bash -c 'cd "$1" && .githooks/commit-msg "$2"' _ "$repo" "$msg"
printf 'Fix the parser\n# ------------------------ >8 ------------------------\ndiff: %s\n' "$ref" > "$msg"
expect 0 "hook, a leak below the scissors line" bash -c 'cd "$1" && .githooks/commit-msg "$2"' _ "$repo" "$msg"
printf 'Bump pkijs from 3.4.0 to 3.4.1\n\n%s\n' "$signoff" > "$msg"
expect 1 "hook, Dependabot's sign-off" bash -c 'cd "$1" && .githooks/commit-msg "$2"' _ "$repo" "$msg"

if [[ "$fail" -ne 0 ]]; then
  echo "public hygiene self-tests: FAIL"
  exit 1
fi
echo "public hygiene self-tests: $count cases OK"
