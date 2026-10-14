#!/usr/bin/env bash
# Public hygiene: this repository, its history and its pull requests say
# nothing a reader outside Tzun cannot follow. Every reference is to this
# repository or to a public place, the specification at spec.tzun.ai among them.
#
#   scripts/check-public-hygiene.sh tree              every file git tracks or would add (untracked
#                                                     and not ignored), as in the working tree
#   scripts/check-public-hygiene.sh commits <range>   the message of every commit in <range>
#                                                     (anything `git rev-list` takes: a..b, a single commit, --all)
#   scripts/check-public-hygiene.sh text [<label>]    the text on standard input (a pull
#                                                     request's title and body, a commit message)
#
# Each finding prints as "<where>:<line>: <rule>: <text found>". Exit status:
# 0 when nothing is found, 1 when something is, 2 on a usage error.
#
# Text is read after Unicode NFKC normalization, so a look-alike character
# does not hide a match. Each line is checked on its own, and each paragraph
# once more with its line breaks folded into spaces, so a phrase wrapped
# across lines is found too.
#
# The rules, each a pattern and the exceptions it allows:
#   org-repo       a repository of the TzunAI organisation other than this
#                  one (tzun), tzun-verify and tzun-spec, as owner/name, a
#                  GitHub URL or an npm scope (the organisation's own scope
#                  included). The
#                  branch named by a GitHub merge commit's first line ("Merge
#                  pull request #N from <owner>/<branch>") is not a repository.
#   prefixed-name  a tzun-<word> whose first word is not one of the protocol,
#                  package and file names in PUBLIC_WORDS below. TZUN_<WORD>
#                  environment variables and tzun_<word> identifiers are this
#                  SDK's public API and are not checked.
#   cross-ref      <name>#<number>, an issue or pull request of another
#                  repository; tzun#, tzun-verify# and tzun-spec#<number> are
#                  allowed.
#   session        a link to a conversation with an assistant.
#   local-path     an absolute path under a home, temporary, mount or root
#                  directory, on any operating system.
#   email          an email address, except a noreply address, one at a
#                  domain reserved for examples, or one of the role addresses
#                  in PUBLIC_EMAILS below. In commits mode, a commit whose
#                  author is Dependabot may also hold the line Dependabot
#                  signs off with (DEPENDABOT_SIGNOFF below), exactly. The
#                  author is as the commit states it, not verified.
#   host           a subdomain of tzun.ai other than the ones in PUBLIC_HOSTS
#                  below.
#   requirement    a requirement id (REQ-...). The specification states none.
#   private-status wording that calls this or another repository private.
#   changelog-ref  a bare #<number> in CHANGELOG.md. Its sections become
#                  GitHub Release bodies, where #<number> is a live link: cite
#                  TzunAI/tzun#<number> or the full URL.
#   commit-ref     a commit id cited after "commit" or "cited as" that is not
#                  a commit of this repository (tree mode).
#
# Binary files (any NUL byte) are skipped. A file that must hold one of these
# strings on purpose has no exemption here: the fix is to reword it.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  sed -n '6,12p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

mode="${1:-}"
case "$mode" in
  tree) [[ $# -eq 1 ]] || usage ;;
  commits) [[ $# -eq 2 ]] || usage ;;
  text) [[ $# -le 2 ]] || usage ;;
  *) usage ;;
esac

# The program reads its own input on standard input in text mode, so it is
# passed with -c rather than as a here-document.
IFS= read -r -d '' program <<'PY' || true
import os
import re
import subprocess
import sys
import unicodedata

# First words of tzun-<word> names that the public protocol, the packages and
# this repository use: tzun-anchor/1, tzun-verify and its report, the
# tzun-signoff-v1 and tzun-decision-v1 challenge domains, the
# tzun-merkle-vector- leaf label of the tree vectors, the tzun-spec
# repository that builds spec.tzun.ai, the tzun-recovery protocol string, the
# PyPI distribution tzun-sdk and its exporter id, the tzun-engine and
# tzun-xsdk test labels, the @tzun-canonical-* and @tzun-hashed-fields
# annotations, @tzun-omit-when-unset, the x-tzun-api-key and
# x-tzun-admin-token headers, the tzun-attestation revision actor, the
# tzun-py-default system id, the anvil container labels, the example
# client's package name, prose compounds (Tzun-specific, Tzun-origin, ...),
# and tzun-test-* temporary-directory prefixes. A versioned protocol id
# (tzun-<name>/<n> or tzun-<name>-v<n>) and an HTTP header name
# (Tzun-Signature) are public by construction and always allowed.
PUBLIC_WORDS = {"anchor", "verify", "spec", "signoff", "decision", "merkle", "recovery",
                "sdk", "engine", "test", "tests", "xsdk", "canonical", "hashed", "omit",
                "api", "admin", "attestation", "py", "anvil", "example", "corpus",
                "checkpoint", "events", "alerts", "pgdata", "trust", "review",
                "origin", "specific", "instance", "maintained", "wired"}
VERSIONED_ID = re.compile(r"[Tt]zun-[A-Za-z0-9-]+(?:/[0-9]+|-v[0-9]+)")
HEADER_NAME = re.compile(r"Tzun-[A-Z][a-z]*(?:-[A-Z][a-z]*)*(?![A-Za-z0-9-])")

# Role addresses that deliver to the maintainers.
PUBLIC_EMAILS = {"security@tzun.ai", "hello@tzun.ai", "oss@tzun.ai", "licensing@tzun.ai",
                 "conduct@tzun.ai", "support@tzun.ai"}

# Domains reserved for examples and tests (RFC 2606, RFC 6761): an address
# there belongs to no one.
EXAMPLE_DOMAINS = ("example.com", "example.net", "example.org")
EXAMPLE_TLDS = (".example", ".test", ".invalid", ".localhost")

# Subdomains of tzun.ai that are public or appear in the data model and its
# test vectors, by the label just left of tzun.ai: spec is where the
# specification is published.
PUBLIC_HOSTS = {"www", "demo", "spec", "log", "test", "xlog", "api"}

# Dependabot signs off every commit it makes with GitHub's support address.
# That one line, exactly, is allowed in a commit whose author is Dependabot,
# by name and address, and refused everywhere else: in any other commit, in
# text mode, which the commit hook and the pull request check use, and in
# the tree. A commit's author fields are whatever the commit states, so any
# commit can claim to be Dependabot's; the condition only narrows where the
# line is accepted. What makes the allowance safe is what it admits: one
# fixed line holding GitHub's public support address, with every other rule
# still applied to the rest of the message. The address is written in two
# pieces so that this file passes tree mode.
DEPENDABOT_AUTHOR = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")
DEPENDABOT_SIGNOFF = "Signed-off-by: dependabot[bot] <support" + "@github.com>"

PUBLIC_REPOS = {"tzun", "tzun-verify", "tzun-spec"}


MERGE_LINE = re.compile(r"^Merge pull request #[0-9]+ from ")


def allow_org_repo(m, line, author):
    if m.group(0).startswith("@"):
        return False
    name = m.group(1).lower()
    if name.removesuffix(".git") in PUBLIC_REPOS:
        return True
    # The branch a GitHub merge commit names, not a repository.
    lead = MERGE_LINE.match(line)
    return bool(lead) and m.start() == lead.end()


def allow_prefixed_name(m, line, author):
    if m.group(1).lower() in PUBLIC_WORDS:
        return True
    return bool(VERSIONED_ID.match(line, m.start()) or HEADER_NAME.match(line, m.start()))


def allow_cross_ref(m, line, author):
    return m.group(1).lower() in PUBLIC_REPOS


def allow_email(m, line, author):
    local, _, domain = m.group(0).lower().partition("@")
    if m.group(0).lower() in PUBLIC_EMAILS:
        return True
    if author == DEPENDABOT_AUTHOR and line == DEPENDABOT_SIGNOFF:
        return True
    if local in ("noreply", "no-reply") or domain.endswith("users.noreply.github.com"):
        return True
    if domain in EXAMPLE_DOMAINS or domain.endswith(tuple("." + d for d in EXAMPLE_DOMAINS)) or domain.endswith(EXAMPLE_TLDS):
        return True
    return m.group(0).lower() == "git@github.com"


def allow_host(m, line, author):
    return m.group("label").lower() in PUBLIC_HOSTS


RULES = [
    ("org-repo", re.compile(r"(?i)(?:github\.com[/:]|@)?tzunai/([a-z0-9._-]+)"), allow_org_repo),
    ("prefixed-name", re.compile(r"(?<![A-Za-z0-9])[Tt]zun-([A-Za-z0-9]+)"), allow_prefixed_name),
    ("cross-ref", re.compile(r"(?<![A-Za-z0-9_./#-])([A-Za-z][A-Za-z0-9._-]*)#[0-9]+(?![0-9])"), allow_cross_ref),
    ("session", re.compile(r"(?i)claude\.ai/(?:code|chat|share|project)"), None),
    ("local-path", re.compile(
        r"(?<![A-Za-z0-9_.~-])/(?:tmp|home|mnt|root|Users|private/var|var/folders)/"
        r"|~/rep[o]s/|(?<![A-Za-z0-9])[A-Za-z]:\\+Users\\"), None),
    ("email", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9-])"), allow_email),
    ("host", re.compile(r"(?i)(?<![A-Za-z0-9.-])(?:[a-z0-9-]+\.)*(?P<label>[a-z0-9-]+)\.tzun\.ai(?![A-Za-z0-9-])"), allow_host),
    ("requirement", re.compile(r"(?<![A-Za-z0-9-])REQ-[A-Z0-9]+(?:-[A-Z0-9]+)*"), None),
    ("private-status", re.compile(r"(?i)\b(?:this|the) repo(?:sitory)? is (?:still )?private\b|\bprivate repo(?:sitory|sitories|s)?\b"), None),
]

# A comment or quotation marker at the start of a line, left out when the
# lines of a paragraph are folded together.
LEAD = re.compile(r"^\s*(?:#+|//+|/\*+|\*+|>+)?\s*")


def found(where, n, rule, text, out):
    out.append(f"{where}:{n}: {rule}: {text}")


CHANGELOG_REF = re.compile(r"(?<![A-Za-z0-9_/#&-])#[0-9]+(?![0-9])")
COMMIT_REF = re.compile(r"(?i)\b(?:commit|cited as)\s+`?([0-9a-f]{7,40})\b")
_known = {}


def is_commit(sha):
    if sha not in _known:
        _known[sha] = subprocess.run(["git", "cat-file", "-e", sha + "^{commit}"],
                                     capture_output=True).returncode == 0
    return _known[sha]


def scan_paths(where, text, out):
    lines = unicodedata.normalize("NFKC", text).splitlines()
    for n, line in enumerate(lines, 1):
        if where == "CHANGELOG.md":
            for m in CHANGELOG_REF.finditer(line):
                found(where, n, "changelog-ref", m.group(0), out)
        for m in COMMIT_REF.finditer(line):
            if not is_commit(m.group(1)):
                found(where, n, "commit-ref", m.group(0), out)


# author is the (name, address) of the commit whose message text is, in
# commits mode, and None in the other modes.
def scan(where, text, out, author=None):
    lines = unicodedata.normalize("NFKC", text).splitlines()
    for n, line in enumerate(lines, 1):
        for rule, rx, allow in RULES:
            for m in rx.finditer(line):
                if allow is None or not allow(m, line, author):
                    found(where, n, rule, m.group(0), out)
    # Each paragraph again, its lines folded into one; a match is reported
    # here only when it spans a line break, since the pass above found the
    # others.
    i = 0
    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue
        j = i
        while j < len(lines) and lines[j].strip():
            j += 1
        if j - i > 1:
            pieces = [LEAD.sub("", lines[k]).rstrip() for k in range(i, j)]
            starts, pos = [], 0
            for p in pieces:
                starts.append(pos)
                pos += len(p) + 1
            joined = " ".join(pieces)
            for rule, rx, allow in RULES:
                for m in rx.finditer(joined):
                    first = max(k for k, s in enumerate(starts) if s <= m.start())
                    if m.end() <= starts[first] + len(pieces[first]):
                        continue
                    if allow is None or not allow(m, joined, author):
                        found(where, i + first + 1, rule, m.group(0), out)
        i = j


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def main():
    mode = sys.argv[1]
    out = []
    if mode == "tree":
        for path in git("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0"):
            if not path or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                raw = f.read()
            if b"\0" in raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            scan(path, text, out)
            scan_paths(path, text, out)
        what = "the files git tracks or would add"
    elif mode == "commits":
        shas = git("rev-list", sys.argv[2], "--").decode().split()
        for sha in shas:
            name, email, msg = git("show", "-s", "--format=%an%x00%ae%x00%B", sha).decode(
                "utf-8", errors="replace").split("\0", 2)
            scan(f"commit {sha[:12]}", msg, out, author=(name, email))
        what = f"{len(shas)} commit message(s)"
    else:
        label = sys.argv[2] if len(sys.argv) > 2 else "stdin"
        scan(label, sys.stdin.buffer.read().decode("utf-8", errors="replace"), out)
        what = label
    for f in out:
        print(f)
    if out:
        print(f"public hygiene: {len(out)} finding(s) in {what}", file=sys.stderr)
        sys.exit(1)
    print(f"public hygiene: nothing found in {what}", file=sys.stderr)


try:
    main()
except subprocess.CalledProcessError as e:
    sys.stderr.write(e.stderr.decode(errors="replace"))
    sys.exit(2)
PY
exec python3 -c "$program" "$@"
