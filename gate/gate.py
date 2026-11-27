#!/usr/bin/env python3
"""Device Lab security gate. Runs FIRST in every workflow; any failure stops the run.

Modes:
  pre   <repo_root>   before anything else: actor allowlist, trigger check, workflow pinning,
                      secret scan, no-source scan, build hash allowlist.
  post  <out_dir>     before anything is uploaded: only encrypted files may leave, and nothing
                      readable may contain a secret.
  logs  <file|dir>    run logs (gh run view <id> --log > run.log): no secret and no internal
                      name may appear in what the public can read.
Internal names are never stored in plain text: allowlist.json keeps their SHA-256 ("markers"),
and the optional secret GATE_MARKERS (one regex per line) adds patterns at run time.
Exit 0 = pass, 1 = BLOCK. Prints only check names and pass/fail, never file contents.
"""
import hashlib, json, os, re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent
ALLOW = json.loads((ROOT / "allowlist.json").read_text())

SECRET_PATTERNS = [
    r"sk-ant-[A-Za-z0-9_\-]{20,}", r"sk-[A-Za-z0-9]{32,}", r"gh[pousr]_[A-Za-z0-9]{30,}",
    r"github_pat_[A-Za-z0-9_]{40,}", r"AKIA[0-9A-Z]{16}", r"AIza[0-9A-Za-z_\-]{35}",
    r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----", r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    r"sk_live_[A-Za-z0-9]{20,}", r"rk_live_[A-Za-z0-9]{20,}", r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.",
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"\s]{16,}['\"]",
]
# Our own code must never be in this repo: KMP/Android/iOS source files and our internal names.
SOURCE_EXT = {".kt", ".kts", ".swift", ".m", ".mm", ".java", ".gradle", ".xcodeproj", ".pbxproj"}
MARKER_HASHES = set(ALLOW.get("markers", []))  # sha256 of lower-cased tokens, see token_hashes()
EXTRA_MARKERS = [l.strip() for l in os.environ.get("GATE_MARKERS", "").splitlines() if l.strip()]
SKIP_DIRS = {".git", "node_modules"}  # the gate is scanned too: it names nothing in plain text

def token_hashes(t):
    """sha256 of every word and every pair of words joined by . - or / (lower case)."""
    out = set()
    for m in re.finditer(r"[a-z0-9_]+(?:[./\-][a-z0-9_]+)*", t.lower()):
        parts = re.split(r"([./\-])", m.group())
        words, seps = parts[0::2], parts[1::2]
        for i, w in enumerate(words):
            out.add(w)
            if i + 1 < len(words): out.add(w + seps[i] + words[i + 1])
    return {hashlib.sha256(x.encode()).hexdigest() for x in out}

def internal(t):
    return bool(MARKER_HASHES & token_hashes(t)) or any(re.search(m, t, re.I) for m in EXTRA_MARKERS)

fails = []
def check(name, ok, why=""):
    print(f"[{'PASS' if ok else 'BLOCK'}] {name}" + ("" if ok else f" -- {why}"))
    if not ok: fails.append(name)

def files(root):
    for p in pathlib.Path(root).rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            yield p

def text(p, limit=2_000_000):
    try:
        b = p.read_bytes()[:limit]
        return None if b"\x00" in b[:4096] else b.decode("utf-8", "ignore")
    except OSError:
        return None

def sha(p): return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()  # same hash on Windows and CI

def pre(root):
    root = pathlib.Path(root)
    env = os.environ
    in_ci = env.get("GITHUB_ACTIONS") == "true"
    # 1. Who and how: only the owner's accounts, only by hand (never PRs, issues, comments, forks).
    if in_ci:
        check("actor is allowlisted", env.get("GITHUB_ACTOR") in ALLOW["actors"], f"actor not allowed")
        check("trigger is manual", env.get("GITHUB_EVENT_NAME") in ALLOW["events"], "event not allowed")
        check("not a fork", env.get("GITHUB_REPOSITORY") == ALLOW["repository"], "wrong repository")
    # 2. Workflows pinned: any edit to a workflow or the gate must be re-approved (hash list).
    wf = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    for p in wf:
        rel = p.relative_to(root).as_posix()
        check(f"workflow pinned: {rel}", ALLOW["pinned"].get(rel) == sha(p), "unapproved workflow change")
        t = text(p) or ""
        bad = [e for e in ("pull_request", "issue_comment", "issues:", "pull_request_target", "discussion", "fork", "schedule", "repository_dispatch")
               if re.search(rf"^\s*{re.escape(e)}", t, re.M)]
        check(f"manual-only triggers: {rel}", not bad, f"forbidden trigger {bad}")
    for rel in ("gate/gate.py",):
        p = root / rel
        check(f"gate pinned: {rel}", p.exists() and ALLOW["pinned"].get(rel) == sha(p), "unapproved gate change")
    # 3. No secrets anywhere in the repo.
    hits = []
    for p in files(root):
        t = text(p)
        if t and any(re.search(pat, t) for pat in SECRET_PATTERNS): hits.append(p.relative_to(root).as_posix())
    check("no secrets in repo", not hits, f"{len(hits)} file(s): {hits[:5]}")
    # 4. No app source code in the repo.
    src = [p.relative_to(root).as_posix() for p in files(root) if p.suffix.lower() in SOURCE_EXT]
    check("no app source files", not src, f"{src[:5]}")
    ours = []
    for p in files(root):
        t = text(p)
        if t and internal(t): ours.append(p.relative_to(root).as_posix())
    check("no internal names", not ours, f"{ours[:5]}")
    # 5. No app binaries committed (builds arrive encrypted at run time only).
    bins = [p.relative_to(root).as_posix() for p in files(root) if p.suffix.lower() in (".apk", ".aab", ".ipa", ".app", ".zip") ]
    check("no app builds committed", not bins, f"{bins[:5]}")

def build(path):
    p = pathlib.Path(path)
    h = hashlib.sha256(p.read_bytes()).hexdigest()  # builds: exact bytes
    check("build is an approved hash", h in ALLOW["builds"], "build not signed off")

def post(out):
    out = pathlib.Path(out)
    readable, leaks = [], []
    for p in out.rglob("*"):
        if not p.is_file(): continue
        if not (p.suffix in (".enc", ".age", ".gpg") or p.name.endswith(".key.bin")): readable.append(p.name)
        t = text(p)
        if t and any(re.search(pat, t) for pat in SECRET_PATTERNS): leaks.append(p.name)
    check("only encrypted outputs leave", not readable, f"{len(readable)} plain file(s)")
    check("no secrets in outputs", not leaks, f"{leaks[:5]}")

def logs(path):
    path = pathlib.Path(path)
    items = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    sec, ours = [], []
    for p in items:
        t = text(p, limit=50_000_000)
        if not t: continue
        if any(re.search(pat, t) for pat in SECRET_PATTERNS): sec.append(p.name)
        if internal(t): ours.append(p.name)
    check("log files found", bool(items), "nothing to scan")
    check("no secrets in logs", not sec, f"{sec[:5]}")
    check("no internal names in logs", not ours, f"{ours[:5]}")

if __name__ == "__main__":
    mode, arg = sys.argv[1], sys.argv[2]
    {"pre": pre, "post": post, "build": build, "logs": logs}[mode](arg)
    print("GATE:", "BLOCKED" if fails else "PASSED")
    sys.exit(1 if fails else 0)

