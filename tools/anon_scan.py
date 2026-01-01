#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from typing import Iterable, List, Set, Tuple

TEXT_EXTENSIONS = {
    ".md", ".txt", ".xml", ".json", ".java", ".yml", ".yaml",
    ".properties", ".gradle", ".sh", ".bat", ".ps1", ".kts",
    ".groovy", ".cfg", ".conf", ".gitignore",
}
TEXT_FILENAMES = {
    "README", "README.md", "REPRODUCE.md", "QUICKSTART.md",
    "OPEN_SCIENCE_APPENDIX.md", "pom.xml", ".gitignore",
}

SKIP_DIRS = {
    ".git", "target", "out", "jar_file",
    "node_modules", "__pycache__", ".idea", ".vscode",
}
SKIP_PREFIXES = [
    os.path.join("demo", "output"),
    os.path.join("demo", "temp"),
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HTTP_RE = re.compile(r"https?://\S+")
GIT_REMOTE_RE = re.compile(r"(git@|ssh://|git://)\S+")
GITHUB_RE = re.compile(r"github\.com|gitlab\.com", re.IGNORECASE)
ALLOWED_URL_PREFIXES = (
    "https://anonymous.4open.science/",
)
USERS_PATH = "/" + "Users" + "/"
HOME_PATH = "/" + "home" + "/"
WIN_USERS_PATH = "C:" + "\\\\" + "Users" + "\\\\"
ABS_PATH_RE = re.compile(r"(" + re.escape(USERS_PATH) + r"|" + re.escape(HOME_PATH) + r"|" + re.escape(WIN_USERS_PATH) + r")")

MAVEN_TAGS = {
    "<developers>", "</developers>",
    "<organization>", "</organization>",
    "<scm>", "</scm>",
    "<url>", "</url>",
    "<issuemanagement>", "</issuemanagement>",
    "<cimanagement>", "</cimanagement>",
    "<contributors>", "</contributors>",
}

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)secret\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)token\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
]

HEX_RE = re.compile(r"\\b[0-9a-fA-F]{32,}\\b")
BASE64_RE = re.compile(r"\\b[A-Za-z0-9+/]{40,}={0,2}\\b")


def run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def derive_sensitive_tokens(root: str) -> Set[str]:
    tokens: Set[str] = set()

    # Local and global git config
    for scope in ("--global",):
        name = run_cmd(["git", "config", scope, "user.name"]).strip()
        email = run_cmd(["git", "config", scope, "user.email"]).strip()
        if name:
            tokens.add(name)
        if email:
            tokens.add(email)
    name = run_cmd(["git", "config", "user.name"]).strip()
    email = run_cmd(["git", "config", "user.email"]).strip()
    if name:
        tokens.add(name)
    if email:
        tokens.add(email)

    # whoami / hostname
    whoami = run_cmd(["whoami"]).strip()
    if whoami:
        tokens.add(whoami)
    hostname = run_cmd(["hostname"]).strip()
    if hostname:
        tokens.add(hostname)

    # username from pwd
    cwd = os.path.abspath(root)
    m = re.search(re.escape(USERS_PATH) + r"([^/]+)/", cwd)
    if m:
        tokens.add(m.group(1))
    m = re.search(re.escape(HOME_PATH) + r"([^/]+)/", cwd)
    if m:
        tokens.add(m.group(1))

    # origin remotes from current repo (URL only)
    remotes = run_cmd(["git", "-C", root, "remote", "-v"])
    for line in remotes.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            tokens.add(parts[1])

    # origin remotes from source repo (URL only, if provided)
    source_repo = os.environ.get("SOURCE_REPO")
    if source_repo:
        remotes = run_cmd(["git", "-C", source_repo, "remote", "-v"])
        for line in remotes.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                tokens.add(parts[1])

    # Filter tokens and drop placeholder identity values.
    tokens = {t for t in tokens if t and len(t) > 2}
    tokens.discard("Anonymous")
    tokens.discard("anon" + "@" + "example.invalid")
    return tokens


def is_text_file(path: str) -> bool:
    base = os.path.basename(path)
    if base in TEXT_FILENAMES:
        return True
    _, ext = os.path.splitext(base)
    return ext.lower() in TEXT_EXTENSIONS


def iter_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if rel == ".":
            rel = ""
        if any(rel == p or rel.startswith(p + os.sep) for p in SKIP_PREFIXES):
            dirnames[:] = []
            continue
        parts = [p for p in rel.split(os.sep) if p]
        if any(p in SKIP_DIRS for p in parts):
            dirnames[:] = []
            continue
        for name in filenames:
            path = os.path.join(dirpath, name)
            if is_text_file(path):
                yield path


def clip(snippet: str, limit: int = 140) -> str:
    s = snippet.replace("\t", " ").replace("\n", " ").strip()
    if len(s) > limit:
        return s[:limit] + "..."
    return s


def scan_file(path: str, tokens: Set[str]) -> List[Tuple[int, str, str]]:
    findings: List[Tuple[int, str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                if EMAIL_RE.search(line):
                    findings.append((idx, "email", clip(line)))
                urls = HTTP_RE.findall(line)
                if urls:
                    non_allowed = [
                        u for u in urls
                        if not any(u.startswith(prefix) for prefix in ALLOWED_URL_PREFIXES)
                    ]
                    if non_allowed:
                        findings.append((idx, "url", clip(line)))
                if GIT_REMOTE_RE.search(line):
                    findings.append((idx, "git-remote", clip(line)))
                if GITHUB_RE.search(line):
                    findings.append((idx, "github-gitlab", clip(line)))
                if ABS_PATH_RE.search(line):
                    findings.append((idx, "absolute-path", clip(line)))
                lower = line.lower()
                if any(tag in lower for tag in MAVEN_TAGS):
                    findings.append((idx, "maven-metadata", clip(line)))
                if any(tok in line for tok in tokens):
                    findings.append((idx, "sensitive-token", clip(line)))
                if any(p.search(line) for p in SECRET_PATTERNS):
                    findings.append((idx, "secret-pattern", clip(line)))
                hex_match = HEX_RE.search(line)
                if hex_match:
                    findings.append((idx, "high-entropy", clip(line)))
                else:
                    b64_match = BASE64_RE.search(line)
                    if b64_match:
                        token = b64_match.group(0)
                        if re.search(r"[0-9]", token) and re.search(r"[+/=]", token):
                            findings.append((idx, "high-entropy", clip(line)))
    except Exception as exc:
        findings.append((0, "scan-error", f"{path}: {exc}"))
    return findings


def main() -> int:
    root = os.path.abspath(os.path.dirname(__file__) + os.sep + "..")
    tokens = derive_sensitive_tokens(root)
    all_findings: List[Tuple[str, int, str, str]] = []

    for path in iter_files(root):
        rel = os.path.relpath(path, root)
        for line_no, category, snippet in scan_file(path, tokens):
            all_findings.append((rel, line_no, category, snippet))

    if all_findings:
        for rel, line_no, category, snippet in all_findings:
            print(f"{rel}:{line_no}: {category}: {snippet}")
        return 1

    print("anon_scan: no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
ALLOWED_URL_PREFIXES = (
    "https://anonymous.4open.science/",
)
