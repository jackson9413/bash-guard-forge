"""Analysis layer: turns a shell script into findings, a timeline, a score and a patch."""
from __future__ import annotations

import re
import difflib
from dataclasses import dataclass
from typing import Any, Optional

import rules_extra  # noqa: F401  (registers the extra rule set)
from engine import (
    AXES,
    AXIS_LABELS,
    RULES,
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    VERDICTS,
    Rule,
    find_unquoted_vars,
    is_assignment_context,
    split_logical_lines,
    strip_comment,
)

ENV_WEIGHTS = {
    "ci": {"error_handling": 0.25, "quoting": 0.22, "security": 0.20, "portability": 0.18, "destructive": 0.15},
    "laptop": {"destructive": 0.26, "security": 0.24, "quoting": 0.20, "error_handling": 0.20, "portability": 0.10},
    "prod": {"destructive": 0.32, "security": 0.26, "error_handling": 0.20, "quoting": 0.12, "portability": 0.10},
    "root": {"destructive": 0.35, "security": 0.30, "error_handling": 0.20, "quoting": 0.08, "portability": 0.07},
    "review": {"destructive": 0.24, "security": 0.24, "quoting": 0.20, "error_handling": 0.20, "portability": 0.12},
    "default": {"destructive": 0.28, "security": 0.22, "quoting": 0.20, "error_handling": 0.20, "portability": 0.10},
}

ENV_LABELS = {
    "ci": "CI pipeline",
    "laptop": "Laptop / workstation",
    "prod": "Production server",
    "root": "Running as root",
    "review": "Code review / shared repo",
    "default": "Unspecified",
}

BASHISMS = [
    (r"\[\[", "[[ ]] test"),
    (r"(?<![-\w])local\s+\w", "local"),
    (r"\+=", "+= assignment"),
    (r"(?<![-\w])source\s", "source"),
    (r"<<<", "here-string"),
    (r"&>", "&> redirection"),
    (r"\bfunction\s+\w+\s*\(\)", "function keyword"),
    (r"\$\{[A-Za-z_]\w*,,", "case conversion"),
    (r"\bdeclare\b", "declare"),
    (r"=~", "=~ regex match"),
    (r"\becho\s+-e\b", "echo -e"),
    (r"\bmapfile\b|\breadarray\b", "mapfile/readarray"),
    (r"\bprintf\s+-v\b", "printf -v"),
    (r"\(\(", "double-paren arithmetic"),
]

COMMAND_DESCRIPTIONS = {
    "rm": "deletes files or directories",
    "rmdir": "removes empty directories",
    "mv": "moves or renames files",
    "cp": "copies files",
    "mkdir": "creates directories",
    "touch": "creates empty files or updates timestamps",
    "chmod": "changes file permissions",
    "chown": "changes file ownership",
    "curl": "downloads content from the network",
    "wget": "downloads content from the network",
    "git": "manipulates a git repository",
    "npm": "runs the Node package manager",
    "npx": "runs a package binary from the network",
    "pip": "installs Python packages",
    "pip3": "installs Python packages",
    "apt": "manages Debian/Ubuntu packages",
    "apt-get": "manages Debian/Ubuntu packages",
    "brew": "manages Homebrew packages",
    "yum": "manages RPM packages",
    "docker": "manages containers",
    "kubectl": "talks to a Kubernetes cluster",
    "aws": "runs an AWS CLI command",
    "gcloud": "runs a Google Cloud CLI command",
    "az": "runs an Azure CLI command",
    "psql": "talks to a PostgreSQL database",
    "mysql": "talks to a MySQL database",
    "sqlite3": "queries a SQLite database",
    "systemctl": "manages systemd services",
    "launchctl": "manages macOS launchd jobs",
    "service": "manages system services",
    "ssh": "opens an SSH connection to another host",
    "scp": "copies files over SSH",
    "rsync": "synchronises files between two paths",
    "find": "searches the filesystem",
    "grep": "searches inside files",
    "sed": "edits text in files",
    "awk": "processes text line by line",
    "tar": "creates or extracts archives",
    "unzip": "extracts zip archives",
    "dd": "copies raw blocks to a device",
    "mkfs": "formats a filesystem",
    "shutdown": "powers the machine down",
    "reboot": "reboots the machine",
    "kill": "sends a signal to a process",
    "killall": "kills processes by name",
    "pkill": "kills processes by pattern",
    "echo": "prints text",
    "printf": "prints formatted text",
    "cat": "prints file contents",
    "ls": "lists files",
    "set": "changes shell options",
    "export": "exports environment variables",
    "source": "sources another script into this shell",
    "python3": "runs Python",
    "node": "runs Node.js",
    "make": "runs a build",
    "jq": "parses JSON",
    "openssl": "performs cryptography",
    "base64": "encodes or decodes binary data",
    "nc": "opens a network connection",
    "test": "tests a condition",
    "true": "does nothing and succeeds",
    "false": "does nothing and fails",
    "sleep": "waits",
    "wait": "waits for background jobs",
}

CONTROL_WORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
    "case", "esac", "function", "select", "time", "!", "{", "}",
}

LEADERS = {"sudo", "env", "command", "nohup", "time", "nice", "ionice", "xargs", "stdbuf", "exec"}

PACKAGE_INSTALLERS = {"apt", "apt-get", "brew", "yum", "dnf", "apk", "pacman", "npm", "pip", "pip3", "gem", "cargo", "go"}
DB_TOOLS = {"psql", "mysql", "sqlite3", "mongosh", "redis-cli"}


# --------------------------------------------------------------------------------------


def _head_word(line: str) -> str:
    s = line.strip()
    # drop leading assignments
    while True:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", s)
        if not m:
            break
        s = s[m.end():].lstrip()
    words = s.split()
    if not words:
        return ""
    while words and words[0] in LEADERS:
        words = words[1:]
    if not words:
        return ""
    head = words[0]
    if head in CONTROL_WORDS:
        return ""
    return head.split("/")[-1]


def _strip_quotes(tok: str) -> str:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        tok = tok[1:-1]
    return tok


def describe_step(line: str) -> tuple[str, str]:
    """Return (category, human description)."""
    s = line.strip()
    low = s.lower()
    if s.split(";")[0].strip() in CONTROL_WORDS or s in ("{", "}"):
        return "control", "control flow"

    if re.search(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", low):
        return "execute_remote", "downloads code from the internet and runs it immediately"
    if re.search(r"\b(curl|wget)\b[^|]*\|\s*(python3?|perl|ruby|node)\b", low):
        return "execute_remote", "downloads code from the internet and pipes it into an interpreter"
    if re.search(r"/dev/tcp/|/dev/udp/", low):
        return "execute_remote", "opens a raw network socket back to a remote host"
    if re.search(r"\beval\b", low):
        return "execute_remote", "evaluates a string as shell code"

    head = _head_word(s)
    if not head:
        if re.match(r"^(if|for|while|case|until|\}|\{)", s):
            return "control", "control flow"
        if s.startswith("#"):
            return "comment", "a comment"
        if s.endswith(";") or ";" in s:
            head = _head_word(s.split(";")[0])
        if not head:
            return "other", "shell command"

    args = s.split()
    if head in PACKAGE_INSTALLERS:
        pkgs = [a for a in args[1:] if not a.startswith("-")]
        return "install", "installs or updates packages (%s)" % (", ".join(pkgs[:4]) if pkgs else "packages")
    if head in DB_TOOLS:
        return "db", "runs a database command"
    if head == "rm":
        targets = [_strip_quotes(a) for a in args[1:] if not a.startswith("-")]
        return "delete", "deletes %s" % (", ".join(targets[:4]) if targets else "files")
    if head == "mv":
        targets = [_strip_quotes(a) for a in args[1:] if not a.startswith("-")]
        return "move", "moves %s" % (" -> ".join(targets[:3]) if targets else "files")
    if head == "cp":
        targets = [_strip_quotes(a) for a in args[1:] if not a.startswith("-")]
        return "copy", "copies %s" % (", ".join(targets[:3]) if targets else "files")
    if head in ("curl", "wget"):
        urls = re.findall(r"https?://([^/\s\x22\x27|]+)", s)
        dest = "to stdout" if ">" not in s else "to a file"
        return "download", "downloads %s %s" % (urls[0] if urls else "content", dest)
    if head in ("chmod", "chown"):
        return "permissions", "changes %s on %s" % (head, " ".join(args[2:4]) or "a path")
    if head in ("systemctl", "launchctl", "service"):
        return "service", "manages a system service"
    if head == "docker":
        return "container", "works with containers"
    if head == "kubectl":
        return "container", "changes Kubernetes resources"
    if head == "git":
        sub = next((a for a in args[1:] if not a.startswith("-")), "")
        return "git", "runs git %s" % (sub or "command")
    if head == "sudo":
        return "privilege", "escalates privileges to root"
    if head in ("echo", "printf", "cat"):
        return "print", "prints output"
    if head in ("find", "grep", "awk", "sed", "cut", "sort", "uniq"):
        return "search", "reads and transforms text"
    if head == "set":
        return "control", "sets shell options"
    if head in ("export",):
        return "control", "sets an environment variable"
    if head in ("source", "."):
        return "control", "runs another script in this shell"
    if head in ("ssh", "scp"):
        return "network", "connects to another machine over SSH"
    if head in ("dd", "mkfs", "shred"):
        return "destructive", "writes directly to a device"
    if head in ("kill", "killall", "pkill"):
        return "destructive", "stops a running process"
    if head in ("openssl", "gpg"):
        return "security", "performs a cryptographic operation"
    if head in ("rsync", "tar", "unzip"):
        return "copy", "copies or extracts files"
    if head in ("python3", "node", "make", "pytest", "jq"):
        return "build", "runs %s" % head
    return "other", COMMAND_DESCRIPTIONS.get(head, "runs %s" % head)


# --------------------------------------------------------------------------------------


def _heredoc_regions(logical: list[tuple[int, str]]) -> set[int]:
    """Indices (0-based into logical) that are heredoc bodies."""
    skip: set[int] = set()
    i = 0
    while i < len(logical):
        _, text = logical[i]
        m = re.search(r"<<-?\s*([\x27\x22]?)([A-Za-z_][A-Za-z0-9_]*)\1", text)
        if m:
            term = m.group(2)
            j = i + 1
            while j < len(logical) and logical[j][1].strip() != term:
                skip.add(j)
                j += 1
            if j < len(logical):
                skip.add(j)
                i = j
        i += 1
    return skip


def _in_double_bracket(line: str, pos: int) -> bool:
    start = line.find("[[")
    if start == -1:
        return False
    end = line.find("]]", start)
    if end == -1:
        return pos > start
    return start < pos < end


def _bashism_hits(line: str) -> list[str]:
    return [label for pat, label in BASHISMS if re.search(pat, line)]


# --------------------------------------------------------------------------------------


@dataclass
class Ctx:
    script: str
    env: str
    shell: str
    intent: str
    logical: list[tuple[int, str]]
    skip: set
    raw: list[str]


def _detect_shell(ctx: Ctx) -> str:
    for _, text in ctx.logical:
        s = text.strip()
        if s.startswith("#!"):
            m = re.search(r"\b(bash|sh|zsh|ksh|dash|fish)\b", s)
            if m:
                return m.group(1)
            return "unknown"
        if s and not s.startswith("#"):
            break
    return ctx.shell or "bash"


def _script_level_findings(ctx: Ctx, shell: str) -> list[dict]:
    out: list[dict] = []
    texts = [t for _, t in ctx.logical]
    body = "\n".join(texts)
    shebang_idx = None
    for i, (ln, t) in enumerate(ctx.logical):
        if t.strip().startswith("#!"):
            shebang_idx = i
            break

    if shebang_idx is None:
        out.append(_finding("missing_shebang", "portability", "medium",
                           "No shebang line",
                           "Without #!, the shell that runs the script is whatever invoked it. Run under bash by accident and under sh by accident, the two behave differently.",
                           "Add a shebang: #!/usr/bin/env bash",
                           line_no=1, evidence=ctx.raw[0] if ctx.raw else ""))
    elif shell in ("sh", "dash", "ash"):
        hits: list[str] = []
        seen = set()
        for idx in ctx.skip:
            continue
        for _, t in ctx.logical:
            for h in _bashism_hits(t):
                if h not in seen:
                    seen.add(h)
                    hits.append(h)
        if hits:
            out.append(_finding("bashism_in_sh", "portability", "high",
                               "bash syntax in a POSIX sh script",
                               "Under /bin/sh (dash on Debian/Ubuntu, ash on Alpine) these constructs fail at runtime, often deep into a long pipeline: " + ", ".join(hits[:6]) + ".",
                               "Either change the shebang to #!/usr/bin/env bash, or rewrite the construct in POSIX sh.",
                               line_no=ctx.logical[shebang_idx][0], evidence=ctx.logical[shebang_idx][1]))

    has_e = bool(re.search(r"(^|;|\s)set\s+-[A-Za-z]*e", body))
    has_u = bool(re.search(r"(^|;|\s)set\s+-[A-Za-z]*u", body))
    has_pipefail = "pipefail" in body
    if not (has_e and has_u and has_pipefail):
        missing = [n for n, present in (("-e", has_e), ("-u", has_u), ("pipefail", has_pipefail)) if not present]
        out.append(_finding("missing_set_flags", "error_handling", "medium",
                           "No strict mode",
                           "Without set -euo pipefail the script keeps going after a failed command, treats an unset variable as an empty string, and only notices a broken pipe at the end." + (" Missing: " + " ".join(missing) + "." if missing else ""),
                           "Add set -euo pipefail right after the shebang.",
                           line_no=ctx.logical[shebang_idx][0] if shebang_idx is not None else 1,
                           evidence=ctx.logical[shebang_idx][1] if shebang_idx is not None else ""))
    elif not has_pipefail:
        out.append(_finding("no_pipefail", "error_handling", "low",
                           "No pipefail",
                           "In a pipeline only the exit status of the last command is checked, so curl can fail while the pipeline still reports success.",
                           "Add set -o pipefail.",
                           line_no=ctx.logical[shebang_idx][0] if shebang_idx is not None else 1,
                           evidence=ctx.logical[shebang_idx][1] if shebang_idx is not None else ""))

    # cd without error check
    for i, (ln, t) in enumerate(ctx.logical):
        if re.match(r"^\s*cd\s+", t) and "||" not in t:
            nxt = ctx.logical[i + 1][1].strip() if i + 1 < len(ctx.logical) else ""
            if not (nxt.startswith("||") or nxt.startswith("&&")):
                out.append(_finding("cd_without_check", "error_handling", "medium",
                                   "cd without an error check",
                                   "If the directory does not exist the script continues in the wrong directory and then writes files to the wrong place.",
                                   'Use cd "$DIR" || exit 1.',
                                   line_no=ln, evidence=t))
                break

    if not re.search(r"\btrap\b", body):
        out.append(_finding("no_cleanup_trap", "error_handling", "low",
                           "No cleanup trap",
                           "If the script fails halfway, temp files and partial downloads are left behind.",
                           "Add trap cleanup EXIT INT TERM at the top.",
                           line_no=1, evidence=""))

    if not re.search(r"\busage\b|--help|\bhelp\(\)|\bprint_usage\b", body) and re.search(r"\$\d|\$\{?1\}?", body):
        out.append(_finding("no_usage_fn", "error_handling", "low",
                           "No usage or help function",
                           "A script that takes arguments but has no --help output is hard to call correctly and impossible to self-document.",
                           "Add a usage() function and call it on -h/--help or on a bad argument count.",
                           line_no=1, evidence=""))

    tools = {t for t in re.findall(r"(?<![-\w./])(jq|aws|kubectl|docker|git|yq|helm|psql|terraform|node|python3)\b", body)}
    checked = set(re.findall(r"command\s+-v\s+([A-Za-z0-9_.-]+)", body))
    unchecked = sorted(tools - checked)
    if unchecked:
        out.append(_finding("no_dependency_check", "error_handling", "low",
                           "No dependency checks",
                           "If a required tool is missing the script fails partway through, after it has already changed some state. Not checked: " + ", ".join(unchecked[:6]) + ".",
                           "Check for each tool with command -v at the top and exit with a clear message.",
                           line_no=1, evidence=""))

    suppressed = len(re.findall(r"2>\s*/dev/null", body))
    if suppressed >= 3:
        out.append(_finding("stderr_suppressed", "error_handling", "low",
                           "Errors are being thrown away",
                           "There are %d places where stderr goes to /dev/null. That hides the exact message you need when something goes wrong." % suppressed,
                           "Capture the error and print it, or redirect to a log file.",
                           line_no=1, evidence=""))

    if "mktemp" in body and not re.search(r"chmod\s+[46]00|chmod\s+700", body):
        out.append(_finding("mktemp_no_chmod", "security", "medium",
                           "Temporary file is not locked down",
                           "A file created with mktemp stays readable by other users until you chmod it, so a secret written to it can be read in the gap.",
                           "chmod 600 the file right after creating it.",
                           line_no=1, evidence=""))

    if re.search(r"\$\{?[1-9]\d?\}?", body) and not re.search(r"\$\#|\[\s+-\w\s*\]", body) and not re.search(r"\bset\s+-u\b", body):
        out.append(_finding("no_arg_validation", "error_handling", "low",
                           "Arguments are not validated",
                           "The script reads positional parameters without checking they exist, so a missing argument silently becomes an empty string.",
                           "Check $# and validate each argument before using it.",
                           line_no=1, evidence=""))
    return out


def _finding(rule_id: str, axis: str, severity: str, title: str, why: str, fix: str,
             line_no: int = 0, evidence: str = "", extra: Optional[dict] = None) -> dict:
    d = {
        "id": rule_id,
        "axis": axis,
        "axis_label": AXIS_LABELS.get(axis, axis),
        "severity": severity,
        "title": title,
        "why": why,
        "fix": fix,
        "line": line_no,
        "evidence": evidence.strip()[:240],
    }
    if extra:
        d.update(extra)
    return d


def _apply_line_rules(ctx: Ctx, shell: str) -> list[dict]:
    findings: list[dict] = []
    raw_lines = ctx.raw
    for idx, (ln, text) in enumerate(ctx.logical):
        if idx in ctx.skip:
            continue
        s = text.strip()
        if not s or s.startswith("#"):
            continue
        code = strip_comment(text)
        if not code.strip():
            continue
        evidence = raw_lines[ln - 1] if 0 < ln <= len(raw_lines) else text

        for rule in RULES:
            if rule.scope != "line":
                continue
            fired = False
            detail = None
            if rule.check is not None:
                fired = bool(rule.check(code, None))
            elif rule.quotable:
                hits = [h for h in find_unquoted_vars(code)
                        if h[2] and not is_assignment_context(code, h[0]) and not _in_double_bracket(code, h[0])]
                if hits:
                    fired = True
                    detail = {"positions": hits}
            elif rule.pattern:
                if re.search(rule.pattern, code, re.MULTILINE):
                    fired = True
            if not fired:
                continue
            findings.append(_finding(rule.id, rule.axis, rule.severity, rule.title, rule.why, rule.fix,
                                      line_no=ln, evidence=evidence, extra=detail))
    return findings


def _quote_fix(line: str, positions: list) -> str:
    out = line
    for start, end, _name in sorted(positions, key=lambda p: -p[0]):
        if out[start:end].startswith("$"):
            out = out[:start] + '"' + out[start:end] + '"' + out[end:]
    return out


def _mechanical_fix(line: str) -> str:
    fixed = line
    fixed = re.sub(r"\bchmod\s+(-\w+\s+)?777\b", lambda m: (m.group(0).replace("777", "755")), fixed)
    fixed = re.sub(r"(^|[;&|]\s*)which\s+", r"\1command -v ", fixed)
    fixed = re.sub(r"\bsed\s+([^|;]*?)-i(\s|$)", r"sed \1-i.bak\2", fixed)
    fixed = re.sub(r"\becho\s+-e\b", "printf '%b'", fixed)
    return fixed


def build_patch(ctx: Ctx, findings: list[dict], shell: str) -> dict:
    """Build a unified diff with the safe mechanical fixes applied."""
    raw = list(ctx.raw)
    changes: list[tuple[int, str, str]] = []  # (line index, before, after)

    for f in findings:
        if f["id"] == "unquoted_var" and f.get("positions"):
            ln = f["line"]
            if 0 < ln <= len(raw):
                before = raw[ln - 1]
                after = _quote_fix(before, f["positions"])
                if after != before:
                    changes.append((ln, before, after))
        elif f["id"] in ("chmod_777", "which_cmd", "sed_i_no_suffix", "echo_e"):
            ln = f["line"]
            if 0 < ln <= len(raw):
                before = raw[ln - 1]
                after = _mechanical_fix(before)
                if after != before:
                    changes.append((ln, before, after))

    fixed = list(raw)
    for ln, _before, after in changes:
        fixed[ln - 1] = after

    if not re.search(r"set\s+-[A-Za-z]*[eu]|set\s+.*pipefail", "\n".join(raw)):
        insert_at = 0
        for i, l in enumerate(raw):
            if l.strip().startswith("#!"):
                insert_at = i + 1
                break
            if l.strip():
                insert_at = i
                break
        fixed.insert(insert_at, "set -euo pipefail")

    if fixed == raw:
        return {"available": False, "diff": "", "note": "No mechanical fix could be applied safely."}

    diff = difflib.unified_diff(raw, fixed, fromfile="script.sh", tofile="script.sh (safer)", lineterm="")
    return {
        "available": True,
        "diff": "\n".join(diff),
        "fixed_script": "\n".join(fixed),
        "note": "Mechanical fixes only - quoting, permissions and portability. Review before applying.",
    }


# --------------------------------------------------------------------------------------


def _blast_radius(ctx: Ctx, steps: list[dict]) -> dict:
    body = "\n".join(t for _, t in ctx.logical)
    paths: list[str] = []
    for m in re.finditer(r"(?<![\w$])(/(?:[A-Za-z0-9._~-]+)(?:/[A-Za-z0-9._~*-]+)?)", body):
        p = m.group(1)
        if p.count("/") >= 1 and len(p) > 1:
            paths.append(p)
    hosts = sorted(set(re.findall(r"https?://([^/\s\x22\x27|]+)", body)))
    hosts = sorted(set(re.findall(r"https?://([^/\s\x22\x27|]+)", body)))
    ssh_hosts = sorted(set(re.findall(r"\bssh\s+(?:-\S+\s+)*[\w.-]*@([\w.-]+)", body)))
    hosts = sorted(set(hosts) | set(ssh_hosts))
    packages: list[str] = []
    for m in re.finditer(r"(?m)^\s*(?:sudo\s+)?(apt|apt-get|brew|yum|dnf|apk|pacman|npm|pip3?|gem)\s+(?:install|add|i)\s+(.+)$", body):
        for tok in m.group(2).split():
            tok = tok.strip("'\"")
            if tok and not tok.startswith("-"):
                packages.append(tok)
    dbs = sorted(set(re.findall(r"(?i)\b(?:USE|CREATE|DROP|TRUNCATE)\s+(?:DATABASE|TABLE)?\s*\x22?([a-z_][a-z0-9_]*)", body)))
    privilege = bool(re.search(r"(^|[;&|\s])sudo\b", body))
    root_dirs = [p for p in paths if p.split("/")[1] in ("etc", "usr", "bin", "sbin", "boot", "var", "lib", "dev", "root", "home", "Users")]
    return {
        "paths": sorted(set(paths))[:14],
        "system_paths": sorted(set(root_dirs))[:10],
        "hosts": hosts[:10],
        "packages": sorted(set(packages))[:10],
        "databases": dbs[:8],
        "escalates_to_root": privilege,
        "network": bool(hosts) or bool(re.search(r"\b(curl|wget|nc|ssh|scp|rsync)\b", body)),
        "deletes": bool(re.search(r"\brm\b|find\s+[^\n]*-delete|rsync[^\n]*--delete", body)),
    }


def _intent_summary(ctx: Ctx, steps: list[dict], blast: dict) -> dict:
    """Plain-English read of what the script actually does."""
    real = [s for s in steps if s["category"] not in ("comment", "control", "other") or s["category"] == "other"]
    bullets: list[str] = []
    seen: set[str] = set()
    for s in steps:
        if s["category"] in ("comment",):
            continue
        desc = s["description"]
        if desc in seen:
            continue
        seen.add(desc)
        bullets.append(desc)
    summary = ""
    if ctx.intent:
        summary = ctx.intent.strip()
    return {
        "summary": summary,
        "steps_plain": bullets[:10],
        "step_count": len([s for s in steps if s["category"] != "comment"]),
        "hosts": blast["hosts"],
        "escalates_to_root": blast["escalates_to_root"],
    }


def _empty_result(env: str, shell: str, intent: str = "") -> dict:
    weights = ENV_WEIGHTS.get(env, ENV_WEIGHTS["default"])
    return {
        "score": 100.0,
        "verdict": "deploy_ready",
        "verdict_label": "Deploy ready",
        "verdict_note": "There is nothing in the script to run, so there is nothing to break.",
        "axes": [{"id": a, "label": AXIS_LABELS[a], "score": 100.0, "weight": weights[a]} for a in AXES],
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
        "top_findings": [],
        "steps": [],
        "blast": {"paths": [], "system_paths": [], "hosts": [], "packages": [], "databases": [],
                  "escalates_to_root": False, "network": False, "deletes": False},
        "intent": {"summary": intent or "", "steps_plain": [], "step_count": 0, "hosts": [],
                   "escalates_to_root": False},
        "shell": shell or "bash",
        "env": env,
        "env_label": ENV_LABELS.get(env, env),
        "patch": {"available": False, "diff": "", "note": "Nothing to fix."},
        "line_count": 0,
        "findings_count": 0,
    }


def analyze(script: str, env: str = "default", shell: str = "bash", intent: str = "") -> dict:
    script = script or ""
    if not script.strip():
        return _empty_result(env, shell, intent)
    if not script.strip():
        return _empty_result(env, shell, intent)
    raw = script.splitlines()
    logical = split_logical_lines(script)
    skip = _heredoc_regions(logical)
    ctx = Ctx(script=script, env=env or "default", shell=shell or "bash", intent=intent or "",
              logical=logical, skip=skip, raw=raw)
    detected_shell = _detect_shell(ctx)

    findings = _script_level_findings(ctx, detected_shell)
    findings.extend(_apply_line_rules(ctx, detected_shell))

    # dedupe identical rule id + line
    seen = set()
    unique: list[dict] = []
    for f in findings:
        key = (f["id"], f["line"], f["evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    findings = unique

    # timeline
    steps: list[dict] = []
    for idx, (ln, text) in enumerate(ctx.logical):
        if idx in ctx.skip:
            continue
        s = text.strip()
        if not s or s.startswith("#"):
            continue
        cat, desc = describe_step(text)
        line_findings = [f for f in findings if f["line"] == ln]
        sev = "ok"
        for f in line_findings:
            if sev == "ok" or SEVERITY_ORDER[f["severity"]] < SEVERITY_ORDER[sev]:
                sev = f["severity"]
        steps.append({
            "n": len(steps) + 1,
            "line": ln,
            "raw": text.strip()[:200],
            "command": _head_word(text),
            "category": cat,
            "description": desc,
            "severity": sev,
            "finding_ids": [f["id"] for f in line_findings],
        })

    # axis scores
    axis_scores: dict[str, float] = {}
    for axis in AXES:
        contrib: dict[str, float] = {}
        for f in findings:
            if f["axis"] != axis:
                continue
            w = SEVERITY_WEIGHT[f["severity"]]
            n = contrib.get(f["id"], 0) + 1
            contrib[f["id"]] = w * (1 + 0.35 * (n - 1))
        penalty = sum(contrib.values())
        axis_scores[axis] = max(0.0, min(100.0, 100.0 - penalty))

    weights = ENV_WEIGHTS.get(ctx.env, ENV_WEIGHTS["default"])
    overall = sum(axis_scores[a] * weights[a] for a in AXES)
    overall = round(overall, 1)

    # a weak axis caps the overall verdict: you cannot be deploy ready with a broken axis
    worst_axis = min(axis_scores.values())
    if worst_axis < 40:
        overall = min(overall, 69.0)
    elif worst_axis < 60:
        overall = min(overall, 79.0)
    # too many small problems is itself a problem
    total_findings = len(findings)
    if total_findings >= 16:
        overall -= 12
    elif total_findings >= 10:
        overall -= 6
    overall = max(0.0, round(overall, 1))

    criticals = [f for f in findings if f["severity"] == "critical"]
    if len(criticals) >= 2:
        overall = min(overall, 22.0)
    elif criticals:
        overall = min(overall, 33.0)

    verdict = "dangerous_do_not_run"
    vlabel = ""
    vnote = ""
    for threshold, vid, label, note in VERDICTS:
        if overall >= threshold:
            verdict, vlabel, vnote = vid, label, note
            break

    blast = _blast_radius(ctx, steps)
    intent_info = _intent_summary(ctx, steps, blast)
    patch = build_patch(ctx, findings, detected_shell)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] += 1

    top = sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"]))[:8]

    return {
        "score": overall,
        "verdict": verdict,
        "verdict_label": vlabel,
        "verdict_note": vnote,
        "axes": [
            {"id": a, "label": AXIS_LABELS[a], "score": round(axis_scores[a], 1), "weight": weights[a]}
            for a in AXES
        ],
        "counts": counts,
        "findings": sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"])),
        "top_findings": [f["id"] for f in top],
        "steps": steps,
        "blast": blast,
        "intent": intent_info,
        "shell": detected_shell,
        "env": ctx.env,
        "env_label": ENV_LABELS.get(ctx.env, ctx.env),
        "patch": patch,
        "line_count": len(raw),
        "findings_count": len(findings),
    }
