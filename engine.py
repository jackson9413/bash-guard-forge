"""bash-guard-forge analysis engine.

Static risk review for shell scripts. No network, no API keys, standard library only.
"""
from __future__ import annotations

import re
import difflib
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

AXES = ["destructive", "quoting", "security", "portability", "error_handling"]

AXIS_LABELS = {
    "destructive": "Blast radius",
    "quoting": "Quoting safety",
    "security": "Secret & trust",
    "portability": "Portability",
    "error_handling": "Failure handling",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SEVERITY_WEIGHT = {"critical": 24, "high": 11, "medium": 5, "low": 2}

VERDICTS = [
    (85, "deploy_ready", "Deploy ready", "Nothing here should stop this from running."),
    (70, "mostly_safe", "Mostly safe", "A few things deserve a second look before you run it."),
    (55, "needs_review", "Needs review", "This has real problems. Read the findings before running."),
    (40, "tight_but_usable", "Tight but usable", "Usable only once you fix the flagged lines."),
    (0, "dangerous_do_not_run", "Dangerous - do not run", "This script can destroy data or leak credentials. Do not run it as written."),
]

# --------------------------------------------------------------------------------------
# rule model
# --------------------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    axis: str
    severity: str
    title: str
    why: str
    fix: str
    pattern: Optional[str] = None
    flags: int = 0
    scope: str = "line"  # line | script
    check: Optional[Callable[[str, "Context"], Optional[bool]]] = None
    exclude: Optional[str] = None
    quotable: bool = False   # supports the mechanical quote-the-variable fix


RULES: list[Rule] = []


def R(*args, **kwargs) -> None:
    RULES.append(Rule(*args, **kwargs))


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------

VAR_CHARS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SPECIAL_VARS = {"?", "!", "#", "@", "*", "$", "-", "0", "_"}


def strip_comment(line: str) -> str:
    """Remove a trailing # comment while respecting quotes."""
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#" and (not out or out[-1] in " \t" or out[-1] == ";"):
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def split_logical_lines(script: str) -> list[tuple[int, str]]:
    """Split a script into logical lines, honouring backslash continuations.

    Returns a list of (starting line number, joined text).
    """
    raw_lines = script.splitlines()
    logical: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for idx, raw in enumerate(raw_lines, start=1):
        stripped = raw.rstrip()
        if buf:
            buf += " " + stripped.lstrip()
        else:
            buf = stripped
            start = idx
        if buf.endswith("\\"):
            buf = buf[:-1]
            continue
        logical.append((start, buf))
        buf = ""
    if buf:
        logical.append((start, buf))
    return logical


def quote_state_map(line: str) -> list[str]:
    """Return per-character quote state: 'n' none, 's' single, 'd' double.

    Command substitution is resolved recursively so that "$(cmd "$VAR")" is
    treated as a single quoted region instead of ending the outer quote.
    """
    states = []
    quote = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "$" and i + 1 < n and line[i + 1] == "(" and quote != "s":
            depth = 1
            j = i + 2
            inner = []
            while j < n:
                c = line[j]
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                inner.append(c)
                j += 1
            states.append(quote or "n")
            states.append(quote or "n")
            states.extend(quote_state_map("".join(inner)))
            i = j
            continue
        if quote:
            states.append(quote)
            if ch == "\\" and quote == '"' and i + 1 < n:
                states.append(quote)
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = "s" if ch == "'" else "d"
            states.append(quote)
            i += 1
            continue
        states.append("n")
        i += 1
    return states


def find_unquoted_vars(line: str) -> list[tuple[int, int, str]]:
    """Locate shell variable expansions used without quotes.

    Returns a list of (start_index, end_index_exclusive, name).
    """
    states = quote_state_map(line)
    hits: list[tuple[int, int, str]] = []
    i = 0
    in_double = False
    for idx, st in enumerate(states):
        in_double = st == "d"
    # recompute sequentially, tracking double-quote regions
    dq = [st in ("s", "d") for st in states]
    while i < len(line):
        if line[i] != "$":
            i += 1
            continue
        if dq[i]:
            i += 1
            continue
        # unquoted expansion
        j = i + 1
        if j >= len(line):
            break
        if line[j] == "{":
            m = VAR_CHARS.match(line, j + 1)
            if not m:
                i += 1
                continue
            name = m.group(0)
            end = m.end()
            if end < len(line) and line[end] == "}":
                end += 1
            hits.append((i, end, name))
            i = end
            continue
        if line[j] == "(":
            # command substitution
            hits.append((i, i + 2, ""))
            i += 2
            continue
        m = VAR_CHARS.match(line, j)
        if m:
            name = m.group(0)
            hits.append((i, m.end(), name))
            i = m.end()
            continue
        if line[j] in SPECIAL_VARS:
            i += 1
            continue
        i += 1
    return hits


def is_assignment_context(line: str, pos: int) -> bool:
    """True when the expansion at pos sits on the right-hand side of an assignment."""
    head = line[:pos]
    head = head.rstrip()
    if not head.endswith("="):
        return False
    left = head[:-1]
    if "=" in left:
        return False
    if not VAR_CHARS.fullmatch(left.strip()):
        # could be 'export FOO='
        if re.fullmatch(r"(export|declare|local|readonly)\s+" + VAR_CHARS.pattern, left.strip()):
            return True
        return False
    return True


def _rm_var_unquoted(line, ctx=None):
    """True when a recursive delete targets an unquoted, glob-expanded or substituted variable."""
    m = re.search(r"(?<![!\w-])rm\s+[^|;&]*?-[A-Za-z]*[rR][A-Za-z]*\s+(.*)$", line)
    if not m:
        return False
    args = m.group(1)
    for _s, _e, _name in find_unquoted_vars(args):
        return True
    if re.search(r"[\"']\$\{?[A-Za-z_]\w*\}?[\"']\s*/", args):
        return True
    return False


def _rm_no_dashdash(line, ctx=None):
    """True when a delete target could be read as a flag."""
    m = re.search(r"(?<![\w-])rm\s+([^|;&]*)", line)
    if not m:
        return False
    args = m.group(1)
    if "--" in args:
        return False
    if "*" in args:
        return True
    for _s, _e, _name in find_unquoted_vars(args):
        return True
    return False


def _find_delete_pattern(line):
    return bool(re.search(r"\bfind\b[^|;&]*(-delete|-exec\s+rm\b|-execdir\s+rm\b)", line))


def _find_delete_narrow(line, ctx=None):
    if not _find_delete_pattern(line):
        return False
    if _find_delete_broad(line, ctx):
        return False
    return True


def _find_delete_broad(line, ctx=None):
    if not _find_delete_pattern(line):
        return False
    return bool(re.search(r"\bfind\s+(/|/\*|\"\$HOME\"|\$HOME|~)(/|\s|$)", line))


# --------------------------------------------------------------------------------------
# destructive rules
# --------------------------------------------------------------------------------------

R("rm_root", "destructive", "critical", "Deletes an entire filesystem",
  "rm -rf against / or $HOME wipes the machine (or the home directory) with no undo. On a CI runner it can delete the wrong volume entirely.",
  "Scope the delete to a specific directory, resolve and print the target first, and use -- to end option parsing.",
  r"(?<![\w-])rm\s+(-[A-Za-z]*\s+)*(-[A-Za-z]*[rR][A-Za-z]*\s+)*(/\s*$|/\*|\$HOME|~/\*|\"\$HOME\"(/\*)?|\$\{HOME\}(/\*)?)")

R("rm_absolute_dir", "destructive", "critical", "Recursive delete of a system path",
  "Recursive deletion of /etc, /usr, /var, /bin, /lib or /boot breaks the operating system and cannot be repaired by reinstalling your app.",
  "Never recursively delete a system path. If a system path really must change, move the old copy aside instead of deleting it.",
  r"(?<![\w-])rm\s+[^|;&]*\s(/etc|/usr|/bin|/sbin|/lib|/boot)(\s|$|/)")

R("rm_force_var", "destructive", "high", "Recursive delete driven by an unquoted variable",
  "An unquoted variable in a delete target is word-split and glob-expanded. If the variable is empty, rm -rf $VAR/* becomes rm -rf /* and erases the filesystem.",
  "Guard the variable first: [ -n \"$DIR\" ] && [ -d \"$DIR\" ] && case \"$DIR\" in /|/home|/*) exit 1;; esac, then rm -rf -- \"$DIR\".",
  check=_rm_var_unquoted)



R("rm_no_dashdash", "destructive", "medium", "Delete without -- end-of-options marker",
  "A filename that begins with a dash is parsed as a flag, so rm $DIR where DIR holds -rf runs the wrong command.",
  "Use rm -rf -- \"$TARGET\" so anything that looks like a flag is treated as a literal path.",
  check=_rm_no_dashdash)

R("rm_var_target", "destructive", "medium", "Delete target is decided at run time",
  "The path being deleted is only known when the script runs, so a mistyped variable quietly deletes the wrong directory. Quoting stops word splitting, but it does not stop the wrong target.",
  "Resolve the path, print it, and refuse to continue unless it starts with the prefix you expect.",
  r"(?<!\w-])rm\s+(?:-[A-Za-z]*\s+)*[\"']\$(\{)?[A-Za-z_]\w*(\})?[\"']\s*;?\s*$")

R("find_delete", "destructive", "medium", "find with -delete or -exec rm",
  "find -delete removes every match with no confirmation and no undo. The match set is decided by the search root, so a wrong root deletes the wrong files.",
  "Run find ... -print first, review the list, then delete only the listed paths.",
  check=_find_delete_narrow)

R("find_delete_broad", "destructive", "high", "find -delete starting from a broad root",
  "A find that starts at / or in $HOME and deletes every match can wipe a filesystem in one command, with no undo.",
  "Scope the search to one directory and print the matches before deleting them.",
  check=_find_delete_broad)

R("dd_device", "destructive", "critical", "Raw block write to a device",
  "dd of=/dev/sdX overwrites a physical disk. There is no undo and it destroys every filesystem and partition on that device.",
  "Never point dd at a raw device in a script. Use a normal file target, or a tool that is explicitly scoped to the intended device.",
  r"dd\s+[^|;&]*of=/dev/(sd|hd|nvme|vd|disk|xvd)")

R("mkfs", "destructive", "critical", "Formats a filesystem",
  "mkfs erases the partition table and filesystem of the target device. Everything on that device is gone.",
  "Only ever run mkfs interactively, on a device you have just verified by hand.",
  r"\bmkfs(\.\w+)?\b")

R("write_device", "destructive", "critical", "Redirects output into a raw device",
  "Writing into /dev/sdX writes bytes straight to the disk, corrupting the filesystem.",
  "Redirect to a regular file path instead.",
  r">\s*/dev/(sd|hd|nvme|vd|disk)")

R("shred_device", "destructive", "critical", "shred on a block device",
  "shred is for regular files. Pointed at a device it destroys the disk contents.",
  "Use shred only on a regular file, and never in an automated script.",
  r"\bshred\s+[^|;&]*/dev/(sd|hd|nvme|vd)")

R("chmod_777_recursive", "destructive", "critical", "Recursive world-writable chmod",
  "chmod -R 777 makes every file below the path writable and executable by anyone on the machine. On a shared host this is a full compromise.",
  "Use 755 for directories and 644 for files, and apply them separately.",
  r"chmod\s+(-R\s+)?777\b")

R("chown_root_recursive", "destructive", "high", "Recursive ownership change to root",
  "chown -R root over a path can hand ownership of user data or a whole home directory to root, locking the owner out of their own files.",
  "Change ownership only on the specific files that need it.",
  r"chown\s+(-R\s+)?root\b")

R("overwrite_system_path", "destructive", "critical", "Writes over a system configuration file",
  "Redirecting output into /etc, /usr, /bin or /boot replaces a system file. A typo here takes the machine down.",
  "Write to a staging path and install with a package manager or a single explicit copy.",
  r">>?\s*(/etc|/usr|/bin|/sbin|/boot)/")

R("truncate_system_log", "destructive", "medium", "Truncates a system log",
  "Zeroing a log under /var/log removes the evidence you would need for an incident review, and can break log rotation.",
  "Rotate logs instead of truncating them, and never touch logs outside your own service directory.",
  r":\s*>\s*/var/log/")

R("git_clean_force", "destructive", "high", "git clean -fdx destroys untracked files",
  "-fdx removes ignored files too: build caches, .env files, downloaded fixtures and local databases all disappear without a prompt.",
  "Run git clean -ndx first and read the list. Prefer removing a named path: git clean -fd -- build/",
  r"git\s+clean\s+-[a-zA-Z]*[fdx]")

R("git_reset_hard", "destructive", "medium", "git reset --hard discards local work",
  "Uncommitted changes to tracked files are thrown away with no recovery path.",
  "git stash first, or use git reset --keep when you mean to preserve work.",
  r"git\s+reset\s+--hard")

R("git_push_force", "destructive", "high", "Force push overwrites remote history",
  "--force rewrites published history. On a shared branch it destroys other people's commits.",
  "Use --force-with-lease and only on a personal branch.",
  r"git\s+push\b[^|;&]*(--force|-f)\b")

R("db_destructive_sql", "destructive", "critical", "Destructive SQL statement",
  "DROP / TRUNCATE removes the table and its contents. There is no transaction rollback once it commits.",
  "Take a backup in the same script, then verify the row count before running the destructive statement.",
  r"\b(DROP\s+(DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE)\b")

R("kill_daemon", "destructive", "high", "Kills processes by name",
  "killall / pkill match every process with that name, including the one you did not mean to stop.",
  "Target a PID from a pidfile, or use a service manager (systemctl stop, launchctl) instead.",
  r"\b(killall|pkill)\b")

R("kill_init", "destructive", "critical", "Sends a signal to PID 1",
  "PID 1 is init. Killing it takes the whole machine down immediately.",
  "Never signal PID 1 from a script.",
  r"\bkill\s+(-9\s+)?1\b")

R("system_power", "destructive", "critical", "Powers the machine down",
  "shutdown / reboot / halt from an unattended script kills every other job that is running.",
  "Run power commands manually, never from automation.",
  r"\b(shutdown|reboot|halt|poweroff|init\s+0)\b")

R("rsync_delete", "destructive", "high", "rsync --delete removes destination files",
  "--delete erases anything at the destination that is not in the source. With a wrong source path that is a silent mass deletion.",
  "Dry run with --dry-run --itemize-changes before the first real run.",
  r"rsync\s+[^|;&]*--delete\b")

R("s3_delete", "destructive", "high", "S3 sync with --delete removes objects",
  "aws s3 sync --delete removes objects from the bucket that are not in the source, including versions you may still need.",
  "Use --dryrun, and restrict with --exclude.",
  r"aws\s+s3\s+sync\s+[^|;&]*--delete\b")

R("docker_prune_all", "destructive", "medium", "docker prune -a removes all unused images",
  "-a removes every image not used by a running container, including ones you deliberately kept for a rollback.",
  "Prune with a filter and prune images and volumes in separate, deliberate steps.",
  r"docker\s+(system\s+)?prune\s+[^|;&]*-a\b")

R("kubectl_delete_all", "destructive", "high", "kubectl delete --all removes every object",
  "--all removes every matching resource in the namespace, including pods you did not create.",
  "Delete by explicit name, and confirm the current namespace first.",
  r"kubectl\s+delete\s+[^|;&]*(--all\b|-l\s)")

R("terraform_destroy", "destructive", "high", "terraform destroy removes managed infrastructure",
  "destroy deletes real cloud resources: databases, buckets, disks. Data that is not in Terraform state is not restored.",
  "Run terraform plan -destroy and read it. Never wire destroy into an unattended job.",
  r"terraform\s+destroy\b")

R("mv_to_devnull", "destructive", "medium", "Moves a file into /dev/null",
  "The data is gone - mv across filesystems deletes the source after copying.",
  "Use rm only after confirming, and keep a copy until the run is verified.",
  r"\bmv\s+[^|;&]*/dev/null\b")

R("history_clear", "destructive", "medium", "Clears shell history",
  "history -c erases the record of what ran on the machine. In a shared or monitored environment that is a red flag on its own.",
  "Do not erase shell history from scripts.",
  r"\bhistory\s+-c\b")

# --------------------------------------------------------------------------------------
# security rules
# --------------------------------------------------------------------------------------

R("curl_pipe_shell", "security", "critical", "Downloads and runs code straight from the internet",
  "curl ... | sh executes whatever the server returns at that moment with no signature, no checksum and no review. A compromised or hijacked host owns the machine.",
  "Download to a file, verify the checksum or signature, review the diff, then run it as a separate step.",
  r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b")

R("curl_pipe_interpreter", "security", "high", "Pipes remote content into an interpreter",
  "Piping downloaded content into python / perl / ruby runs unreviewed remote code with the same trust problem as curl | sh.",
  "Download, verify, then execute.",
  r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b")

R("base64_exec", "security", "high", "Decodes and executes an encoded blob",
  "A base64 blob hides its contents from review. Decoding it and piping it to a shell hides what actually runs.",
  "Keep payloads in version control in plain text so they can be reviewed.",
  r"base64\s+(-d|--decode)[^|;]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b")

R("eval_variable", "security", "critical", "Evaluates a variable as code",
  "eval runs its argument as shell code. If the argument contains anything from the outside world - an argument, an environment variable, a file - this is remote code execution.",
  "Use arrays or $@ to pass arguments, and the [[ ]] test operator in bash.",
  r"\beval\b\s*[\"\']?\$\{?[A-Za-z0-9_]")

R("eval_any", "security", "high", "Uses eval",
  "eval re-parses a string as code, so quoting bugs and injection bugs become code execution.",
  "Prefer direct invocation. If you must build a command, use an array.",
  r"(^|[;&|]\s*)eval\b")

R("curl_insecure", "security", "high", "Disables TLS verification",
  "-k / --insecure turns off certificate checking, which is exactly the protection that stops a man-in-the-middle from rewriting what you download.",
  "Remove the flag. If a certificate is genuinely broken, fix the trust store on the host.",
  r"\b(curl|wget)\b[^|;]*(\s-k\b|--insecure\b)")

R("ssh_strict_host_key_off", "security", "high", "Disables SSH host key checking",
  "StrictHostKeyChecking=no accepts any host key, so the connection can be silently redirected to an attacker's machine and your credentials go to them.",
  "Add the host key to known_hosts once, out of band.",
  r"StrictHostKeyChecking\s*=\s*no")

R("chmod_777", "security", "high", "World-writable permissions",
  "chmod 777 lets any local user read, modify and execute the file. On a shared machine that is a foothold.",
  "755 for directories and executables, 644 for ordinary files, 600 for anything secret.",
  r"chmod\s+(?!777\b)-?[A-Za-z]*\s*777\b|\bchmod\s+777\b")

R("secret_literal", "security", "critical", "Hard-coded credential in the script",
  "A literal password, token or private key ends up in version control, in the process list and in every CI log that prints this script.",
  "Read the credential from a secret manager or the environment at runtime, and rotate anything that has been committed.",
  r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-/+]{6,}")

R("secret_token_format", "security", "critical", "Live-looking API token in the script",
  "That token shape matches a real credential format, so this looks like a working key rather than a placeholder.",
  "Revoke the key, then load it from the environment or a secret store.",
  r"(gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})")

R("private_key_block", "security", "critical", "Private key material in the script",
  "A private key block in a script is a key compromise the moment the file is shared, logged or committed.",
  "Mount the key from a secret store and set 600 on it.",
  r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

R("echo_secret", "security", "high", "Prints a secret to stdout",
  "Anything printed here lands in the CI log, the terminal scrollback and possibly a pasted bug report.",
  "Print only whether the value is set, never the value.",
  r"(?i)\b(echo|printf)\b[^|;]*\$\{?(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)\b")

R("env_dump", "security", "medium", "Dumps the whole environment",
  "env output routinely contains tokens and passwords that were exported for another tool.",
  "Print only the specific variables you need.",
  r"(^|[;&|]\s*)(env|printenv|set)\s*(\||$)")

R("curl_no_fail", "security", "medium", "curl can silently save an error page",
  "Without --fail, a 404 or 500 response body is written to the file as if it were the download, and the script carries on.",
  "Add --fail --show-error --location, and check the file size afterwards.",
  r"\bcurl\b[^|;]*>[^|;]*$")

R("plaintext_http", "security", "high", "Fetches over plain HTTP",
  "http:// traffic is readable and modifiable by anyone on the path. If this is a script or a package, the content can be swapped.",
  "Use https:// and verify the checksum of whatever you downloaded.",
  r"\bhttp://[^\s'\"]+")

R("password_on_cmdline", "security", "medium", "Password passed on the command line",
  "A password in the argument list is visible to every other process on the machine via ps.",
  "Use a prompt, MYSQL_PWD, or a credentials file with 600 permissions.",
  r"(-p\$|--password=|--token=|--api-key=)")

R("nc_exec", "security", "high", "nc with an execute flag",
  "nc -e hands a shell to a remote listener. This is the payload half of a reverse shell.",
  "Remove it. If you need a tunnel, use ssh -L.",
  r"\bnc\s+[^|;]*-e\b")

R("openssl_weak_cipher", "security", "medium", "Weak or broken cipher",
  "RC4, DES and MD5-based digests are broken. They protect nothing against anyone who has actually tried.",
  "Use aes-256-gcm or chacha20-poly1305, and sha256.",
  r"(?i)\bopenssl\b[^|;]*\b(rc4|des|des3|md5|ecb)\b")

R("world_readable_secret", "security", "high", "Makes a secret file world-readable",
  "644 on a credential file lets every account on the host read it.",
  "chmod 600 on the file, and put it in a directory with 700.",
  r"(?i)chmod\s+6[0-4][0-9][^|;]*(secret|password|token|key|cred)")

R("insecure_tmp", "security", "medium", "Writes sensitive data into /tmp",
  "/tmp is shared and world-writable. A predictable filename there can be pre-created or read by another user.",
  "Use mktemp, then chmod 600 on the result.",
  r">>?\s*/tmp/")

R("nc_reverse_shell", "security", "critical", "Reverse-shell pattern",
  "bash -i >& /dev/tcp/host/port pipes an interactive shell to a remote machine. This is what a compromised host looks like.",
  "Remove it and audit where it came from.",
  r"/dev/tcp/|/dev/udp/")

# --------------------------------------------------------------------------------------
# quoting rules
# --------------------------------------------------------------------------------------

R("unquoted_var", "quoting", "medium", "Unquoted variable expansion",
  "An unquoted expansion is split on whitespace and glob-expanded. A file name with a space becomes two arguments, and a variable holding * becomes every file in the directory.",
  "Always quote expansions: \"$VAR\".",
  quotable=True)

R("unquoted_cmd_sub", "quoting", "medium", "Unquoted command substitution",
  "$(...) unquoted is split into multiple words, so a multi-word result silently becomes several arguments.",
  "Quote it: \"$(...)\".",
  r"\$\([^)]*\)(?![\"'])")

R("for_ls_loop", "quoting", "medium", "for loop over ls output",
  "Parsing ls breaks on spaces in file names and breaks completely when a directory has thousands of entries.",
  "Use a glob: for f in ./*.txt; do ... done",
  r"for\s+\w+\s+in\s+\$\(\s*ls\b")

R("test_unquoted", "quoting", "medium", "Unquoted variable inside [ ]",
  "[ $x = y ] breaks when the value is empty or contains a space: bash reports 'unary operator expected' or a syntax error.",
  "Use [[ $x == y ]] in bash, or [ \"$x\" = \"y\" ] in POSIX sh.",
  r"\[\s*\$[A-Za-z_{]")

R("cd_unquoted", "quoting", "low", "Unquoted path in cd",
  "An unquoted path with a space silently changes directory to the wrong place.",
  "Quote the path: cd \"$DIR\"",
  r"^\s*cd\s+[^\"'][^\s]*\$")

R("echo_var_split", "quoting", "low", "echo of an unquoted variable",
  "echo $x word-splits the value, so a value with spaces prints as several words.",
  "Use printf '%s\n' \"$x\".",
  r"^\s*echo\s+[^\"'][^\s]*\$")

# --------------------------------------------------------------------------------------
# portability rules
# --------------------------------------------------------------------------------------

R("missing_shebang", "portability", "medium", "No shebang line",
  "Without #!, the shell that runs the script is whatever invoked it. Run under bash by accident and under sh by accident, and the two behave differently.",
  "Add a shebang: #!/usr/bin/env bash",
  scope="script")

R("bashism_in_sh", "portability", "high", "bash syntax in a POSIX sh script",
  "Under /bin/sh (dash on Debian/Ubuntu, ash on Alpine) these constructs fail at runtime, often deep into a long pipeline.",
  "Either change the shebang to #!/usr/bin/env bash, or rewrite the construct in POSIX sh.",
  scope="script")

R("which_cmd", "portability", "low", "which instead of command -v",
  "which is not POSIX and returns different results for aliases and shell functions.",
  "Use command -v.",
  r"(^|[;&|]\s*)which\s+")

R("sed_i_no_suffix", "portability", "medium", "sed -i without a backup suffix",
  "GNU sed takes -i.bak; BSD sed takes -i and -i requires an argument. The same line works on one OS and errors on the other.",
  "Use sed -i.bak and delete the backup afterwards, or sed -i'' on macOS.",
  r"\bsed\s+[^|;]*-i(\s|$)")

R("date_d", "portability", "medium", "date -d is GNU-only",
  "BSD date uses -j -f with a format string, so date -d fails on macOS.",
  "Use date -u +%Y-%m-%d for portable timestamps, or branch on uname.",
  r"\bdate\s+[^|;]*\s-d\b")

R("readlink_f", "portability", "low", "readlink -f is not on macOS",
  "macOS readlink has no -f flag, so the command errors out.",
  "Use a portable pattern or resolve the path in Python.",
  r"\breadlink\s+[^|;]*-f\b")

R("grep_p", "portability", "low", "grep -P is not everywhere",
  "PCRE support is missing from BSD grep and some busybox builds.",
  "Use grep -E for portable extended regular expressions.",
  r"\bgrep\s+[^|;]*-P\b")

R("echo_e", "portability", "low", "echo -e is not portable",
  "POSIX echo has no -e flag; some shells print a literal -e and others interpret escapes. Behaviour differs between sh and bash.",
  "Use printf '\\n' or printf with an explicit format.",
  r"\becho\s+-e\b")

R("python_cmd", "portability", "low", "Calls python instead of python3",
  "Many systems have no python binary, or point it at Python 2.",
  "Call python3 explicitly.",
  r"(^|[;&|\s])python\s+[-A-Za-z0-9_./]+")

R("apt_not_noninteractive", "portability", "medium", "apt-get without -y or DEBIAN_FRONTEND",
  "apt-get waits for a confirmation prompt that never arrives in CI, so the job hangs until the timeout.",
  "Use DEBIAN_FRONTEND=noninteractive apt-get install -y ...",
  r"\bapt(-get)?\s+install\b")

R("mkdir_p_missing", "portability", "low", "mkdir without -p",
  "mkdir without -p fails when the directory already exists, which turns a rerun into a failure.",
  "Use mkdir -p.",
  r"\bmkdir\s+(?!--)(?![-]*p)\S")

# --------------------------------------------------------------------------------------
# error handling rules
# --------------------------------------------------------------------------------------

R("missing_set_flags", "error_handling", "medium", "No strict mode",
  "Without set -euo pipefail the script keeps going after a failed command, uses an unset variable as an empty string, and only notices a broken pipe at the end.",
  "Add set -euo pipefail after the shebang.",
  scope="script")

R("no_pipefail", "error_handling", "low", "No pipefail",
  "In a pipeline, only the exit status of the last command is checked, so curl can fail while the pipeline still reports success.",
  "Add set -o pipefail.",
  scope="script")

R("cd_without_check", "error_handling", "medium", "cd without an error check",
  "If the directory does not exist the script continues in the wrong directory and then writes files to the wrong place.",
  "Use cd \"$DIR\" || exit 1.",
  scope="script")

R("no_cleanup_trap", "error_handling", "low", "No cleanup trap",
  "If the script fails halfway, temp files and partial downloads are left behind.",
  "Add trap cleanup EXIT INT TERM at the top.",
  scope="script")

R("unchecked_commands", "error_handling", "low", "Unchecked command failures",
  "Commands that can fail are not followed by || exit or && chaining, so a failure is silently ignored.",
  "Check the exit status of anything that matters.",
  scope="script")

R("stderr_suppressed", "error_handling", "low", "Errors are being thrown away",
  "2>/dev/null hides the exact message you need when something goes wrong.",
  "Capture the error and print it, or redirect to a log file.",
  scope="script")

R("no_usage_fn", "error_handling", "low", "No usage or help function",
  "A script that takes arguments but has no --help output is hard to call correctly and impossible to self-document.",
  "Add a usage() function and call it on -h/--help or on a bad argument count.",
  scope="script")

R("no_dependency_check", "error_handling", "low", "No dependency checks",
  "If a required tool is missing the script fails partway through, after it has already changed some state.",
  "Check for each tool with command -v at the top and exit with a clear message.",
  scope="script")

R("subshell_cd", "error_handling", "low", "cd inside a subshell",
  "A cd inside $(...) or a pipeline runs in a subshell, so it does not change the directory of the script.",
  "cd in the main shell, or use a subshell with cd at the start of the body.",
  r"\$\([^)]*\bcd\b")

R("background_orphan", "error_handling", "low", "Background process without cleanup",
  "A background job started with & can be orphaned when the script exits and keep running with no way to stop it.",
  "Capture the PID and kill it in the EXIT trap.",
  r"(^|[;&|]\s*)\w+[^|;&]*&\s*$")

R("no_arg_validation", "error_handling", "low", "Arguments are not validated",
  "The script reads positional parameters without checking they exist, so a missing argument silently becomes an empty string.",
  "Check $# and validate each argument before using it.",
  scope="script")

R("temp_file_predictable", "error_handling", "medium", "Predictable temp filename",
  "A fixed name in /tmp can be pre-created by another user (a symlink attack) or collide with a concurrent run.",
  "Use mktemp and trap to remove it.",
  r"\btmp\w*=|/tmp/[\w.-]+")
