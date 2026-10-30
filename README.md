# bash-guard-forge

**Paste a shell script. Get a risk review, a plain-English read of what it actually does, and a safer patch.**

bash-guard-forge is a local-first static reviewer for bash / sh / zsh scripts. It reads the
text you paste, it never runs your script, and it never calls out to the network. No API keys,
no telemetry, no account.

It exists because the worst shell incidents are not subtle bugs - they are a curl piped into
a shell, an rm -rf where the variable is empty, a token pasted straight into a script, or a
chmod -R 777 that was meant to be 755. Those are exactly the things a reviewer should catch
and exactly the things people skim past.

---

## What you get

1. **A 0-100 risk score** with five weighted axes:
   - *Blast radius* - what the script can delete, overwrite or take down
   - *Quoting safety* - unquoted expansions, unquoted command substitution, for-loops over ls
   - *Secret & trust* - credentials in the file, code downloaded and executed, TLS checks turned off
   - *Portability* - missing shebang, bash syntax in a POSIX sh script, GNU-only flags
   - *Failure handling* - unchecked cd, no strict mode, no cleanup trap, swallowed errors
2. **A step-by-step read** of what the script does, in plain English, in execution order.
3. **A blast radius summary** - paths touched, system paths, hosts contacted, packages,
   databases, whether it escalates to root.
4. **Every finding with evidence, why it matters, and a concrete fix.**
5. **A safer patch** - a unified diff with the mechanical fixes applied (quoting, permissions,
   portability, strict mode).
6. **Exports** - Markdown, JSON, and the .patch file.
7. **A local review log** - SQLite, with a 1-5 star self-rating and notes per review.

## The rule library

91 rules across the five axes. A representative slice:

| Axis | Examples |
| --- | --- |
| Blast radius | rm -rf /, rm -rf "$HOME", dd of=/dev/sda, mkfs, DROP DATABASE, find / -delete, git clean -fdx, git push --force, kubectl delete --all, terraform destroy, rsync --delete, crontab -r, iptables -F, kill -9 1 |
| Secret & trust | curl piped into sh, eval "$1", source of a downloaded file, hard-coded tokens, private key blocks, -k / --insecure, StrictHostKeyChecking=no, chmod 777, the Docker socket mounted into a container, --privileged, reverse-shell patterns |
| Quoting safety | unquoted $VAR, unquoted $(...), for f in $(ls ...), [ $x = y ], rm $DIR/*.log |
| Portability | missing shebang, [[ ]] / local / += in a #!/bin/sh script, sed -i without a suffix, date -d, readlink -f, grep -P, echo -e, which instead of command -v |
| Failure handling | no set -euo pipefail, cd without "|| exit 1", no trap cleanup, missing command -v dependency checks, 2>/dev/null everywhere, no usage function, unchecked arguments |

Severity is critical / high / medium / low. A single critical finding caps the score,
because one curl-into-a-shell is enough to change the verdict.

## Scoring

- Each axis starts at 100 and loses points per finding (critical 24, high 11, medium 5, low 2).
  Repeated hits of the same rule are damped so one noisy pattern does not dominate.
- Axis weights change with the environment you pick:
  - *CI pipeline* leans on failure handling and portability
  - *Production server* leans on blast radius and secrets
  - *Running as root* leans hardest on blast radius and secrets
  - *Code review* is balanced
- A weak axis caps the overall verdict: you cannot be "deploy ready" with a broken axis.
- Ten or more findings costs extra points, because a pile of small problems is a problem.

Verdict bands: deploy_ready (85+), mostly_safe (70+), needs_review (55+),
tight_but_usable (40+), dangerous_do_not_run (below 40).

## Run it

~~~bash
cd bash-guard-forge
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
~~~

Then open http://127.0.0.1:5057

There is also a one-liner:

~~~bash
./run.sh
~~~

## Tests

~~~bash
python3 -m unittest discover -s tests -v
~~~

33 tests covering the rule engine, the scoring bands, the patch generator and the REST API.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | / | the app |
| POST | /api/analyze | body: script, env, shell, intent - returns the full review |
| GET | /api/samples | the built-in sample scripts |
| GET | /api/sample/&lt;id&gt; | one sample |
| GET | /api/sessions | review history |
| GET | /api/sessions/&lt;id&gt; | one stored review |
| PATCH | /api/sessions/&lt;id&gt; | body: rating, notes |
| GET | /api/export/&lt;id&gt;?fmt=md,json,patch | export |
| GET | /api/health | health check |

## Layout

~~~
app.py              Flask app, REST API, SQLite store, exports, samples
engine.py           rule library (core) + shell parsing helpers
rules_extra.py      the second half of the rule library
analysis.py         findings, timeline, blast radius, scoring, patch generation
templates/          single page UI
static/             dark UI, vanilla JS, no framework
tests/              smoke tests
data/               local SQLite database (created on first run, git-ignored)
~~~

## Tech

Python 3.10+, Flask, SQLite, vanilla HTML/CSS/JS. The analysis engine is pure standard
library - no pandas, no LLM, no API keys, no network access at any point.

## Limits worth knowing

This is static analysis of the text you paste. It does not resolve variables, follow
symlinks, or understand what a function called from a sourced file does. Treat the score
as a second pair of eyes, not as a guarantee - and read the findings, not just the number.
