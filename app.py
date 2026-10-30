"""bash-guard-forge - local-first shell script safety reviewer.

Flask app: paste a shell script, get a risk review, a plain-English read of what it
does, a scored risk breakdown, a safer patch and a Markdown/JSON export.
Everything stays local. No API keys, no network calls.
"""
from __future__ import annotations

import datetime
import json
import os
import sqlite3
import uuid

from flask import Flask, Response, jsonify, render_template, request

from analysis import analyze

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "guard.db")

app = Flask(__name__)

# --------------------------------------------------------------------------------------
# samples
# --------------------------------------------------------------------------------------

SAMPLES = {
    "ci-deploy": {
        "title": "CI deploy that will bite you",
        "env": "ci",
        "shell": "bash",
        "intent": "Deploy the app to the staging box and restart nginx.",
        "script": """#!/bin/bash
# deploy.sh - one line, no questions asked
cd /srv/app
curl -sSL https://get.example.com/install.sh | bash
rm -rf /var/log/app/*
export API_KEY=sk-live-9f8a7b6c5d4e3f2a1b0c9d8e
echo $API_KEY
chmod -R 777 /srv/app
git push --force origin main
kubectl delete pods --all
""",
    },
    "nightly-cleanup": {
        "title": "Nightly cleanup (sloppy but recoverable)",
        "env": "prod",
        "shell": "bash",
        "intent": "Delete old logs and archive them to /var/backups.",
        "script": """#!/bin/bash
LOGDIR=/var/log/app
BACKUP=/var/backups
cd $LOGDIR
find . -name '*.log' -mtime +30 -delete
tar -czf $BACKUP/logs.tar.gz $(ls *.log | head -20)
rm $LOGDIR/*.log
sed -i 's/verbose = true/verbose = false/' $LOGDIR/app.conf
which rsync
""",
    },
    "safe-backup": {
        "title": "Backup script done properly",
        "env": "prod",
        "shell": "bash",
        "intent": "Nightly backup of the config directory, with a checksum and a 7 day retention.",
        "script": """#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <source_dir> <dest_dir>"
  exit 1
}

[ "$#" -eq 2 ] || usage

SRC_DIR="$1"
DEST_DIR="$2"

command -v rsync >/dev/null 2>&1 || { echo "rsync is required" >&2; exit 1; }

[ -d "$SRC_DIR" ] || { echo "source dir does not exist" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$DEST_DIR/backup-$STAMP"

mkdir -p "$TARGET"

cleanup() {
  rm -rf "$TARGET.tmp"
}
trap cleanup EXIT INT TERM

rsync -a --exclude '*.tmp' "$SRC_DIR/" "$TARGET/"
tar -czf "$TARGET.tar.gz" -C "$DEST_DIR" "$(basename "$TARGET")"
sha256sum "$TARGET.tar.gz" > "$TARGET.tar.gz.sha256"
find "$DEST_DIR" -name 'backup-*.tar.gz' -mtime +7 -delete

echo "backup written to $TARGET.tar.gz"
""",
    },
    "docker-publish": {
        "title": "Docker publish with a host backdoor",
        "env": "ci",
        "shell": "bash",
        "intent": "Build and push the app image to the registry.",
        "script": """#!/usr/bin/env bash
set -e

IMAGE="registry.example.com/app:latest"
docker build -t $IMAGE .
docker run --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/app $IMAGE build
docker push $IMAGE
ssh -o StrictHostKeyChecking=no deploy@10.0.0.5 "docker pull $IMAGE && docker restart app"
""",
    },
}

# --------------------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------------------


def get_db() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            title TEXT NOT NULL,
            env TEXT NOT NULL,
            script TEXT NOT NULL,
            intent TEXT NOT NULL DEFAULT '',
            score REAL NOT NULL,
            verdict TEXT NOT NULL,
            findings_count INTEGER NOT NULL,
            payload TEXT NOT NULL,
            rating INTEGER,
            notes TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.commit()
    conn.close()


def save_session(script: str, env: str, intent: str, result: dict) -> str:
    sid = uuid.uuid4().hex[:12]
    first = script.strip().splitlines()[0] if script.strip() else "untitled script"
    title = (intent or first).strip().replace("\n", " ")[:90] or "untitled script"
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (id, created_at, title, env, script, intent, score, verdict, findings_count, payload)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            sid,
            datetime.datetime.now().isoformat(timespec="seconds"),
            title,
            env,
            script,
            intent,
            result["score"],
            result["verdict"],
            result["findings_count"],
            json.dumps(result),
        ),
    )
    conn.commit()
    conn.close()
    return sid


def load_session(sid: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
    conn.close()
    return row


# --------------------------------------------------------------------------------------
# export helpers
# --------------------------------------------------------------------------------------


def render_markdown(meta: dict, result: dict) -> str:
    lines = []
    lines.append("# bash-guard-forge review")
    lines.append("")
    lines.append("**Score:** %s / 100  **Verdict:** %s (%s)" % (result["score"], result["verdict_label"], result["verdict"]))
    lines.append("**Environment:** %s  **Shell:** %s" % (result["env_label"], result["shell"]))
    lines.append("**Findings:** %d critical / %d high / %d medium / %d low" % (
        result["counts"]["critical"], result["counts"]["high"],
        result["counts"]["medium"], result["counts"]["low"]))
    lines.append("")
    if meta.get("intent"):
        lines.append("**Stated intent:** %s" % meta["intent"])
        lines.append("")
    lines.append("## Risk axes")
    lines.append("")
    for ax in result["axes"]:
        lines.append("- **%s** - %s/100 (weight %.0f%%)" % (ax["label"], ax["score"], ax["weight"] * 100))
    lines.append("")
    lines.append("## What this script does")
    lines.append("")
    for step in result["steps"][:25]:
        lines.append("%d. [line %d] %s - %s" % (step["n"], step["line"], step["raw"], step["description"]))
    lines.append("")
    blast = result["blast"]
    lines.append("## Blast radius")
    lines.append("")
    if blast["paths"]:
        lines.append("- Paths touched: %s" % ", ".join(blast["paths"]))
    if blast["system_paths"]:
        lines.append("- System paths: %s" % ", ".join(blast["system_paths"]))
    if blast["hosts"]:
        lines.append("- Hosts contacted: %s" % ", ".join(blast["hosts"]))
    if blast["packages"]:
        lines.append("- Packages: %s" % ", ".join(blast["packages"]))
    if blast["escalates_to_root"]:
        lines.append("- Escalates to root")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = sorted(result["findings"], key=lambda f: (order[f["severity"]], f["line"]))
    for f in findings:
        lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines.append("")
        lines.append("- **Axis:** %s" % f["axis_label"])
        lines.append("- **Line:** %d" % f["line"])
        if f["evidence"]:
            lines.append("- **Code:** %s" % f["evidence"])
        lines.append("- **Why it matters:** %s" % f["why"])
        lines.append("- **Fix:** %s" % f["fix"])
        lines.append("")
    if result.get("patch", {}).get("available"):
        lines.append("## Safer patch")
        lines.append("")
        lines.append("~~~diff")
        lines.append(result["patch"]["diff"])
        lines.append("~~~")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html", sample_ids=list(SAMPLES.keys()))


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "app": "bash-guard-forge", "samples": len(SAMPLES)})


@app.route("/api/samples")
def api_samples():
    return jsonify([
        {"id": k, "title": v["title"], "env": v["env"], "shell": v["shell"],
         "intent": v["intent"], "script": v["script"]}
        for k, v in SAMPLES.items()
    ])


@app.route("/api/sample/<sid>")
def api_sample(sid: str):
    if sid not in SAMPLES:
        return jsonify({"error": "unknown sample"}), 404
    return jsonify({"id": sid, **SAMPLES[sid]})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    script = data.get("script") or ""
    env = data.get("env") or "default"
    shell = data.get("shell") or "bash"
    intent = data.get("intent") or ""
    if not script.strip():
        return jsonify({"error": "script is empty"}), 400
    if len(script) > 200000:
        return jsonify({"error": "script is too large (200k characters max)"}), 400
    result = analyze(script, env=env, shell=shell, intent=intent)
    sid = save_session(script, env, intent, result)
    result["session_id"] = sid
    return jsonify(result)


@app.route("/api/sessions")
def api_sessions():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, created_at, title, env, score, verdict, findings_count, rating, notes"
        " FROM sessions ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/sessions/<sid>")
def api_session(sid: str):
    row = load_session(sid)
    if row is None:
        return jsonify({"error": "session not found"}), 404
    payload = json.loads(row["payload"])
    payload["session_id"] = row["id"]
    payload["title"] = row["title"]
    payload["rating"] = row["rating"]
    payload["notes"] = row["notes"]
    payload["script"] = row["script"]
    payload["created_at"] = row["created_at"]
    return jsonify(payload)


@app.route("/api/sessions/<sid>", methods=["PATCH"])
def api_patch_session(sid: str):
    row = load_session(sid)
    if row is None:
        return jsonify({"error": "session not found"}), 404
    data = request.get_json(silent=True) or {}
    rating = data.get("rating", row["rating"])
    notes = data.get("notes", row["notes"])
    conn = get_db()
    conn.execute("UPDATE sessions SET rating = ?, notes = ? WHERE id = ?", (rating, notes, sid))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": sid, "rating": rating, "notes": notes})


@app.route("/api/export/<sid>")
def api_export(sid: str):
    row = load_session(sid)
    if row is None:
        return jsonify({"error": "session not found"}), 404
    payload = json.loads(row["payload"])
    fmt = (request.args.get("fmt") or "md").lower()
    meta = {"intent": row["intent"], "title": row["title"]}
    if fmt == "json":
        body = json.dumps({**payload, "intent": row["intent"]}, indent=2)
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=bash-guard-%s.json" % sid})
    if fmt == "patch":
        patch = payload.get("patch", {})
        if not patch.get("available"):
            return Response("No mechanical patch is available for this script.\n", mimetype="text/plain")
        body = patch["diff"] + "\n"
        return Response(body, mimetype="text/x-diff",
                        headers={"Content-Disposition": "attachment; filename=bash-guard-%s.patch" % sid})
    body = render_markdown(meta, payload)
    return Response(body, mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=bash-guard-%s.md" % sid})


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    init_db()
    print("bash-guard-forge running on http://127.0.0.1:5057")
    app.run(host="127.0.0.1", port=5057, debug=False)
