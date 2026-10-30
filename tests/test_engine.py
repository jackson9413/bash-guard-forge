"""Smoke tests for bash-guard-forge. Run: python3 -m unittest discover -s tests"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analysis import analyze  # noqa: E402

DANGEROUS = """#!/bin/bash
cd /srv/app
curl -sSL https://get.example.com/install.sh | bash
rm -rf /var/log/app/*
export API_KEY=sk-live-9f8a7b6c5d4e3f2a1b0c9d8e
echo $API_KEY
chmod -R 777 /srv/app
"""

SAFE = """#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <src>"
  exit 1
}

[ "$#" -eq 1 ] || usage
SRC_DIR="$1"

command -v rsync >/dev/null 2>&1 || { echo "rsync is required" >&2; exit 1; }

[ -d "$SRC_DIR" ] || { echo "missing dir" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "/var/backups/$STAMP"

cleanup() {
  rm -rf "/var/backups/$STAMP.tmp"
}
trap cleanup EXIT INT TERM

rsync -a "$SRC_DIR/" "/var/backups/$STAMP/"
sha256sum "/var/backups/$STAMP" > "/var/backups/$STAMP.sha256"
echo "done"
"""


def ids(result):
    return set(f["id"] for f in result["findings"])


class EngineTests(unittest.TestCase):
    def test_dangerous_script_is_flagged(self):
        r = analyze(DANGEROUS, env="prod")
        got = ids(r)
        self.assertIn("curl_pipe_shell", got)
        self.assertIn("secret_token_format", got)
        self.assertIn("chmod_777_recursive", got)
        self.assertLess(r["score"], 40)
        self.assertEqual(r["verdict"], "dangerous_do_not_run")

    def test_safe_script_scores_high(self):
        r = analyze(SAFE, env="prod")
        self.assertGreaterEqual(r["score"], 80)
        self.assertEqual(r["verdict"], "deploy_ready")

    def test_safe_script_has_no_high_findings(self):
        r = analyze(SAFE, env="prod")
        high = [f for f in r["findings"] if f["severity"] in ("critical", "high")]
        self.assertEqual(high, [], "safe script should not raise critical/high findings: %s" % high)

    def test_rm_root_flagged(self):
        r = analyze("#!/bin/bash\nrm -rf /\n")
        self.assertIn("rm_root", ids(r))

    def test_rm_home_flagged(self):
        r = analyze('#!/bin/bash\nrm -rf "$HOME"\n')
        self.assertIn("rm_root", ids(r))

    def test_unquoted_var_detected_and_quoted_not(self):
        a = analyze("#!/bin/bash\necho $NAME\n")
        b = analyze('#!/bin/bash\necho "$NAME"\n')
        self.assertIn("unquoted_var", ids(a))
        self.assertNotIn("unquoted_var", ids(b))

    def test_unquoted_var_not_flagged_in_assignment(self):
        r = analyze("#!/bin/bash\nFOO=$BAR\n")
        self.assertNotIn("unquoted_var", ids(r))

    def test_command_substitution_unquoted_detected(self):
        r = analyze("#!/bin/bash\ntar -czf out.tgz $(ls *.log)\n")
        self.assertIn("unquoted_cmd_sub", ids(r))

    def test_bashism_in_sh_detected(self):
        r = analyze("#!/bin/sh\nif [[ -f file ]]; then\n  echo yes\nfi\n")
        self.assertIn("bashism_in_sh", ids(r))

    def test_bashism_not_flagged_in_bash(self):
        r = analyze("#!/bin/bash\nif [[ -f file ]]; then\n  echo yes\nfi\n")
        self.assertNotIn("bashism_in_sh", ids(r))

    def test_missing_shebang_detected(self):
        r = analyze("echo hello\n")
        self.assertIn("missing_shebang", ids(r))

    def test_set_flags_present_not_flagged(self):
        r = analyze("#!/bin/bash\nset -euo pipefail\necho ok\n")
        self.assertNotIn("missing_set_flags", ids(r))

    def test_eval_variable_is_critical(self):
        r = analyze('#!/bin/bash\neval "$1"\n')
        sev = [f["severity"] for f in r["findings"] if f["id"] == "eval_variable"]
        self.assertEqual(sev, ["critical"])

    def test_docker_socket_mount_is_critical(self):
        r = analyze("#!/bin/bash\ndocker run -v /var/run/docker.sock:/var/run/docker.sock img\n")
        sev = [f["severity"] for f in r["findings"] if f["id"] == "docker_socket_mount"]
        self.assertEqual(sev, ["critical"])

    def test_tls_verification_off(self):
        r = analyze("#!/bin/bash\ncurl -k https://example.com/x.sh -o x.sh\n")
        self.assertIn("curl_insecure", ids(r))

    def test_strict_host_key_off(self):
        r = analyze("#!/bin/bash\nssh -o StrictHostKeyChecking=no host uptime\n")
        self.assertIn("ssh_strict_host_key_off", ids(r))

    def test_drop_database(self):
        r = analyze("#!/bin/bash\npsql -c 'DROP DATABASE prod;'\n")
        self.assertIn("db_destructive_sql", ids(r))

    def test_patch_quotes_variable(self):
        r = analyze("#!/bin/bash\necho $NAME\n")
        self.assertTrue(r["patch"]["available"])
        self.assertIn('"$NAME"', r["patch"]["diff"])

    def test_patch_inserts_strict_mode(self):
        r = analyze("#!/bin/bash\necho hi\n")
        self.assertIn("set -euo pipefail", r["patch"]["diff"])

    def test_patch_absent_for_clean_script(self):
        r = analyze(SAFE, env="prod")
        self.assertFalse(r["patch"]["available"])

    def test_steps_describe_script(self):
        r = analyze(DANGEROUS, env="prod")
        cats = set(s["category"] for s in r["steps"])
        self.assertIn("execute_remote", cats)
        self.assertIn("delete", cats)

    def test_blast_radius_captures_host_and_path(self):
        r = analyze(DANGEROUS, env="prod")
        self.assertIn("get.example.com", r["blast"]["hosts"])
        self.assertTrue(r["blast"]["system_paths"])

    def test_environment_changes_weights(self):
        r_ci = analyze("#!/bin/bash\ncd /x\n", env="ci")
        r_prod = analyze("#!/bin/bash\ncd /x\n", env="prod")
        w_ci = dict((a["id"], a["weight"]) for a in r_ci["axes"])
        w_prod = dict((a["id"], a["weight"]) for a in r_prod["axes"])
        self.assertGreater(w_prod["destructive"], w_ci["destructive"])
        self.assertGreater(w_ci["error_handling"], w_prod["error_handling"])

    def test_all_five_axes_present(self):
        r = analyze("echo hi\n")
        self.assertEqual(len(r["axes"]), 5)

    def test_counts_match_findings(self):
        r = analyze(DANGEROUS, env="prod")
        total = sum(r["counts"].values())
        self.assertEqual(total, len(r["findings"]))

    def test_empty_script_handled(self):
        r = analyze("")
        self.assertEqual(r["findings_count"], 0)


class ApiTests(unittest.TestCase):
    def setUp(self):
        os.environ["BGF_TEST"] = "1"
        import app as app_module
        app_module.DB_PATH = os.path.join(ROOT, "data", "test_guard.db")
        app_module.DATA_DIR = os.path.dirname(app_module.DB_PATH)
        app_module.init_db()
        self.client = app_module.app.test_client()

    def tearDown(self):
        try:
            os.remove(os.path.join(ROOT, "data", "test_guard.db"))
        except OSError:
            pass

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_samples_available(self):
        r = self.client.get("/api/samples")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(len(r.get_json()), 4)

    def test_analyze_empty_script_rejected(self):
        r = self.client.post("/api/analyze", json={"script": "   "})
        self.assertEqual(r.status_code, 400)

    def test_analyze_then_fetch_session(self):
        r = self.client.post("/api/analyze", json={"script": DANGEROUS, "env": "prod", "intent": "deploy"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        sid = data["session_id"]
        got = self.client.get("/api/sessions/" + sid)
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.get_json()["session_id"], sid)

    def test_patch_rating_and_notes(self):
        r = self.client.post("/api/analyze", json={"script": "#!/bin/bash\necho $NAME\n"})
        sid = r.get_json()["session_id"]
        p = self.client.patch("/api/sessions/" + sid, json={"rating": 4, "notes": "fixed by hand"})
        self.assertEqual(p.status_code, 200)
        got = self.client.get("/api/sessions/" + sid).get_json()
        self.assertEqual(got["rating"], 4)
        self.assertEqual(got["notes"], "fixed by hand")

    def test_exports(self):
        r = self.client.post("/api/analyze", json={"script": "#!/bin/bash\necho $NAME\n"})
        sid = r.get_json()["session_id"]
        md = self.client.get("/api/export/" + sid + "?fmt=md")
        self.assertEqual(md.status_code, 200)
        self.assertIn("bash-guard-forge review", md.get_data(as_text=True))
        js = self.client.get("/api/export/" + sid + "?fmt=json")
        self.assertEqual(js.status_code, 200)
        self.assertIn("findings", js.get_data(as_text=True))
        pt = self.client.get("/api/export/" + sid + "?fmt=patch")
        self.assertEqual(pt.status_code, 200)
        self.assertIn("---", pt.get_data(as_text=True))

    def test_history_list(self):
        self.client.post("/api/analyze", json={"script": "#!/bin/bash\necho hi\n"})
        rows = self.client.get("/api/sessions").get_json()
        self.assertGreaterEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
