import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from types import SimpleNamespace

from alert_doctor import analyzer
from alert_doctor.analyzer import Analyzer, should_escalate, validate_verdict
from alert_doctor.config import ChannelSpec, Config, RepoSpec, SystemSpec
from alert_doctor.models import CheckSpec, ParsedAlert
from alert_doctor.store import Store

CH = "C1"
NOW = 1_800_000_000.0


def good(**kw):
    v = {"category": "transient", "severity": "low", "confidence": 0.9,
         "cause": "c", "impact": "i", "project": "repo", "action": "observe",
         "fix": ["若明天同時段再發生,比對結束 log 時間"],
         "fix_in_system": "unknown", "needs_human": False, "evidence": []}
    v.update(kw)
    return v


def analyzer_max_attempts():
    from alert_doctor.store import MAX_ANALYSIS_ATTEMPTS
    return MAX_ANALYSIS_ATTEMPTS


class FakeSlack:
    def __init__(self):
        self.posts, self.reactions, self.full_reactions = [], [], []

    def post_message(self, token, channel, text, thread_ts=None):
        self.posts.append((channel, text, thread_ts))
        return f"9.{len(self.posts)}"

    def add_reaction(self, token, channel, ts, name):
        self.reactions.append(("add", name))
        self.full_reactions.append(("add", channel, ts, name))

    def remove_reaction(self, token, channel, ts, name):
        self.reactions.append(("remove", name))
        self.full_reactions.append(("remove", channel, ts, name))


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.makedirs(os.path.join(self.tmp.name, "app"))
        with open(os.path.join(self.tmp.name, "app", "a.py"), "w") as f:
            f.write("one\ntwo\nthree\n")
        self.ev = {"total": 3, "samples": [{"request_id": "r1"}]}

    def check(self, v):
        return validate_verdict(v, {"r": self.tmp.name}, self.ev)

    def test_valid(self):
        v = good(evidence=[{"type": "code", "repo": "r", "file": "app/a.py", "line": 3},
                           {"type": "elk", "key": "samples[0].request_id"},
                           {"type": "elk", "key": "total"}])
        self.assertEqual(self.check(v), [])

    def test_long_fix_naming_code_location_passes_untouched(self):
        step = "user/views.py TWCALoginAPIView 的 except 加 CacheManagerException,回 ResResult.INVALID_USER"
        v = good(fix=[step])
        self.assertEqual(self.check(v), [])
        self.assertEqual(v["fix"], [step])

    def test_overlong_fix_is_trimmed_without_blocking(self):
        v = good(fix=["改" * 200])
        problems = self.check(v)
        self.assertEqual(analyzer._blocking(problems), [])
        self.assertTrue(problems[0].startswith(analyzer.FIX_TRIMMED))
        self.assertEqual(len(v["fix"][0]), analyzer.FIX_ITEM_HARD_CHARS)
        self.assertTrue(v["fix"][0].endswith("…"))
        self.assertFalse(should_escalate(v, problems, CheckSpec(key="k")))

    def test_repairable_parts_are_dropped_not_rejected(self):
        code = [{"type": "code", "repo": "r", "file": "app/a.py", "line": n} for n in (1, 2, 3, 1)]
        v = good(remark=3, evidence=code)
        problems = self.check(v)
        self.assertEqual(analyzer._blocking(problems), [])
        self.assertNotIn("remark", v)
        self.assertEqual(len(v["evidence"]), analyzer.MAX_CODE_EVIDENCE)

    def test_field_errors(self):
        for bad in (good(category="x"), good(severity="x"), good(confidence=1.5),
                    good(confidence=True), good(cause=""), good(impact=" "), good(project=None),
                    good(action="fix_code", fix=[]), good(fix="f"), good(fix=["ok", ""]),
                    good(needs_human="no"), good(evidence="x"), good(fix_in_system=""),
                    good(fix_in_system=None)):
            self.assertTrue(self.check(bad), bad)
        for key in ("cause", "impact", "project", "fix"):
            v = good(category="unknown", action="investigate", needs_human=True, confidence=0.5)
            del v[key]
            self.assertTrue(self.check(v), key)

    def test_old_summary_fields_no_longer_required(self):
        self.assertEqual(self.check(good(remark="r", logs=[])), [])
        self.assertNotIn("summary", good())

    def test_bad_citations(self):
        for item in ({"type": "code", "repo": "r", "file": "app/a.py", "line": 4},
                     {"type": "code", "repo": "r", "file": "app/a.py", "line": 0},
                     {"type": "code", "repo": "r", "file": "app/nope.py", "line": 1},
                     {"type": "code", "repo": "r", "file": "../x", "line": 1},
                     {"type": "code", "repo": "r", "file": "/etc/passwd", "line": 1},
                     {"type": "elk", "key": "samples[1].request_id"},
                     {"type": "elk", "key": "nope"},
                     {"type": "other"}, "str"):
            self.assertEqual(len(self.check(good(evidence=[item]))), 1, item)

    def test_absolute_and_dot_slash_paths_normalised_in_place(self):
        abs_path = os.path.join(os.path.realpath(self.tmp.name), "app", "a.py")
        v = good(evidence=[{"type": "code", "repo": "r", "file": abs_path, "line": 2},
                           {"type": "code", "repo": "r", "file": "./app/a.py", "line": 1}])
        self.assertEqual(self.check(v), [])
        self.assertEqual([i["file"] for i in v["evidence"]], ["app/a.py", "app/a.py"])

    def test_absolute_path_through_symlinked_worktree(self):
        link = os.path.join(self.tmp.name, "link")
        os.symlink(os.path.join(self.tmp.name, "app"), link)
        wt = os.path.join(self.tmp.name, "wtlink")
        os.symlink(self.tmp.name, wt)
        v = good(evidence=[{"type": "code", "repo": "r", "file": os.path.join(wt, "app", "a.py"), "line": 1}])
        self.assertEqual(validate_verdict(v, {"r": wt}, self.ev), [])
        self.assertEqual(v["evidence"][0]["file"], "app/a.py")

    def test_absolute_path_outside_worktree_still_rejected(self):
        v = good(evidence=[{"type": "code", "repo": "r", "file": "/etc/hosts", "line": 1}])
        self.assertEqual(len(self.check(v)), 1)

    def test_unknown_or_missing_repo_in_citation_rejected(self):
        for item in ({"type": "code", "repo": "other", "file": "app/a.py", "line": 1},
                     {"type": "code", "file": "app/a.py", "line": 1},
                     {"type": "code", "repo": 3, "file": "app/a.py", "line": 1}):
            self.assertEqual(len(self.check(good(evidence=[item]))), 1, item)

    def test_citation_resolved_under_its_own_repo(self):
        with tempfile.TemporaryDirectory() as other:
            with open(os.path.join(other, "b.py"), "w") as f:
                f.write("1\n2\n")
            repos = {"r": self.tmp.name, "o": other}
            ok = good(evidence=[{"type": "code", "repo": "o", "file": "b.py", "line": 2}])
            self.assertEqual(validate_verdict(ok, repos, self.ev), [])
            wrong = good(evidence=[{"type": "code", "repo": "o", "file": "app/a.py", "line": 1}])
            self.assertEqual(len(validate_verdict(wrong, repos, self.ev)), 1)
            absolute = good(evidence=[{"type": "code", "repo": "o",
                                       "file": os.path.join(os.path.realpath(other), "b.py"),
                                       "line": 1}])
            self.assertEqual(validate_verdict(absolute, repos, self.ev), [])
            self.assertEqual(absolute["evidence"][0]["file"], "b.py")

    def test_no_repo_rejects_code(self):
        v = good(evidence=[{"type": "code", "repo": "r", "file": "app/a.py", "line": 1}])
        self.assertTrue(validate_verdict(v, {}, self.ev))

    def test_no_evidence_rejects_elk(self):
        self.assertTrue(validate_verdict(
            good(evidence=[{"type": "elk", "key": "total"}]), {}, None))


class LogValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(os.path.join(self.tmp.name, analyzer.ELK_RESULTS_FILE), "w") as f:
            f.write("$ elk-query recent boom --size 2\n"
                    "# 區間內最新 2 筆\n"
                    "10/20 14:00:01 | T+1交割款不足自動通知開始\n"
                    "10/20 14:00:07 | KeyError:   'phone' in msg_helper\n")
        self.ev = {"total": 1, "samples": [{"message": "ConnectionError: broker down"}]}

    def check(self, v, run_dir="default"):
        return validate_verdict(v, {}, self.ev, self.tmp.name if run_dir == "default" else run_dir)

    def test_whole_lines_found_in_elk_results_are_kept(self):
        logs = ["10/20 14:00:01 | T+1交割款不足自動通知開始",
                "2026-10-20T14:00:07+08:00 KeyError: 'phone' in msg_helper"]
        v = good(logs=list(logs))
        self.assertEqual(self.check(v), [])
        self.assertEqual(v["logs"], logs)

    def test_invented_lines_are_dropped_and_reported(self):
        v = good(logs=["10/20 14:00:01 | T+1交割款不足自動通知開始",
                       "10/20 14:00:02 | NullPointerException at Foo",
                       "10/20 14:00:03 | ", 42])
        problems = self.check(v)
        self.assertEqual(v["logs"], ["10/20 14:00:01 | T+1交割款不足自動通知開始"])
        self.assertEqual(len(problems), 3)
        self.assertTrue(all(p.startswith(analyzer.LOG_PROBLEM) for p in problems))

    def test_evidence_samples_are_not_a_log_source(self):
        v = good(logs=["10/20 14:00:01 | T+1交割款不足自動通知開始", "ConnectionError: broker down"])
        self.check(v, run_dir=os.path.join(self.tmp.name, "missing"))
        self.assertEqual(v["logs"], [])
        v = good(logs=["ConnectionError: broker down"])
        self.check(v)
        self.assertEqual(v["logs"], [])

    def test_logs_not_a_list_is_cleared(self):
        v = good(logs="10/20 14:00:01 | T+1交割款不足自動通知開始")
        problems = self.check(v)
        self.assertEqual(v["logs"], [])
        self.assertTrue(problems[0].startswith(analyzer.LOG_PROBLEM))

    def test_dropped_logs_alone_do_not_escalate(self):
        v = good(logs=["made up"])
        problems = self.check(v)
        self.assertTrue(problems)
        self.assertFalse(should_escalate(v, problems, CheckSpec(key="k")))
        self.assertTrue(should_escalate(v, problems + ["category 不合法"], CheckSpec(key="k")))


class EscalateTests(unittest.TestCase):
    def test_conditions(self):
        plain = CheckSpec(key="k")
        self.assertFalse(should_escalate(good(), [], plain))
        self.assertTrue(should_escalate(good(), ["p"], plain))
        self.assertTrue(should_escalate(good(confidence=0.5), [], None))
        self.assertTrue(should_escalate(good(), [], CheckSpec(key="k", never_silence=True)))
        self.assertTrue(should_escalate(good(category="code_bug", needs_human=True), [], plain))
        self.assertFalse(should_escalate(good(category="code_bug"), [], plain))

    def test_fix_in_system_must_be_configured_or_unknown(self):
        systems = {"pxy": object(), "sso": object()}
        self.assertFalse(should_escalate(good(fix_in_system="sso"), [], None, systems))
        self.assertFalse(should_escalate(good(fix_in_system="unknown"), [], None, systems))
        self.assertTrue(should_escalate(good(fix_in_system="nonsense"), [], None, systems))
        self.assertFalse(should_escalate(good(fix_in_system="nonsense"), [], None))


class RunClaudeTests(unittest.TestCase):
    def test_command_and_verdict_file(self):
        with tempfile.TemporaryDirectory() as d:
            seen = {}

            def run(cmd, **kw):
                seen.update(cmd=cmd, kw=kw)
                with open(os.path.join(d, "verdict.json"), "w") as f:
                    json.dump(good(), f)
                return SimpleNamespace(returncode=0, stdout='{"is_error": false}', stderr="")

            orig = analyzer.resolve_cli
            analyzer.resolve_cli = lambda name: "/bin/claude"
            self.addCleanup(setattr, analyzer, "resolve_cli", orig)
            v = analyzer.run_claude("sonnet", "P", d, ["/wt"], 5, run)
            self.assertEqual(v, good())
            cmd = seen["cmd"]
            self.assertEqual(cmd[:3], ["/bin/claude", "-p", "P"])
            self.assertIn("Read,Grep,Glob,Write", cmd)
            self.assertEqual(cmd[cmd.index("--add-dir") + 1], "/wt")
            self.assertEqual(seen["kw"]["stdin"], subprocess.DEVNULL)
            self.assertEqual(seen["kw"]["cwd"], d)

    def test_bash_limited_to_elk_query_and_alert_doctor_importable(self):
        with tempfile.TemporaryDirectory() as d:
            seen = {}

            def run(cmd, **kw):
                seen.update(cmd=cmd, kw=kw)
                with open(os.path.join(d, "verdict.json"), "w") as f:
                    json.dump(good(), f)
                return SimpleNamespace(returncode=0, stdout="{}", stderr="")

            orig = analyzer.resolve_cli
            analyzer.resolve_cli = lambda name: "/bin/claude"
            self.addCleanup(setattr, analyzer, "resolve_cli", orig)
            analyzer.run_claude("sonnet", "P", d, [], 5, run)
            cmd = seen["cmd"]
            rule = f"Bash({sys.executable} -m alert_doctor elk-query:*)"
            self.assertEqual(cmd[cmd.index("--allowedTools") + 1:cmd.index("--allowedTools") + 3],
                             ["Read,Grep,Glob,Write", rule])
            self.assertEqual([c for c in cmd if c.startswith("Bash")], [rule])
            self.assertTrue(os.path.isabs(sys.executable))
            paths = seen["kw"]["env"]["PYTHONPATH"].split(os.pathsep)
            self.assertEqual(paths[0], str(analyzer.PROJECT_ROOT))

    def test_missing_cli_is_not_launched(self):
        def boom(name):
            raise FileNotFoundError("找不到 'claude'")
        orig = analyzer.resolve_cli
        analyzer.resolve_cli = boom
        self.addCleanup(setattr, analyzer, "resolve_cli", orig)
        with self.assertRaises(analyzer.NotLaunched) as cm:
            analyzer.run_claude("m", "p", "/tmp", [], 5, lambda *a, **k: self.fail("ran"))
        self.assertIn("claude", str(cm.exception))

    def test_popen_oserror_is_not_launched(self):
        orig = analyzer.resolve_cli
        analyzer.resolve_cli = lambda name: "claude"
        self.addCleanup(setattr, analyzer, "resolve_cli", orig)

        def run(cmd, **kw):
            raise PermissionError("nope")
        with self.assertRaises(analyzer.NotLaunched):
            analyzer.run_claude("m", "p", "/tmp", [], 5, run)

    def test_missing_verdict_raises(self):
        with tempfile.TemporaryDirectory() as d:
            orig = analyzer.resolve_cli
            analyzer.resolve_cli = lambda name: "claude"
            self.addCleanup(setattr, analyzer, "resolve_cli", orig)
            run = lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="{}", stderr="")
            with self.assertRaises(RuntimeError):
                analyzer.run_claude("m", "p", d, [], 5, run)


class AnalyzerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(channels=(ChannelSpec(CH, "alerts-a", ("sys",)),), workspace_url="https://x.slack.com",
                          runs_dir=os.path.join(self.tmp.name, "runs"),
                          db_path=os.path.join(self.tmp.name, "db"),
                          mirrors_dir=os.path.join(self.tmp.name, "mirrors"),
                          known_path=os.path.join(self.tmp.name, "known.toml"),
                          topology_path=os.path.join(self.tmp.name, "topology.toml"),
                          systems={"sys": SystemSpec("sys", ("repo",), ("U1",), "sys", {}),
                                   "other": SystemSpec("other", (), ("U9",), "o", {})},
                          repos={"repo": RepoSpec("repo", "/src/repo")})
        self.store = Store(":memory:")
        self.slack = FakeSlack()
        self.now = NOW
        self.calls = []
        self.checkout = os.path.join(self.tmp.name, "mirrors", "repo", "deadbeefcafe")
        os.makedirs(self.checkout)
        self.current_map = {"repo": (self.checkout, "deadbeefcafe")}
        self.refreshed = []
        self.responses = [good()]
        self.checks = {}
        self.snapshot_path = os.path.join(self.tmp.name, "no_snapshot", "tasks.json")
        self.snapshot_loader = lambda path: None
        self.archive = mock.Mock()

    def code_fix(self, **kw):
        """A fix_code verdict whose code citation resolves in the fake checkout."""
        with open(os.path.join(self.checkout, "app.py"), "w") as f:
            f.write("one\ntwo\n")
        return good(**{"category": "code_bug", "action": "fix_code", "fix": ["app.py 第 2 行改用 .get()"],
                       "evidence": [{"type": "code", "repo": "repo", "file": "app.py", "line": 2}],
                       **kw})

    def outbox(self):
        rows = self.store.read(
            "SELECT channel, kind, thread_ts, payload, priority, dedupe_key, incident_id"
            " FROM outbox ORDER BY id")
        return [SimpleNamespace(channel=c, kind=k, thread_ts=t, payload=json.loads(p),
                                priority=pr, dedupe_key=d, incident_id=i)
                for c, k, t, p, pr, d, i in rows]

    def posts(self):
        return [(o.channel, o.payload["text"], o.thread_ts) for o in self.outbox()]

    def full_reactions(self):
        found = []
        for o in self.outbox():
            found += [("remove", o.channel, o.thread_ts, n) for n in o.payload.get("remove_on_root", ())]
            found += [("add", o.channel, o.thread_ts, n) for n in o.payload.get("reactions_on_root", ())]
        return found

    def reactions(self):
        return [(r[0], r[3]) for r in self.full_reactions()]

    def make(self, runner=None):
        def default_runner(model, prompt, cwd, add_dirs, timeout):
            self.calls.append((model, cwd, add_dirs))
            r = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
            if isinstance(r, Exception):
                raise r
            return r
        return Analyzer(
            self.cfg, self.store, self.slack, "tok", self.checks,
            clock=lambda: self.now, runner=runner or default_runner,
            current=lambda rid, mdir: self.current_map.get(rid),
            refresh=self._refresh, snapshot_path=self.snapshot_path,
            snapshot_loader=self.snapshot_loader, archive=self.archive)

    def _refresh(self, repo, mirrors_dir):
        self.refreshed.append(repo.id)
        self.current_map[repo.id] = (self.checkout, "deadbeefcafe")
        return self.current_map[repo.id]

    def incident(self, code="c1", ts="1000.0", analyze=True, report=True, extra=None):
        a = ParsedAlert(channel=CH, ts=ts, raw_text="r", parse_ok=True,
                        check_title="T", check_code=code, result_message="boom",
                        extra=extra or {})
        self.store.insert_message(a, 1.0)
        inc = self.store.create_incident(a, f"fp-{code}", "g")
        if report:
            self.store.upsert_report(inc.id, CH, ts, now=NOW)
        if analyze:
            self.store.request_analysis(inc.id, now=NOW)
        return inc


class AnalyzerTests(AnalyzerBase):
    def test_nothing_to_do(self):
        self.assertFalse(self.make().run_once())

    def test_happy_path_posts_once_and_completes(self):
        inc = self.incident()
        a = self.make()
        self.assertTrue(a.run_once())
        self.assertFalse(a.run_once())
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(self.posts()[0][0::2], (CH, "1000.0"))
        self.assertIn(("remove", "mag"), self.reactions())
        self.assertIn(("add", "white_check_mark"), self.reactions())
        self.assertEqual([c[0] for c in self.calls], ["sonnet"])
        done = self.store.get_incident(inc.id)
        self.assertEqual(done.analysis_state, "done")
        self.assertEqual(done.verdict, good())
        self.assertEqual(self.store.llm_calls_on("sonnet", 0, NOW + 1e6), 1)

    def test_needs_human_reaction(self):
        self.responses = [good(category="unknown", action="investigate", needs_human=True, confidence=0.6)]
        self.incident()
        self.make().run_once()
        self.assertIn(("add", "raising_hand"), self.reactions())

    def test_bad_citation_escalates_to_opus_and_posts_opus_verdict(self):
        self.incident()
        self.responses = [good(evidence=[{"type": "elk", "key": "nope"}]), good(cause="opus")]
        self.make().run_once()
        self.assertEqual([c[0] for c in self.calls], ["sonnet", "opus"])
        self.assertIn("opus", self.posts()[0][1])
        self.assertEqual(len(self.posts()), 1)

    def test_persistent_bad_citation_is_stripped_and_flagged(self):
        inc = self.incident()
        bad = good(evidence=[{"type": "elk", "key": "nope"}])
        self.responses = [bad, bad]
        self.make().run_once()
        v = self.store.get_incident(inc.id).verdict
        self.assertEqual(v["evidence"], [])
        self.assertTrue(v["needs_human"])

    def test_validation_failure_reruns_once_with_feedback_then_fails_without_retry(self):
        inc = self.incident()
        prompts = []
        bad = good(category="code_bug", action="observe")

        def runner(model, prompt, cwd, add_dirs, timeout):
            prompts.append((model, prompt))
            return bad
        self.make(runner).run_once()
        self.assertEqual([m for m, _ in prompts], ["sonnet", "opus"])
        self.assertNotIn("上一次輸出沒有通過驗證", prompts[0][1])
        self.assertIn("上一次輸出沒有通過驗證", prompts[1][1])
        self.assertIn("category", prompts[1][1])
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "failed")
        self.assertTrue(any("自動分析失敗" in text for _, text, _ in self.posts()))

    def test_never_silence_escalates(self):
        self.checks["c1"] = CheckSpec(key="c1", never_silence=True)
        self.incident()
        self.make().run_once()
        self.assertEqual([c[0] for c in self.calls], ["sonnet", "opus"])

    def test_escalation_over_budget_keeps_sonnet_verdict(self):
        self.checks["c1"] = CheckSpec(key="c1", never_silence=True)
        for _ in range(self.cfg.daily_limit_escalation):
            self.store.record_llm_call("opus", NOW)
        self.incident()
        self.make().run_once()
        self.assertEqual([c[0] for c in self.calls], ["sonnet"])
        self.assertEqual(len(self.posts()), 1)

    def test_recent_verdict_reused_without_runner(self):
        old = self.incident(ts="900.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(summary="old"), "sonnet", NOW - 7200)
        new = self.incident(ts="1000.0")
        self.make().run_once()
        self.assertEqual(self.calls, [])
        self.assertIn("沿用", self.posts()[0][1])
        self.assertEqual(self.store.get_incident(new.id).analysis_state, "done")

    def test_over_budget_leaves_incident_queued_for_tomorrow(self):
        for _ in range(self.cfg.daily_limit):
            self.store.record_llm_call("sonnet", NOW)
        inc = self.incident()
        a = self.make()
        self.assertFalse(a.run_once())
        self.assertFalse(a.run_once())
        self.assertEqual(self.calls, [])
        got = self.store.get_incident(inc.id)
        self.assertEqual((got.analysis_state, got.attempts), ("pending", 0))
        self.now = NOW + 86400
        self.assertTrue(a.run_once())
        self.assertEqual(len(self.calls), 1)

    def test_over_budget_notice_posted_once_per_incident(self):
        for _ in range(self.cfg.daily_limit):
            self.store.record_llm_call("sonnet", NOW)
        inc = self.incident()
        a = self.make()
        a.run_once()
        a.run_once()
        self.assertEqual(len(self.posts()), 1)
        self.assertIn("額度", self.posts()[0][1])
        self.assertEqual(self.posts()[0][0::2], (CH, "1000.0"))
        self.assertTrue(os.path.exists(
            os.path.join(self.cfg.runs_dir, str(inc.id), "budget_notified")))

    def test_over_budget_notice_failure_is_swallowed_and_retried(self):
        for _ in range(self.cfg.daily_limit):
            self.store.record_llm_call("sonnet", NOW)
        inc = self.incident()
        a = self.make()
        with mock.patch.object(self.store, "enqueue_reply", side_effect=RuntimeError("x")):
            self.assertFalse(a.run_once())
        self.assertFalse(os.path.exists(
            os.path.join(self.cfg.runs_dir, str(inc.id), "budget_notified")))

    def test_over_budget_still_reuses_recent_verdict(self):
        old = self.incident(ts="900.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(summary="old"), "sonnet", NOW - 7200)
        for _ in range(self.cfg.daily_limit):
            self.store.record_llm_call("sonnet", NOW)
        new = self.incident(ts="1000.0")
        self.assertTrue(self.make().run_once())
        self.assertEqual(self.calls, [])
        self.assertIn("沿用", self.posts()[0][1])
        self.assertEqual(self.store.get_incident(new.id).analysis_state, "done")

    def test_budget_counts_only_today_taipei(self):
        yesterday = NOW - 86400
        for _ in range(self.cfg.daily_limit):
            self.store.record_llm_call("sonnet", yesterday)
        self.incident()
        self.make().run_once()
        self.assertEqual(len(self.calls), 1)

    def test_runner_exception_requeues_and_charges_the_call(self):
        inc = self.incident()
        self.responses = [RuntimeError("boom")]
        self.make().run_once()
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "pending")
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.store.llm_calls_on("sonnet", 0, NOW + 1e6), 1)

    def test_run_that_never_launched_is_not_charged(self):
        inc = self.incident()
        self.responses = [analyzer.NotLaunched("找不到 'claude'")]
        self.make().run_once()
        self.assertEqual(self.store.llm_calls_on("sonnet", 0, NOW + 1e6), 0)
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "pending")

    def test_intermediate_failure_does_not_post(self):
        self.incident()
        self.responses = [RuntimeError("boom")]
        self.make().run_once()
        self.assertEqual(self.posts(), [])

    def test_final_failure_posts_warning_and_flips_reaction(self):
        inc = self.incident()
        self.responses = [RuntimeError("boom " + "x" * 400)]
        a = self.make()
        for _ in range(analyzer_max_attempts()):
            a.run_once()
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "failed")
        self.assertEqual(len(self.posts()), 1)
        text = self.posts()[0][1]
        self.assertIn("自動分析失敗", text)
        self.assertIn("請人工查看", text)
        self.assertIn("boom", text)
        self.assertLess(len(text), 300)
        self.assertEqual(self.posts()[0][0::2], (CH, "1000.0"))
        self.assertIn(("remove", "mag"), self.reactions())
        self.assertIn(("add", "raising_hand"), self.reactions())

    def test_final_failure_slack_errors_swallowed(self):
        inc = self.incident()
        self.responses = [RuntimeError("boom")]
        a = self.make()
        with mock.patch.object(self.store, "enqueue_reply", side_effect=RuntimeError("x")):
            for _ in range(analyzer_max_attempts()):
                self.assertTrue(a.run_once())
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "failed")

    def test_all_repo_checkouts_passed_and_context_written(self):
        self.cfg = Config(**{**self.cfg.__dict__, "repos": {
            "repo": RepoSpec("repo", "/src/repo"), "second": RepoSpec("second", "/src/second")}})
        second = os.path.join(self.tmp.name, "mirrors", "second", "cafe")
        os.makedirs(second)
        self.current_map["second"] = (second, "cafe" * 10)
        self.store.save_evidence(self.incident().id, {"total": 3, "candidates": [{"system": "sso"}]})
        self.make().run_once()
        _, cwd, add_dirs = self.calls[0]
        self.assertEqual(add_dirs, [self.checkout, second])
        with open(os.path.join(cwd, "context.json")) as f:
            ctx = json.load(f)
        self.assertEqual(ctx["repos"]["repo"],
                         {"path": self.checkout, "sha": "deadbeefcafe", "system": "sys"})
        self.assertEqual(ctx["shas"], {"repo": "deadbeefcafe", "second": "cafe" * 10})
        self.assertEqual(ctx["channel"], CH)
        self.assertEqual(ctx["start_systems"], ["sys"])
        self.assertEqual(ctx["co_erroring"], [{"system": "sso"}])
        self.assertEqual(ctx["topology"], "")
        self.assertEqual(ctx["alert"]["result_message"], "boom")
        self.assertNotIn("deadbeef", self.posts()[0][1])
        self.assertEqual(self.refreshed, [])

    def test_truncated_alert_is_flagged_in_context_and_reply(self):
        a = ParsedAlert(channel=CH, ts="1000.0", raw_text="r", parse_ok=True, check_title="T",
                        check_code="c1", result_message="boom", truncated=True)
        self.store.insert_message(a, 1.0)
        inc = self.store.create_incident(a, "fp-c1", "g")
        self.store.upsert_report(inc.id, CH, "1000.0", now=NOW)
        self.store.request_analysis(inc.id, now=NOW)
        self.make().run_once()
        self.assertTrue(self.context_of()["alert"]["truncated"])
        self.assertIn("原文超過 Slack 長度上限被截斷,尾段不可得", self.posts()[0][1])

    def test_complete_alert_has_no_truncation_line(self):
        self.incident()
        self.make().run_once()
        self.assertFalse(self.context_of()["alert"]["truncated"])
        self.assertNotIn("截斷", self.posts()[0][1])

    def write_known(self):
        # Incident epochs here are ~1000s: 1970-01-01 08:16 Taipei.
        with open(self.cfg.known_path, "w", encoding="utf-8") as f:
            f.write(
                '[[known]]\nid = "morning"\ntitle = "早上維護"\naction = "known"\n'
                'windows = [{ start = "08:00", end = "08:20", label = "62 號主機重啟" }]\n'
                '[known.match]\nsystems = ["cms"]\ntask_pks = [1]\nany_regex = ["廠商甲"]\n'
                '[[known]]\nid = "boom"\ntitle = "固定 boom"\naction = "context"\n'
                'windows = [{ start = "13:00", end = "13:10" }]\n'
                '[known.match]\nany_regex = ["boom"]\n'
                '[[known]]\nid = "night"\ntitle = "夜間"\naction = "known"\n'
                'windows = [{ start = "02:00", end = "02:10" }]\n'
                '[known.match]\nsystems = ["cms"]\ntask_pks = [1]\nany_regex = ["廠商甲"]\n')

    def context_of(self):
        _, cwd, _ = self.calls[0]
        with open(os.path.join(cwd, "context.json")) as f:
            return json.load(f)

    def test_context_lists_overlapping_and_text_matching_known_background(self):
        self.write_known()
        self.incident()
        self.make().run_once()
        found = {b["id"]: b for b in self.context_of()["known_background"]}
        self.assertEqual(sorted(found), ["boom", "morning"])
        self.assertTrue(found["morning"]["in_window"])
        self.assertEqual(found["morning"]["overlapping_windows"], ["08:00 62 號主機重啟"])
        self.assertFalse(found["boom"]["in_window"])
        self.assertTrue(found["boom"]["text_match"])

    def test_linked_error_leads_the_background(self):
        from alert_doctor import known_store
        inc = self.incident()
        alert = self.store.first_message(inc.id)
        known_store.ensure_schema(self.store)
        known_store.add_entry(self.store, "boom-known", "固定 boom", now=NOW)
        analyzer = self.make()
        key = known_store.alert_error_key(alert, source_system=analyzer._source(inc))
        known_store.link(self.store, key, "boom-known", now=NOW, linked_by="U1")
        analyzer.run_once()
        first = self.context_of()["known_background"][0]
        self.assertEqual((first["id"], first["linked_error"], first["linked_by"]),
                         ("boom-known", True, "U1"))

    def test_no_known_file_means_empty_background(self):
        self.incident()
        self.make().run_once()
        self.assertEqual(self.context_of()["known_background"], [])

    def test_prompt_tells_model_to_check_known_background_first(self):
        prompt = analyzer.build_prompt({})
        self.assertIn("known_background", prompt)
        self.assertIn("observe", prompt[prompt.index("known_background"):])

    def test_prompt_lists_repos(self):
        seen = {}

        def runner(model, prompt, cwd, add_dirs, timeout):
            seen["prompt"] = prompt
            return good()
        self.incident()
        self.make(runner=runner).run_once()
        self.assertIn(self.checkout, seen["prompt"])
        self.assertNotIn("__REPOS__", seen["prompt"])

    def test_missing_checkout_refreshed_once(self):
        self.current_map.clear()
        self.incident()
        self.make().run_once()
        self.assertEqual(self.refreshed, ["repo"])
        self.assertEqual(self.calls[0][2], [self.checkout])

    def test_repo_that_cannot_be_checked_out_is_skipped(self):
        self.current_map.clear()
        self.incident()
        a = self.make()
        a.refresh = lambda repo, mdir: (_ for _ in ()).throw(RuntimeError("git down"))
        a.run_once()
        self.assertEqual(self.calls[0][2], [])
        self.assertEqual(len(self.posts()), 1)

    def test_topology_rendered_lazily_and_failure_is_swallowed(self):
        open(self.cfg.topology_path, "w").close()
        fake = mock.Mock()
        fake.load_topology.return_value.render_for_prompt.return_value = "拓樸文字"
        self.incident()
        with mock.patch.dict("sys.modules", {"alert_doctor.topology": fake}), \
                mock.patch("alert_doctor.topology", fake, create=True):
            self.make().run_once()
        fake.load_topology.return_value.render_for_prompt.assert_called_once_with(("sys",))
        with open(os.path.join(self.calls[0][1], "context.json")) as f:
            self.assertEqual(json.load(f)["topology"], "拓樸文字")

        fake.load_topology.side_effect = RuntimeError("壞掉")
        self.incident(code="c2", ts="2000.0")
        with mock.patch.dict("sys.modules", {"alert_doctor.topology": fake}), \
                mock.patch("alert_doctor.topology", fake, create=True):
            self.make().run_once()
        self.assertEqual(len(self.posts()), 2)

    def test_analysis_is_queued_for_the_publisher_never_posted(self):
        inc = self.incident()
        self.make().run_once()
        self.assertEqual(self.slack.posts, [])
        [item] = self.outbox()
        self.assertEqual((item.kind, item.priority, item.channel, item.thread_ts, item.incident_id,
                          item.dedupe_key), ("analysis", 1, CH, "1000.0", inc.id, f"analysis:{inc.id}"))
        self.assertEqual(item.payload["reactions_on_root"], ["white_check_mark", "large_green_circle"])
        self.assertEqual(item.payload["remove_on_root"], ["mag"])

    def test_analysis_goes_to_primary_report_even_in_another_channel(self):
        inc = self.incident(report=False)
        self.occurrence(inc, "C2", "1001.0")
        self.store.upsert_report(inc.id, "C2", "1001.0", now=NOW)
        self.store.upsert_report(inc.id, CH, "1000.0", now=NOW)
        self.make().run_once()
        analysis, link = self.outbox()
        self.assertEqual((analysis.kind, analysis.channel, analysis.thread_ts), ("analysis", "C2", "1001.0"))
        self.assertEqual((link.kind, link.channel, link.thread_ts), ("link", CH, "1000.0"))
        self.assertIn("https://x.slack.com/archives/C2/p10010", link.payload["text"])

    def test_waits_for_first_report_then_analyzes(self):
        inc = self.incident(report=False)
        a = self.make()
        self.assertFalse(a.run_once())
        got = self.store.get_incident(inc.id)
        self.assertEqual((got.analysis_state, got.attempts), ("pending", 0))
        self.assertEqual((self.calls, self.outbox()), ([], []))
        self.now += 30
        self.assertFalse(a.run_once())
        self.store.upsert_report(inc.id, CH, "1000.0", now=self.now)
        self.now += 30
        self.assertTrue(a.run_once())
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.outbox()[0].thread_ts, "1000.0")

    def test_report_that_never_arrives_falls_back_to_anchor_thread(self):
        inc = self.incident(report=False)
        a = self.make()
        self.assertFalse(a.run_once())
        self.now += analyzer.REPORT_WAIT_SECONDS
        self.assertTrue(a.run_once())
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "done")
        self.assertEqual(self.posts()[0][0::2], (CH, "1000.0"))

    def test_incident_waiting_for_report_does_not_block_others(self):
        waiting = self.incident(code="c1", ts="1000.0", report=False)
        ready = self.incident(code="c2", ts="2000.0")
        a = self.make()
        self.assertFalse(a.run_once())
        self.assertTrue(a.run_once())
        self.assertEqual(self.store.get_incident(ready.id).analysis_state, "done")
        self.assertEqual(self.store.get_incident(waiting.id).analysis_state, "pending")

    def test_report_wait_survives_analyzer_restart(self):
        inc = self.incident(report=False)
        self.assertFalse(self.make().run_once())
        self.now += analyzer.REPORT_WAIT_SECONDS
        self.assertTrue(self.make().run_once())
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "done")
        self.assertEqual(self.posts()[0][0::2], (CH, "1000.0"))

    def test_over_budget_notice_is_a_queued_failure(self):
        for _ in range(self.cfg.daily_limit):
            self.store.record_llm_call("sonnet", NOW)
        inc = self.incident()
        self.make().run_once()
        [item] = self.outbox()
        self.assertEqual((item.kind, item.thread_ts, item.dedupe_key),
                         ("failure", "1000.0", f"budget:{inc.id}"))

    def test_final_failure_is_queued_as_failure(self):
        inc = self.incident()
        self.responses = [RuntimeError("boom")]
        a = self.make()
        for _ in range(analyzer_max_attempts()):
            a.run_once()
        [item] = self.outbox()
        self.assertEqual((item.kind, item.priority, item.dedupe_key), ("failure", 1, f"failure:{inc.id}"))
        self.assertEqual(self.slack.posts, [])

    def occurrence(self, inc, channel, ts):
        a = ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True,
                        check_title="T", check_code="c1", result_message="boom")
        self.store.insert_message(a, 1.0)
        self.store.attach(inc.id, a)

    def test_severity_on_anchor_and_earliest_occurrence_per_other_channel(self):
        self.responses = [good(severity="high")]
        inc = self.incident()
        self.occurrence(inc, CH, "1000.5")
        self.occurrence(inc, "C2", "1002.0")
        self.occurrence(inc, "C2", "1001.0")
        self.make().run_once()
        adds = {(r[1], r[2]) for r in self.full_reactions()
                if r[0] == "add" and r[3] == "large_orange_circle"}
        self.assertEqual(adds, {(CH, "1000.0"), ("C2", "1001.0")})
        sev_removals = [r for r in self.full_reactions()
                        if r[0] == "remove" and r[3] in analyzer.SEVERITY_REACTION.values()]
        self.assertEqual(sev_removals, [])

    def test_severity_change_removes_only_previous_severity(self):
        inc = self.incident()
        self.occurrence(inc, "C2", "1001.0")
        self.responses = [good(severity="low")]
        self.make().run_once()
        self.store.request_analysis(inc.id, now=NOW, fresh=True)
        self.responses = [good(severity="high")]
        self.full_reactions().clear()
        self.calls.clear()
        self.make().run_once()
        for channel, ts in ((CH, "1000.0"), ("C2", "1001.0")):
            removed_at = self.full_reactions().index(("remove", channel, ts, "large_green_circle"))
            added_at = self.full_reactions().index(("add", channel, ts, "large_orange_circle"))
            self.assertLess(removed_at, added_at)
        removed = {r[3] for r in self.full_reactions() if r[0] == "remove"}
        self.assertEqual(removed & set(analyzer.SEVERITY_REACTION.values()), {"large_green_circle"})

    def test_reanalysis_clearing_needs_human_removes_raised_hand(self):
        inc = self.incident()
        self.responses = [good(category="unknown", action="investigate", needs_human=True,
                               confidence=0.4, fix=["查 10/20 14:00 後 f0e5 的 ERROR"])]
        self.make().run_once()
        self.store.request_analysis(inc.id, now=NOW, fresh=True)
        self.responses = [good()]
        self.full_reactions().clear()
        self.make().run_once()
        self.assertIn(("remove", CH, "1000.0", "raising_hand"), self.full_reactions())
        self.assertIn(("add", CH, "1000.0", "white_check_mark"), self.full_reactions())

    def test_other_channels_get_link_to_analysis(self):
        inc = self.incident()
        self.occurrence(inc, CH, "1000.5")
        self.occurrence(inc, "C2", "1002.0")
        self.occurrence(inc, "C2", "1001.0")
        self.occurrence(inc, "C3", "1003.0")
        self.make().run_once()
        self.store.upsert_report(inc.id, "C3", "1003.5", now=NOW)
        verdict_post, *links = self.outbox()
        self.assertEqual((verdict_post.channel, verdict_post.thread_ts), (CH, "1000.0"))
        self.assertEqual([(o.channel, o.thread_ts, o.kind, o.priority) for o in links],
                         [("C2", "1001.0", "link", 2), ("C3", "1003.0", "link", 2)])
        for o in links:
            self.assertTrue(o.payload["text"].startswith("🔗"))
            self.assertIn("https://x.slack.com/archives/C1/p10000", o.payload["text"])
            self.assertEqual(o.payload["reactions_on_root"], ["white_check_mark", "large_green_circle"])
            self.assertEqual(o.dedupe_key, f"link:{inc.id}:{o.channel}")

    def test_link_uses_existing_report_root_of_other_channel(self):
        inc = self.incident()
        self.occurrence(inc, "C2", "1001.0")
        self.occurrence(inc, "C2", "1002.0")
        self.store.upsert_report(inc.id, "C2", "1002.0", now=NOW)
        self.make().run_once()
        self.assertEqual(self.outbox()[1].thread_ts, "1002.0")

    def test_single_channel_incident_posts_no_link(self):
        inc = self.incident()
        self.occurrence(inc, CH, "1000.5")
        self.make().run_once()
        self.assertEqual(len(self.posts()), 1)

    def test_reused_verdict_is_flagged(self):
        old = self.incident(ts="900.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(), "sonnet", NOW - 60)
        new = self.incident(ts="1000.0")
        self.make().run_once()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.store.read(
            "SELECT verdict_reused FROM incidents WHERE id=?", (new.id,))[0][0], 1)
        self.assertEqual(self.store.read(
            "SELECT verdict_reused FROM incidents WHERE id=?", (old.id,))[0][0], 0)

    def test_fresh_request_never_reuses(self):
        old = self.incident(ts="900.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(category="noise"), "sonnet", NOW - 60)
        new = self.incident(ts="1000.0", analyze=False)
        self.store.request_analysis(new.id, fresh=True)
        self.make().run_once()
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("沿用", self.posts()[0][1])
        row = self.store.read(
            "SELECT verdict_reused, fresh_requested FROM incidents WHERE id=?", (new.id,))[0]
        self.assertEqual(row, (0, 0))

    def test_refresh_mirrors_beats_each_refreshed_repo(self):
        def fake_refresh_all(cfg, on_change=None):
            return {"repo": ("/x", "b" * 40)}
        analyzer.refresh_mirrors(self.cfg, self.store, NOW, fake_refresh_all)
        self.assertEqual(self.store.last_beat("mirror:repo"), NOW)
        self.assertIsNone(self.store.last_beat("mirror:other"))

    def test_severity_reaction_also_on_reused_verdict(self):
        old = self.incident(ts="900.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(severity="critical"), "sonnet", NOW - 60)
        self.incident(ts="1000.0")
        self.make().run_once()
        self.assertIn(("add", "red_circle"), self.reactions())

    def test_needs_human_adds_raising_hand_and_severity(self):
        self.responses = [good(category="unknown", action="investigate", needs_human=True,
                               confidence=0.6, severity="low")]
        self.incident()
        self.make().run_once()
        self.assertIn(("add", "raising_hand"), self.reactions())
        self.assertIn(("add", "large_green_circle"), self.reactions())
        self.assertTrue(self.posts()[0][1].startswith("🟢"))

    def test_old_format_reused_verdict_shows_project_from_cited_repo(self):
        old_verdict = {"category": "unknown", "severity": "low", "confidence": 0.4,
                       "summary": "舊摘要", "root_cause": "r", "suggested_action": "1. 查 log",
                       "fix_in_system": "unknown", "needs_human": False,
                       "evidence": [{"type": "code", "repo": "repo", "file": "a.py", "line": 1}]}
        old = self.incident(ts="999.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, old_verdict, "sonnet", NOW - 3600)
        self.incident(ts="1000.0")
        self.make().run_once()
        text = self.posts()[-1][1]
        for part in ("*錯誤原因*:\n  舊摘要", "*專案*:\n  repo(sys)", "  1. 查 log", "信心 40%"):
            self.assertIn(part, text)

    def test_cross_system_verdict_notes_and_mentions_target_owners(self):
        self.responses = [good(fix_in_system="other")]
        self.incident()
        self.make().run_once()
        text = self.posts()[0][1]
        self.assertIn("↪️ 根因在 other", text)
        self.assertIn("<@U9>", text)

    def test_unconfigured_fix_in_system_escalates(self):
        self.responses = [good(fix_in_system="nonsense"), good()]
        self.incident()
        self.make().run_once()
        self.assertEqual([c[0] for c in self.calls], ["sonnet", "opus"])

    def test_mark_unhealthy_for_real_problem_categories_and_needs_human(self):
        cases = (
            (self.code_fix(), True), (self.code_fix(category="config"), True),
            (self.code_fix(category="external_dependency", action="vendor", action_target="廠商乙",
                           needs_human=True), True),
            (good(category="unknown", action="investigate", needs_human=True, confidence=0.5), True),
            (good(category="transient"), False), (good(category="noise"), False))
        for n, (response, expected) in enumerate(cases):
            fake = mock.Mock()
            inc = self.incident(code=f"c{n}", ts=f"{2000 + n}.0")
            self.responses = [response]
            self.calls.clear()
            with mock.patch.dict("sys.modules", {"alert_doctor.tuner": fake}), \
                    mock.patch("alert_doctor.tuner", fake, create=True):
                self.make().run_once()
            if expected:
                fake.mark_unhealthy.assert_called_once_with(
                    self.store, f"fp-c{n}", inc.first_epoch, inc.last_epoch)
            else:
                fake.mark_unhealthy.assert_not_called()

    def test_tuner_failure_does_not_break_analysis(self):
        self.responses = [self.code_fix()]
        inc = self.incident()
        fake = mock.Mock()
        fake.mark_unhealthy.side_effect = RuntimeError("tuner down")
        with mock.patch.dict("sys.modules", {"alert_doctor.tuner": fake}), \
                mock.patch("alert_doctor.tuner", fake, create=True):
            self.make().run_once()
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "done")

    def test_lease_expiry_does_not_double_post(self):
        inc = self.incident()
        holder = {}

        def slow_runner(model, prompt, cwd, add_dirs, timeout):
            self.now += 7200
            other = self.store.claim_incident("other", self.now)
            self.assertEqual(other.id, inc.id)
            holder["other"] = other
            return good()

        a = self.make(runner=slow_runner)
        a.run_once()
        self.assertEqual(self.posts(), [])
        current = self.store.get_incident(inc.id)
        self.assertEqual(current.analysis_state, "leased")
        self.assertEqual(current.attempts, holder["other"].attempts)

    def test_expired_but_unclaimed_lease_still_posts(self):
        inc = self.incident()

        def slow_runner(*args):
            self.now += 7200
            return good()

        self.make(runner=slow_runner).run_once()
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "done")

    def test_verdict_archived_and_archive_failure_is_harmless(self):
        inc = self.incident()
        self.make().run_once()
        incident, verdict, model, shas, now = self.archive.record_verdict.call_args.args
        self.assertEqual((incident.id, verdict, model, shas, now),
                         (inc.id, good(), "sonnet", {"repo": "deadbeefcafe"}, NOW))
        self.archive.record_verdict.side_effect = RuntimeError("disk full")
        other = self.incident(code="c2", ts="2000.0")
        self.make().run_once()
        self.assertEqual(self.store.get_incident(other.id).analysis_state, "done")

    def test_archive_opened_lazily_from_config_and_failure_to_open_is_harmless(self):
        self.archive = None
        self.cfg = SimpleNamespace(**{**vars(self.cfg), "archive_db_path": "/x/a.db",
                                      "channel": self.cfg.channel, "permalink": self.cfg.permalink})
        inc = self.incident()
        fake = mock.Mock()
        fake.Archive.side_effect = RuntimeError("cannot open")
        with mock.patch.dict("sys.modules", {"alert_doctor.archive": fake}):
            self.make().run_once()
        fake.Archive.assert_called_once_with("/x/a.db")
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "done")

    def test_reused_verdict_is_archived_too(self):
        old = self.incident(ts="900.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(summary="old"), "sonnet", NOW - 60)
        self.incident(ts="1000.0")
        self.make().run_once()
        self.assertEqual(self.archive.record_verdict.call_count, 1)

    def snapshot_dir(self):
        d = os.path.join(self.tmp.name, "snap")
        os.makedirs(os.path.join(d, "check_scripts"))
        with open(os.path.join(d, "check_scripts", "018_c1.py"), "w") as f:
            f.write("print('check')\n")
        self.snapshot_path = os.path.join(d, "tasks.json")
        return d

    def test_task_and_check_script_in_context_and_snapshot_dir_added(self):
        d = self.snapshot_dir()
        task = SimpleNamespace(id=42, label="下單檢查", cron="*/5 * * * *", check_code="c1",
                               check_title="T", kwargs={"keywords": ["boom"]}, enabled=True)
        seen = []

        def loader(path):
            seen.append(path)
            return SimpleNamespace(task_for_alert=lambda alert: task if alert.extra.get("pk") == 42 else None)
        self.snapshot_loader = loader
        self.incident(extra={"pk": 42})
        self.make().run_once()
        self.assertEqual(seen, [self.snapshot_path])
        _, cwd, add_dirs = self.calls[0]
        self.assertEqual(add_dirs, [self.checkout, d])
        with open(os.path.join(cwd, "context.json")) as f:
            ctx = json.load(f)
        self.assertEqual(ctx["task"], {"id": 42, "label": "下單檢查", "cron": "*/5 * * * *",
                                       "kwargs": {"keywords": ["boom"]}, "check_code": "c1",
                                       "check_title": "T"})
        self.assertEqual(ctx["check_script_path"], os.path.join(d, "check_scripts", "018_c1.py"))

    def test_broken_snapshot_still_finds_script_by_check_code(self):
        self.snapshot_dir()
        self.snapshot_loader = lambda path: (_ for _ in ()).throw(ValueError("bad json"))
        self.incident()
        self.make().run_once()
        with open(os.path.join(self.calls[0][1], "context.json")) as f:
            ctx = json.load(f)
        self.assertIsNone(ctx["task"])
        self.assertTrue(ctx["check_script_path"].endswith("018_c1.py"))

    def test_no_snapshot_dir_means_no_task_and_no_extra_add_dir(self):
        self.incident()
        self.make().run_once()
        self.assertEqual(self.calls[0][2], [self.checkout])
        with open(os.path.join(self.calls[0][1], "context.json")) as f:
            ctx = json.load(f)
        self.assertEqual((ctx["task"], ctx["check_script_path"]), (None, None))

    def test_alert_label_is_the_post_title(self):
        self.snapshot_dir()
        task = SimpleNamespace(id=42, label="[CMS] T+1交割款不足自動通知執行結果", cron="0 14 * * *",
                               check_code="c1", check_title="T", kwargs={}, enabled=True)
        self.snapshot_loader = lambda path: SimpleNamespace(task_for_alert=lambda alert: task)
        self.incident()
        self.make().run_once()
        self.assertTrue(self.posts()[0][1].startswith("🟢 *[CMS] T+1交割款不足自動通知執行結果*\n\n"))

    def test_title_falls_back_to_check_title(self):
        self.incident()
        self.make().run_once()
        self.assertTrue(self.posts()[0][1].startswith("🟢 *T*\n\n"))

    def test_reused_verdict_also_titled_with_label(self):
        self.snapshot_dir()
        task = SimpleNamespace(id=42, label="排程名稱", cron="", check_code="c1",
                               check_title="T", kwargs={}, enabled=True)
        self.snapshot_loader = lambda path: SimpleNamespace(task_for_alert=lambda alert: task)
        old = self.incident(ts="999.0")
        self.store.claim_incident("x", NOW)
        self.store.complete_analysis(old.id, good(), "sonnet", NOW - 7200)
        self.incident(ts="1000.0")
        self.make().run_once()
        text = self.posts()[-1][1]
        self.assertTrue(text.startswith("🟢 *排程名稱*"))
        self.assertTrue(text.endswith("\n\n_沿用 2 小時前的分析_"))

    def test_unfounded_logs_dropped_without_escalation_or_forced_review(self):
        def runner(model, prompt, cwd, add_dirs, timeout):
            self.calls.append((model, cwd, add_dirs))
            with open(os.path.join(cwd, analyzer.ELK_RESULTS_FILE), "w") as f:
                f.write("$ elk-query recent boom\n10/20 14:00:01 | real line from elk\n")
            return good(logs=["10/20 14:00:01 | real line from elk", "10/20 14:00:02 | invented"])
        inc = self.incident()
        self.make(runner=runner).run_once()
        self.assertEqual([c[0] for c in self.calls], ["sonnet"])
        v = self.store.get_incident(inc.id).verdict
        self.assertEqual(v["logs"], ["10/20 14:00:01 | real line from elk"])
        self.assertFalse(v["needs_human"])
        text = self.posts()[0][1]
        self.assertIn("real line from elk", text)
        self.assertNotIn("invented", text)

    def test_prompt_names_the_exact_elk_query_command(self):
        seen = {}

        def runner(model, prompt, cwd, add_dirs, timeout):
            seen["prompt"] = prompt
            return good()
        self.incident()
        self.make(runner=runner).run_once()
        self.assertNotIn("__ELK_QUERY__", seen["prompt"])
        self.assertIn(f"{sys.executable} -m alert_doctor elk-query count", seen["prompt"])
        for field in ("cause", "impact", "project", "fix", "logs", "remark"):
            self.assertIn(f"`{field}`", seen["prompt"])

    def test_prompt_explains_check_scripts_are_data(self):
        text = analyzer.PROMPT_PATH.read_text()
        self.assertIn("check_script_path", text)
        self.assertIn("task", text)

    def test_run_forever_stops(self):
        self.cfg = Config(channels=(ChannelSpec(CH, "alerts-a", ("sys",)),), workspace_url="https://x", db_path=os.path.join(self.tmp.name, "d.db"))
        stop = threading.Event()
        stop.set()
        self.make().run_forever(stop)


class AnalyzerV2Tests(AnalyzerBase):
    """Task C: mentions, auto-rule samples, mirror refresh with SHA invalidation."""

    def setUp(self):
        super().setUp()
        from alert_doctor import autorules, mentions
        self.ar = autorules
        mentions.clear_cache()
        self.addCleanup(mentions.clear_cache)

    def active_sample(self, inc, kind="noise"):
        rule = self.ar.propose_from_human(self.store, inc.fingerprint, NOW - 86400, "U1")
        with self.store.tx() as db:
            db.execute("UPDATE auto_rules SET state='active', kind=?, expires=? WHERE id=?",
                       (kind, NOW + 86400, rule.id))
        self.ar.record_sample(self.store, rule.id, inc.id, CH, inc.anchor_ts, NOW)
        return rule.id

    def rule_row(self, rid):
        return self.store.read(
            "SELECT state, sampled, rejections FROM auto_rules WHERE id=?", (rid,))[0]

    def seed_old_verdict(self, fp):
        old = ParsedAlert(channel=CH, ts="500.0", raw_text="r", parse_ok=True, check_title="T", check_code="c1")
        self.store.insert_message(old, 1.0)
        prev = self.store.create_incident(old, fp, "g")
        self.store.request_analysis(prev.id, now=NOW - 60)
        self.store.claim_incident("w", NOW - 60)
        self.store.complete_analysis(prev.id, good(category="noise"), "sonnet", NOW - 60)

    def test_sample_skips_verdict_reuse_and_agreeing_verdict_counts(self):
        self.make()
        self.seed_old_verdict("fp-c1")
        inc = self.incident()
        rid = self.active_sample(inc)
        self.responses = [good(category="noise")]
        self.make().run_once()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.rule_row(rid), ("active", 1, 0))

    def test_disagreeing_sample_invalidates_rule(self):
        self.make()
        inc = self.incident()
        rid = self.active_sample(inc)
        self.responses = [self.code_fix(fix_in_system="sys")]
        self.make().run_once()
        self.assertEqual(self.rule_row(rid), ("revoked", 0, 1))

    def test_needs_human_mentions_check_owners_first(self):
        self.slack.lookup_user_by_email = lambda token, email: {"o@x.tw": "UCHK"}.get(email)
        self.checks = {"c1": CheckSpec(key="c1", owners=("o@x.tw",))}
        self.responses = [good(category="unknown", action="investigate", needs_human=True, confidence=0.6)]
        self.incident()
        self.make().run_once()
        text = self.posts()[0][1]
        self.assertIn("需人工確認 <@UCHK>", text)
        self.assertNotIn("<@U1>", text)

    def test_needs_human_falls_back_to_system_owners(self):
        self.responses = [good(category="unknown", action="investigate", needs_human=True, confidence=0.6)]
        self.incident()
        self.make().run_once()
        self.assertIn("需人工確認 <@U1>", self.posts()[0][1])

    def test_cross_system_uses_fix_system_owners_not_check_owners(self):
        self.checks = {"c1": CheckSpec(key="c1", owners=("UCHK",))}
        self.responses = [good(fix_in_system="other")]
        self.incident()
        self.make().run_once()
        text = self.posts()[0][1]
        self.assertIn("<@U9>", text)
        self.assertNotIn("<@UCHK>", text)

    def test_final_failure_mentions_owners(self):
        self.checks = {"c1": CheckSpec(key="c1", owners=("UCHK",))}
        self.incident()
        self.responses = [RuntimeError("boom")]
        a = self.make()
        for _ in range(analyzer_max_attempts()):
            a.run_once()
        self.assertIn("<@UCHK>", self.posts()[0][1])

    def test_context_carries_attachments(self):
        inc = self.incident()
        self.store.save_evidence(inc.id, {"attachments": [{"name": "a.log", "path": "attachments/a.log"}]})
        self.make().run_once()
        with open(os.path.join(self.calls[0][1], "context.json")) as f:
            ctx = json.load(f)
        self.assertEqual(ctx["attachments"][0]["path"], "attachments/a.log")

    def test_refresh_mirrors_invalidates_rules_of_systems_using_changed_repo(self):
        self.make()
        a_sys = ParsedAlert(channel=CH, ts="1.0", raw_text="r", parse_ok=True, check_title="T")
        b_other = ParsedAlert(channel=CH, ts="2.0", raw_text="r", parse_ok=True, check_title="U")
        for alert, fp, system in ((a_sys, "fpa", "sys"), (b_other, "fpb", "other")):
            self.store.insert_message(alert, 1.0)
            self.store.create_incident(alert, fp, "g", source_system=system)
        rules = {}
        for fp in ("fpa", "fpb"):
            rule = self.ar.propose_from_human(self.store, fp, NOW - 86400, "U1")
            with self.store.tx() as db:
                db.execute("UPDATE auto_rules SET state='active', expires=? WHERE id=?", (NOW + 86400, rule.id))
            rules[fp] = rule.id

        def fake_refresh_all(cfg, on_change=None):
            on_change("repo", "a" * 40, "b" * 40)
            return {"repo": ("/x", "b" * 40)}
        analyzer.refresh_mirrors(self.cfg, self.store, NOW, fake_refresh_all)
        self.assertEqual(self.rule_row(rules["fpa"])[0], "revoked")
        self.assertEqual(self.rule_row(rules["fpb"])[0], "active")

    def test_run_forever_refreshes_mirrors_first(self):
        self.cfg = Config(**{**self.cfg.__dict__, "db_path": os.path.join(self.tmp.name, "d2.db")})
        stop = threading.Event()
        seen = []

        def fake_refresh_all(cfg, on_change=None):
            seen.append(cfg)
            stop.set()
            return {}
        a = Analyzer(self.cfg, self.store, self.slack, "tok", {}, clock=lambda: self.now,
                     refresh_all=fake_refresh_all, current=lambda *a: None, refresh=self._refresh)
        a.run_forever(stop)
        self.assertEqual(len(seen), 1)


if __name__ == "__main__":
    unittest.main()

