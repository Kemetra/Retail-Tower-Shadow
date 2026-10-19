"""Tests for the kemetra-agent token broker.

Every key here is a THROWAWAY RSA key generated inside the test. The real
App key never appears in tests, fixtures or logs. HTTP and process spawning
are injected fakes, so nothing talks to GitHub or 1Password."""

import base64
import json
import os
import sys
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import broker  # noqa: E402

NOW = 1_800_000_000
TOKEN = "ghs_" + "T" * 36
GOOD_GRANT = {
    "token": TOKEN,
    "expires_at": "2027-01-15T08:00:00Z",
    "permissions": dict(broker.PERMISSIONS),
    "repository_selection": "selected",
    "repositories": [{"id": broker.REPO_ID, "full_name": "Kemetra/Retail-Tower-Shadow"}],
}


def _throwaway_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    return key, pem


def _b64d(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return self.responses.pop(0)


class JwtTests(unittest.TestCase):

    def test_jwt_is_rs256_with_bounded_lifetime_and_valid_signature(self):
        key, pem = _throwaway_key()
        jwt = broker.build_jwt(pem, broker.APP_ID, NOW)
        h, p, s = jwt.split(".")
        self.assertEqual(json.loads(_b64d(h)), {"alg": "RS256", "typ": "JWT"})
        claims = json.loads(_b64d(p))
        self.assertEqual(claims, {"iss": 5373224, "iat": NOW - 60, "exp": NOW + 540})
        key.public_key().verify(_b64d(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())

    def test_non_pem_key_is_rejected_without_echoing_it(self):
        with self.assertRaises(broker.BrokerError) as ctx:
            broker.build_jwt(b"not-a-key-SECRETVALUE", broker.APP_ID, NOW)
        self.assertNotIn("SECRETVALUE", str(ctx.exception))


class MintTests(unittest.TestCase):

    def test_request_is_scoped_to_shadow_and_requested_grants(self):
        http = FakeHttp([(201, GOOD_GRANT)])
        grant = broker.mint_installation_token("JWT", http)
        self.assertEqual(grant["token"], TOKEN)
        call = http.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], "https://api.github.com/app/installations/173158171/access_tokens")
        self.assertEqual(call["headers"]["Authorization"], "Bearer JWT")
        self.assertEqual(json.loads(call["body"]),
                         {"repository_ids": [1425468661], "permissions": broker.PERMISSIONS})

    def test_http_error_never_echoes_response_body(self):
        http = FakeHttp([(401, {"message": "bad", "leak": TOKEN})])
        with self.assertRaises(broker.BrokerError) as ctx:
            broker.mint_installation_token("JWT", http)
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))


class GrantCheckTests(unittest.TestCase):

    def _bad(self, **changes):
        grant = {**GOOD_GRANT, **changes}
        with self.assertRaises(broker.BrokerError) as ctx:
            broker.check_grant(grant)
        self.assertNotIn(TOKEN, str(ctx.exception))
        return str(ctx.exception)

    def test_good_grant_passes(self):
        broker.check_grant(GOOD_GRANT)

    def test_broader_or_extra_permissions_are_refused(self):
        self.assertIn("workflows", self._bad(permissions={**broker.PERMISSIONS, "workflows": "write"}))
        self.assertIn("issues", self._bad(permissions={**broker.PERMISSIONS, "issues": "write"}))
        self.assertIn("administration", self._bad(permissions={**broker.PERMISSIONS, "administration": "read"}))

    def test_wrong_repository_scope_is_refused(self):
        self._bad(repository_selection="all")
        self._bad(repositories=[{"id": broker.REPO_ID}, {"id": 1226504923}])
        self._bad(repositories=[])

    def test_malformed_token_is_refused(self):
        self._bad(token="ghp_classic")
        self._bad(token=None)
        self._bad(expires_at=None)


class ChildEnvTests(unittest.TestCase):

    BASE = {"PATH": "/bin", "GH_TOKEN": "owner", "GITHUB_TOKEN": "owner2", "GIT_ASKPASS": "x",
            "GH_ENTERPRISE_TOKEN": "e", "GH_CONFIG_DIR": "/home/owner/.config/gh", "KEEP": "1"}

    def test_owner_credentials_removed_and_bot_token_injected(self):
        base = dict(self.BASE)
        env = broker.child_env(base, TOKEN, "/tmp/empty-gh")
        self.assertEqual(base, self.BASE)                     # input not mutated
        self.assertEqual(env["GH_TOKEN"], TOKEN)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("GH_ENTERPRISE_TOKEN", env)
        self.assertNotIn("GIT_ASKPASS", env)
        self.assertEqual(env["GH_CONFIG_DIR"], "/tmp/empty-gh")
        self.assertEqual(env["KEEP"], "1")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GCM_INTERACTIVE"], "never")

    def test_git_uses_only_the_bot_token_and_identity(self):
        env = broker.child_env(dict(self.BASE), TOKEN, "/tmp/empty-gh")
        n = int(env["GIT_CONFIG_COUNT"])
        pairs = [(env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"]) for i in range(n)]
        self.assertEqual([v for k, v in pairs if k == "credential.helper"], [""])   # reset only, never unscoped
        scoped = [v for k, v in pairs if k == "credential.https://github.com.helper"]
        self.assertEqual(len(scoped), 1)
        self.assertIn("GH_TOKEN", scoped[0])
        self.assertNotIn(TOKEN, scoped[0])                    # helper reads env, token not in config
        for name in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
            self.assertEqual(env[name], "kemetra-agent[bot]")
        for name in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
            self.assertEqual(env[name], "344537132+kemetra-agent[bot]@users.noreply.github.com")


class GitCredentialIntegrationTests(unittest.TestCase):
    """Runs real `git credential fill` with the broker's env (no network)."""

    def test_git_returns_the_bot_token_not_the_owner_store(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as gh_dir:
            owner_cfg = os.path.join(gh_dir, "owner.gitconfig")
            with open(owner_cfg, "w") as fh:     # a stand-in for the owner's GCM / gh helper
                fh.write('[credential]\n\thelper = "!f() { echo username=owner; echo password=OWNER_SECRET; }; f"\n')
            base = {**os.environ, "GIT_CONFIG_GLOBAL": owner_cfg, "GIT_CONFIG_NOSYSTEM": "1"}
            env = broker.child_env(base, TOKEN, gh_dir)
            out = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                                 capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        fields = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
        self.assertEqual(fields.get("username"), "x-access-token")
        self.assertEqual(fields.get("password"), TOKEN)


class ReviewFindingTests(unittest.TestCase):
    """PR #3 review: helper scope, SSH bypass, revoke failures."""

    def _git(self, env, *args, stdin=None):
        import subprocess
        return subprocess.run(["git", *args], input=stdin, capture_output=True, text=True, env=env, timeout=30)

    def _env(self, tmp):
        owner_cfg = os.path.join(tmp, "owner.gitconfig")
        with open(owner_cfg, "w") as fh:
            fh.write('[credential]\n\thelper = "!f() { echo username=owner; echo password=OWNER_SECRET; }; f"\n')
        base = {**os.environ, "GIT_CONFIG_GLOBAL": owner_cfg, "GIT_CONFIG_NOSYSTEM": "1", "SSH_AUTH_SOCK": "/tmp/agent"}
        return broker.child_env(base, TOKEN, tmp)

    def test_token_is_only_offered_to_github_com(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(tmp)
            other = self._git(env, "credential", "fill", stdin="protocol=https\nhost=evil.example.com\n\n")
        self.assertNotIn(TOKEN, other.stdout)
        self.assertNotIn("OWNER_SECRET", other.stdout)

    def test_ssh_github_urls_are_rewritten_to_https_and_ssh_is_disabled(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(tmp)
            for url in ("git@github.com:Kemetra/Retail-Tower-Shadow.git",
                        "ssh://git@github.com/Kemetra/Retail-Tower-Shadow.git"):
                out = self._git(env, "ls-remote", "--get-url", url)
                self.assertEqual(out.stdout.strip(), "https://github.com/Kemetra/Retail-Tower-Shadow.git", url)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertIn("exit 1", env["GIT_SSH_COMMAND"])

    def test_failed_revoke_warns_instead_of_staying_silent(self):
        import contextlib
        import io
        _, pem = _throwaway_key()
        http = FakeHttp([(201, GOOD_GRANT), (500, None)])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = broker.run_session(["claude"], "op://tower/x/y", run=lambda c: pem, http=http,
                                      spawn=lambda a, e: 0, now=NOW, base_env={}, gh_config_dir="/tmp/g")
        self.assertEqual(code, 0)
        self.assertIn("WARNING", err.getvalue())
        self.assertIn("expires_at", err.getvalue())
        self.assertNotIn(TOKEN, err.getvalue())

    def test_check_mode_reports_failed_revoke(self):
        import contextlib
        import io
        _, pem = _throwaway_key()
        http = FakeHttp([(201, GOOD_GRANT), (0, None)])
        with contextlib.redirect_stderr(io.StringIO()):
            summary = broker.check_only("op://tower/x/y", run=lambda c: pem, http=http, now=NOW)
        self.assertFalse(summary["revoked"])

    def test_network_error_becomes_status_zero_not_traceback(self):
        import urllib.error
        import urllib.request
        original = urllib.request.urlopen

        def boom(*a, **k):
            raise urllib.error.URLError("network down")
        urllib.request.urlopen = boom
        try:
            self.assertEqual(broker._http("DELETE", "https://api.github.com/x", {}, None), (0, None))
        finally:
            urllib.request.urlopen = original


class ReadKeyTests(unittest.TestCase):

    def test_reads_via_op_with_given_reference(self):
        _, pem = _throwaway_key()
        seen = []

        def run(cmd):
            seen.append(cmd)
            return pem + b"\n"
        self.assertEqual(broker.read_key("op://tower/kemetra agent bot/private key", run), pem.strip())
        self.assertEqual(seen, [["op", "read", "op://tower/kemetra agent bot/private key"]])

    def test_account_is_passed_to_op_when_given(self):
        _, pem = _throwaway_key()
        seen = []

        def run(cmd):
            seen.append(cmd)
            return pem
        broker.read_key("op://tower/kemetra agent bot/private key", run, account="kemetra-labs.1password.com")
        self.assertEqual(seen, [["op", "read", "--account", "kemetra-labs.1password.com",
                                 "op://tower/kemetra agent bot/private key"]])

    def test_op_failure_shows_ops_error_line_but_never_stdout(self):
        import subprocess
        original = subprocess.run

        def fake_run(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, stdout=b"-----BEGIN SECRET-----",
                                               stderr=b"[ERROR] 2026/10/20 00:47:40 account is not signed in\nsecond line")
        subprocess.run = fake_run
        try:
            with self.assertRaises(broker.BrokerError) as ctx:
                broker._run_op(["op", "read", "op://v/i/f"])
        finally:
            subprocess.run = original
        msg = str(ctx.exception)
        self.assertIn("account is not signed in", msg)
        self.assertNotIn("SECRET", msg)
        self.assertNotIn("second line", msg)

    def test_non_pem_output_is_rejected_without_echo(self):
        with self.assertRaises(broker.BrokerError) as ctx:
            broker.read_key("op://v/i/f", lambda cmd: b"SECRETVALUE")
        self.assertNotIn("SECRETVALUE", str(ctx.exception))

    def test_reference_must_be_op_uri_and_nothing_is_run_otherwise(self):
        _, pem = _throwaway_key()
        calls = []

        def run(cmd):
            calls.append(cmd)
            return pem
        with self.assertRaises(broker.BrokerError):
            broker.read_key("C:/keys/agent.pem", run)
        self.assertEqual(calls, [])


class SessionTests(unittest.TestCase):

    def setUp(self):
        _, self.pem = _throwaway_key()
        self.spawned = []

    def _spawn(self, code):
        def spawn(argv, env):
            self.spawned.append((argv, env))
            return code
        return spawn

    def test_session_runs_command_with_bot_env_then_revokes(self):
        http = FakeHttp([(201, GOOD_GRANT), (204, None)])
        code = broker.run_session(["claude"], "op://tower/x/y", run=lambda c: self.pem, http=http,
                                  spawn=self._spawn(7), now=NOW, base_env={"PATH": "/bin", "GH_TOKEN": "owner"},
                                  gh_config_dir="/tmp/g")
        self.assertEqual(code, 7)
        argv, env = self.spawned[0]
        self.assertEqual(argv, ["claude"])
        self.assertEqual(env["GH_TOKEN"], TOKEN)
        self.assertFalse(any(self.pem.decode().strip()[:40] in v for v in env.values()))
        self.assertEqual(http.calls[1]["method"], "DELETE")
        self.assertEqual(http.calls[1]["url"], "https://api.github.com/installation/token")
        self.assertEqual(http.calls[1]["headers"]["Authorization"], f"Bearer {TOKEN}")

    def test_token_revoked_even_if_command_crashes(self):
        http = FakeHttp([(201, GOOD_GRANT), (204, None)])

        def spawn(argv, env):
            raise OSError("claude not found")
        with self.assertRaises(OSError):
            broker.run_session(["claude"], "op://tower/x/y", run=lambda c: self.pem, http=http, spawn=spawn,
                               now=NOW, base_env={}, gh_config_dir="/tmp/g")
        self.assertEqual(http.calls[-1]["method"], "DELETE")

    def test_bad_grant_spawns_nothing(self):
        http = FakeHttp([(201, {**GOOD_GRANT, "repository_selection": "all"}), (204, None)])
        with self.assertRaises(broker.BrokerError):
            broker.run_session(["claude"], "op://tower/x/y", run=lambda c: self.pem, http=http,
                               spawn=self._spawn(0), now=NOW, base_env={}, gh_config_dir="/tmp/g")
        self.assertEqual(self.spawned, [])
        self.assertEqual(http.calls[-1]["method"], "DELETE")   # the over-broad token is revoked too

    def test_check_mode_prints_only_non_secret_summary(self):
        http = FakeHttp([(201, GOOD_GRANT), (204, None)])
        summary = broker.check_only("op://tower/x/y", run=lambda c: self.pem, http=http, now=NOW)
        self.assertEqual(summary, {"expires_at": "2027-01-15T08:00:00Z", "repositories": ["Kemetra/Retail-Tower-Shadow"],
                                   "permissions": broker.PERMISSIONS, "revoked": True})
        self.assertNotIn(TOKEN, json.dumps(summary))

    def test_main_requires_a_command_after_separator(self):
        with self.assertRaises(SystemExit):
            broker.main(["--op-ref", "op://tower/x/y"])


if __name__ == "__main__":
    unittest.main()
