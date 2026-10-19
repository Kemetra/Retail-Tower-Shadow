"""kemetra-agent token broker (RT-721 Substep B, step B6).

Runs in the OWNER's shell. It reads the App private key from 1Password
(`op read`; the unlock prompt is the owner's approval), mints a 1-hour
installation token scoped to the private Shadow only, checks the grant is no
broader than requested, starts the given command with ONLY that token, and
revokes the token when the command exits. The key is never written to disk,
passed to the child, or printed; the token is never printed.

Design: tools/ci-gate/AGENT-BROKER.md. This file is in the `policy` class.

Usage:
  python broker.py --check                        # mint, verify, revoke; print non-secret summary
  python broker.py -- claude                      # run a session as kemetra-agent[bot]
  python broker.py --op-ref "op://tower/kemetra agent bot/private key" -- claude
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

APP_ID = 5373224
INSTALLATION_ID = 173158171
REPO_ID = 1425468661
DEFAULT_OP_REF = "op://tower/kemetra agent bot/private key"
API = "https://api.github.com"
PERMISSIONS = {
    "contents": "write",
    "pull_requests": "write",
    "issues": "read",
    "checks": "read",
    "actions": "read",
    "metadata": "read",
}
BOT_NAME = "kemetra-agent[bot]"
BOT_EMAIL = "344537132+kemetra-agent[bot]@users.noreply.github.com"
OWNER_CREDENTIAL_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                         "GIT_ASKPASS", "SSH_ASKPASS", "GH_CONFIG_DIR", "SSH_AUTH_SOCK", "SSH_AGENT_PID",
                         "GIT_SSH", "GIT_SSH_COMMAND")
# SSH would use the owner's keys / agent, so it is disabled; GitHub SSH URLs are rewritten to HTTPS.
NO_SSH = 'echo "broker: SSH is disabled in agent sessions; use HTTPS" >&2; exit 1'
LEVEL = {"read": 1, "write": 2, "admin": 3}
# Reads the token from the environment at call time, so it never lands in git config.
CREDENTIAL_HELPER = '!f() { test "$1" = get && echo username=x-access-token && echo "password=$GH_TOKEN"; }; f'


class BrokerError(RuntimeError):
    """Messages never contain key material, tokens or HTTP bodies."""


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jwt(key_pem, app_id, now):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError):
        raise BrokerError("private key is not a valid unencrypted PEM") from None
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"iss": app_id, "iat": now - 60, "exp": now + 540}
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def _headers(bearer):
    return {"Authorization": f"Bearer {bearer}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "kemetra-agent-broker"}


def mint_installation_token(jwt, http):
    body = json.dumps({"repository_ids": [REPO_ID], "permissions": PERMISSIONS})
    status, data = http("POST", f"{API}/app/installations/{INSTALLATION_ID}/access_tokens", _headers(jwt), body)
    if status != 201 or not isinstance(data, dict):
        raise BrokerError(f"token request failed with HTTP {status}")
    return data


def check_grant(grant):
    token = grant.get("token")
    if not isinstance(token, str) or not token.startswith("ghs_"):
        raise BrokerError("response has no installation token")
    if not grant.get("expires_at"):
        raise BrokerError("response has no expiry")
    if grant.get("repository_selection") != "selected":
        raise BrokerError("token is not limited to selected repositories")
    repo_ids = [r.get("id") for r in grant.get("repositories") or []]
    if repo_ids != [REPO_ID]:
        raise BrokerError(f"token repositories are {repo_ids}, expected only {REPO_ID}")
    for name, level in (grant.get("permissions") or {}).items():
        wanted = PERMISSIONS.get(name)
        if wanted is None or LEVEL.get(level, 99) > LEVEL[wanted]:
            raise BrokerError(f"token grants {name}:{level}, more than requested")


def revoke(token, http):
    status, _ = http("DELETE", f"{API}/installation/token", _headers(token), None)
    return status == 204


def child_env(base_env, token, gh_config_dir):
    env = {k: v for k, v in base_env.items() if k not in OWNER_CREDENTIAL_VARS}
    pairs = [
        ("credential.helper", ""),                                   # drop GCM / gh / owner helpers
        ("credential.https://github.com.helper", CREDENTIAL_HELPER),  # bot token for github.com only
        ("url.https://github.com/.insteadOf", "git@github.com:"),
        ("url.https://github.com/.insteadOf", "ssh://git@github.com/"),
    ]
    env.update({
        "GH_TOKEN": token,
        "GH_CONFIG_DIR": gh_config_dir,
        "GIT_SSH_COMMAND": NO_SSH,
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_AUTHOR_NAME": BOT_NAME, "GIT_COMMITTER_NAME": BOT_NAME,
        "GIT_AUTHOR_EMAIL": BOT_EMAIL, "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        "GIT_CONFIG_COUNT": str(len(pairs)),
    })
    for i, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def read_key(op_ref, run):
    if not op_ref.startswith("op://"):
        raise BrokerError("the key reference must be a 1Password op:// URI")
    out = run(["op", "read", op_ref]).strip()
    if not out.startswith(b"-----BEGIN") or b"PRIVATE KEY-----" not in out:
        raise BrokerError("1Password value is not a PEM private key")
    return out


def _mint(op_ref, run, http, now):
    key = read_key(op_ref, run)
    try:
        jwt = build_jwt(key, APP_ID, now)
    finally:
        del key
    return mint_installation_token(jwt, http)


def _revoke_if_token(grant, http):
    token = grant.get("token")
    if not (isinstance(token, str) and token):
        return False
    if revoke(token, http):
        return True
    print(f"broker: WARNING token revocation failed; it stays valid until expires_at {grant.get('expires_at')}",
          file=sys.stderr)
    return False


def run_session(argv, op_ref, *, run, http, spawn, now, base_env, gh_config_dir):
    grant = _mint(op_ref, run, http, now)
    try:
        check_grant(grant)
        return spawn(argv, child_env(base_env, grant["token"], gh_config_dir))
    finally:
        _revoke_if_token(grant, http)


def check_only(op_ref, *, run, http, now):
    grant = _mint(op_ref, run, http, now)
    try:
        check_grant(grant)
        summary = {"expires_at": grant["expires_at"],
                   "repositories": [r.get("full_name") for r in grant["repositories"]],
                   "permissions": grant["permissions"]}
    finally:
        revoked = _revoke_if_token(grant, http)
    return {**summary, "revoked": revoked}


# ----------------------------------------------------------- real adapters

def _run_op(cmd):
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode != 0:
        raise BrokerError(f"`op read` failed (exit {proc.returncode}); is 1Password unlocked and the reference right?")
    return proc.stdout


def _http(method, url, headers, body):
    data = body.encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read()
    except (urllib.error.URLError, OSError):
        return 0, None          # network failure: callers treat any non-success status as failure
    try:
        return status, (json.loads(raw) if raw else None)
    except ValueError:
        return status, None


def _spawn(argv, env):
    exe = shutil.which(argv[0], path=env.get("PATH")) or argv[0]
    return subprocess.call([exe, *argv[1:]], env=env)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[argv.index("--") + 1:] if "--" in argv else []
    own = argv[:argv.index("--")] if "--" in argv else argv
    parser = argparse.ArgumentParser(prog="broker.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("--op-ref", default=DEFAULT_OP_REF, help="1Password op:// reference to the PEM")
    parser.add_argument("--check", action="store_true", help="mint, verify and revoke; print a non-secret summary")
    args = parser.parse_args(own)
    if not args.check and not command:
        parser.error("give a command after `--`, e.g. `-- claude`, or use --check")
    try:
        if args.check:
            summary = check_only(args.op_ref, run=_run_op, http=_http, now=int(time.time()))
            print(json.dumps(summary, indent=2))
            return 0
        with tempfile.TemporaryDirectory(prefix="kemetra-agent-gh-") as gh_dir:
            return run_session(command, args.op_ref, run=_run_op, http=_http, spawn=_spawn,
                               now=int(time.time()), base_env=dict(os.environ), gh_config_dir=gh_dir)
    except BrokerError as exc:
        print(f"broker: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
