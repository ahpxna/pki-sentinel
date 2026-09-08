"""Run the actual bootstrap script against local command doubles; no Vault needed."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]


class BootstrapRevocationTests(unittest.TestCase):
    def run_bootstrap(self, revoke_status, root_status=200, apply_revoke=True, keep_root=False, already_revoked=False, bootstrap_admin=False, audit_status=0):
        with tempfile.TemporaryDirectory(prefix="pki-bootstrap-test-") as directory:
            root = Path(directory)
            scripts = root / "scripts"
            (scripts / "lib").mkdir(parents=True)
            for name in ("bootstrap.sh", "terraform-day2.sh", "lib/wait_for.sh"):
                shutil.copy2(REPO / "scripts" / name, scripts / name)
            (scripts / "generate-executor-token.sh").write_text("#!/bin/sh\nexit 0\n")
            policies = root / "terraform/bootstrap/policies"
            policies.mkdir(parents=True)
            for name in ("terraform-bootstrap.hcl", "terraform-bootstrap-admin.hcl"):
                (policies / name).write_text("# test policy\n")
            data = root / ".data"
            (data / "approle").mkdir(parents=True)
            (data / "vault-init.json").write_text(json.dumps({"root_token": "test-root"}))
            if not bootstrap_admin:
                (data / "tf-token").write_text("test-day2")
                (data / "approle/terraform.env").write_text("VAULT_ROLE_ID=test-role\nVAULT_SECRET_ID=test-secret\n")
            if already_revoked:
                (root / "root-revoked").touch()
            commands = root / "bin"
            commands.mkdir()
            for name in ("docker", "terraform", "sleep"):
                command = commands / name
                command.write_text("#!/bin/sh\nexit 0\n")
                command.chmod(0o700)
            terraform = commands / "terraform"
            terraform.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["MOCK_STATE"]).parent
with (root / "terraform-calls.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\\n")
if "apply" in args:
    if "-target=vault_audit.file" in args:
        sys.exit(int(os.environ["MOCK_AUDIT_STATUS"]))
    if not any(arg.startswith("-target=") for arg in args):
        (root / ".data/approle/terraform.env").write_text("VAULT_ROLE_ID=test-role\\nVAULT_SECRET_ID=test-secret\\n")
''')
            curl = commands / "curl"
            curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
url = args[-1]
if "/sys/health" in url:
    if "-w" in args:
        print("200", end="")
    else:
        print(json.dumps({"initialized": True, "sealed": False}))
elif "/sys/policies/acl/" in url:
    pass
elif url.endswith("/auth/token/create"):
    print(json.dumps({"auth": {"client_token": "test-admin"}}))
elif url.endswith("/auth/approle/login"):
    print(json.dumps({"auth": {"client_token": "test-day2"}}))
elif url.endswith("/auth/token/lookup-self"):
    root = "X-Vault-Token: test-root" in args
    revoked = pathlib.Path(os.environ["MOCK_STATE"]).exists()
    if root and os.environ["MOCK_ROOT_STATUS"] == "network-error":
        sys.exit(7)
    print(("403" if revoked else os.environ["MOCK_ROOT_STATUS"]) if root else "200", end="")
elif url.endswith("/auth/token/revoke-self"):
    status = int(os.environ["MOCK_REVOKE_STATUS"])
    if status == 204 and os.environ["MOCK_APPLY_REVOKE"] == "1":
        pathlib.Path(os.environ["MOCK_STATE"]).touch()
    if "-w" in args:
        print(status, end="")
    if status >= 400 and any(a.startswith("-") and not a.startswith("--") and "f" in a for a in args):
        sys.exit(22)
else:
    sys.exit("unexpected mock URL: " + url)
''')
            curl.chmod(0o700)
            env = os.environ.copy()
            env.update(PATH=str(commands) + os.pathsep + env["PATH"],
                       MOCK_REVOKE_STATUS=str(revoke_status),
                       MOCK_AUDIT_STATUS=str(audit_status),
                       MOCK_ROOT_STATUS=str(root_status),
                       MOCK_APPLY_REVOKE="1" if apply_revoke else "0",
                       MOCK_STATE=str(root / "root-revoked"),
                       PKI_SENTINEL_KEEP_ROOT="1" if keep_root else "0")
            result = subprocess.run(["bash", str(scripts / "bootstrap.sh")],
                                    env=env, text=True, capture_output=True, timeout=15)
            calls = root / "terraform-calls.jsonl"
            result.terraform_calls = [json.loads(line) for line in calls.read_text().splitlines()]
            return result

    def test_audit_setup_completes_before_full_apply(self):
        result = self.run_bootstrap(204, bootstrap_admin=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        applies = [call for call in result.terraform_calls if "apply" in call]
        self.assertEqual(len(applies), 2, applies)
        self.assertIn("-target=vault_audit.file", applies[0])
        self.assertFalse(any(arg.startswith("-target=") for arg in applies[1]))

    def test_audit_setup_failure_stops_other_resource_writes(self):
        result = self.run_bootstrap(204, bootstrap_admin=True, audit_status=1)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        applies = [call for call in result.terraform_calls if "apply" in call]
        self.assertEqual(len(applies), 1, applies)
        self.assertIn("-target=vault_audit.file", applies[0])
        self.assertNotIn("Root token revoked.", result.stdout)

    def test_revoke_http_error_must_fail_bootstrap(self):
        for status in (302, 403, 500, 503):
            with self.subTest(status=status):
                result = self.run_bootstrap(status)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("Root token revoked.", result.stdout)
                self.assertNotIn("[bootstrap] Done.", result.stdout)

    def test_successful_revoke_finishes_bootstrap(self):
        result = self.run_bootstrap(204)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Root token revoked.", result.stdout)

    def test_lookup_failure_is_not_treated_as_revocation(self):
        for status in (500, 503, "network-error"):
            with self.subTest(status=status):
                result = self.run_bootstrap(204, root_status=status)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("already revoked", result.stdout)

    def test_success_response_requires_rejected_token(self):
        result = self.run_bootstrap(204, apply_revoke=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Root token revoked.", result.stdout)

    def test_already_revoked_token_remains_idempotent(self):
        result = self.run_bootstrap(500, already_revoked=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already revoked", result.stdout)

    def test_explicit_keep_root_option(self):
        result = self.run_bootstrap(500, keep_root=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("keeping root token", result.stdout)


if __name__ == "__main__":
    unittest.main()
