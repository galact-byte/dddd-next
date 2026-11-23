"""Exercise source synchronization with real files and git patch application."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sync_httpx import check_version, sync_httpx

MODULE = "github.com/projectdiscovery/httpx"
CHECKSUM = "h1:" + "A" * 43 + "="
ORIGINAL = """ratelimiter ratelimit.Limiter
minute = *ratelimit.New(ctx, count, time.Minute)
second = *ratelimit.New(ctx, count, time.Second)
unlimited = *ratelimit.NewUnlimited(ctx)
"""
PATCHED = """ratelimiter *ratelimit.Limiter
minute = ratelimit.New(ctx, count, time.Minute)
second = ratelimit.New(ctx, count, time.Second)
unlimited = ratelimit.NewUnlimited(ctx)
"""
PATCH = """--- a/runner/runner.go
+++ b/runner/runner.go
@@ -1,4 +1,4 @@
-ratelimiter ratelimit.Limiter
-minute = *ratelimit.New(ctx, count, time.Minute)
-second = *ratelimit.New(ctx, count, time.Second)
-unlimited = *ratelimit.NewUnlimited(ctx)
+ratelimiter *ratelimit.Limiter
+minute = ratelimit.New(ctx, count, time.Minute)
+second = ratelimit.New(ctx, count, time.Second)
+unlimited = ratelimit.NewUnlimited(ctx)
"""


class SyncHttpxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.vendor = self.repo / "third_party/httpx"
        (self.vendor / "runner").mkdir(parents=True)
        (self.vendor / "runner/runner.go").write_text(PATCHED, encoding="utf-8")
        (self.vendor / "old.txt").write_text("obsolete", encoding="utf-8")
        (self.repo / "third_party/httpx-ratelimiter.patch").write_text(PATCH, encoding="utf-8")
        self.record = self.repo / "third_party/httpx-upstream.json"
        self.record.write_text(json.dumps({"module": MODULE, "version": "v1.9.0", "sum": CHECKSUM}), encoding="utf-8")
        self.set_required("v1.10.0")
        self.source = Path(self.temp.name) / "upstream"
        (self.source / "runner").mkdir(parents=True)
        (self.source / "runner/runner.go").write_text(ORIGINAL, encoding="utf-8")
        (self.source / "go.mod").write_text(f"module {MODULE}\n", encoding="utf-8")
        (self.source / "LICENSE.md").write_text("MIT\n", encoding="utf-8")
        (self.source / "runner/page.html").write_text("embedded resource\n", encoding="utf-8")

    def set_required(self, version):
        (self.repo / "go.mod").write_text(
            f"module example\n\nrequire (\n\t{MODULE} {version}\n)\n"
            f"replace {MODULE} => ./third_party/httpx\n", encoding="utf-8")

    def snapshot(self):
        return {str(path.relative_to(self.repo)): path.read_bytes()
                for path in self.repo.rglob("*") if path.is_file()}

    def test_upgrade_copies_complete_source_and_preserves_fix(self):
        self.assertTrue(sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM))
        self.assertEqual((self.vendor / "runner/runner.go").read_text(), PATCHED)
        self.assertEqual((self.vendor / "runner/page.html").read_text(), "embedded resource\n")
        self.assertEqual((self.vendor / "LICENSE.md").read_text(), "MIT\n")
        self.assertFalse((self.vendor / "old.txt").exists())
        self.assertEqual(json.loads(self.record.read_text()),
                         {"module": MODULE, "version": "v1.10.0", "sum": CHECKSUM})
        check_version(self.repo)

    def test_same_version_preserves_local_dependency_changes(self):
        self.set_required("v1.9.0")
        before = self.snapshot()
        self.assertFalse(sync_httpx(self.repo, self.source / "missing", "v1.9.0", CHECKSUM))
        self.assertEqual(self.snapshot(), before)

    def test_conflicting_patch_leaves_repository_unchanged(self):
        (self.source / "runner/runner.go").write_text("incompatible implementation\n", encoding="utf-8")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "patch"):
            sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM)
        self.assertEqual(self.snapshot(), before)

    def test_already_fixed_upstream_is_not_patched_twice(self):
        (self.source / "runner/runner.go").write_text(PATCHED, encoding="utf-8")
        self.assertTrue(sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM))
        self.assertEqual((self.vendor / "runner/runner.go").read_text(), PATCHED)

    def test_rejects_unsafe_versions_and_downgrades_without_writes(self):
        for version in ("v2.0.0", "v1.10.0/../../escape", "v1.01.0", "v1.8.0", "v1.10.0-rc1"):
            with self.subTest(version=version):
                self.set_required(version)
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    sync_httpx(self.repo, self.source, version, CHECKSUM)
                self.assertEqual(self.snapshot(), before)

    def test_rejects_wrong_module_and_incomplete_source(self):
        (self.source / "go.mod").write_text("module another/module\n", encoding="utf-8")
        before = self.snapshot()
        with self.assertRaises(ValueError):
            sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM)
        self.assertEqual(self.snapshot(), before)
        (self.source / "go.mod").write_text(f"module {MODULE}\n", encoding="utf-8")
        (self.source / "LICENSE.md").unlink()
        with self.assertRaises(ValueError):
            sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM)
        self.assertEqual(self.snapshot(), before)

    def test_readonly_module_cache_becomes_writable_working_source(self):
        (self.source / "go.mod").chmod(0o444)
        self.assertTrue(sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM))
        with (self.vendor / "go.mod").open("a", encoding="utf-8") as output:
            output.write("// local maintenance remains possible\n")

    def test_readonly_previous_directory_is_removed_after_upgrade(self):
        self.vendor.chmod(0o555)
        self.assertTrue(sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM))
        self.assertEqual(json.loads(self.record.read_text())["version"], "v1.10.0")
        self.assertFalse(list((self.repo / "third_party").glob(".httpx-sync-*")))

    def test_manifest_write_failure_rolls_back_source_replacement(self):
        before = self.snapshot()
        with patch("sync_httpx.os.replace", side_effect=OSError("disk write failed")):
            with self.assertRaisesRegex(OSError, "disk write failed"):
                sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM)
        self.assertEqual(self.snapshot(), before)

    def test_temporary_windows_directory_lock_does_not_abort_upgrade(self):
        original_rename = Path.rename
        denied = False

        def deny_first_move(path, target):
            nonlocal denied
            if path == self.vendor and not denied:
                denied = True
                raise PermissionError("temporary directory lock")
            return original_rename(path, target)

        with patch("sync_httpx.WINDOWS", True), patch("sync_httpx.Path.rename", new=deny_first_move):
            self.assertTrue(sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM))
        self.assertEqual(json.loads(self.record.read_text())["version"], "v1.10.0")
        self.assertEqual((self.vendor / "runner/page.html").read_text(), "embedded resource\n")

    def test_failed_source_install_restores_source_and_record(self):
        before = self.snapshot()
        original_rename = Path.rename

        def reject_install(path, target):
            if path.name == "source":
                raise OSError("source installation failed")
            return original_rename(path, target)

        with patch("sync_httpx.Path.rename", new=reject_install):
            with self.assertRaisesRegex(OSError, "source installation failed"):
                sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM)
        self.assertEqual(self.snapshot(), before)

    def test_failed_restoration_keeps_previous_source_for_recovery(self):
        original_rename = Path.rename

        def reject_install_and_restore(path, target):
            if path.name in {"source", "previous"}:
                raise OSError("directory temporarily unavailable")
            return original_rename(path, target)

        with patch("sync_httpx.Path.rename", new=reject_install_and_restore):
            with self.assertRaises(OSError):
                sync_httpx(self.repo, self.source, "v1.10.0", CHECKSUM)
        saved = list((self.repo / "third_party").glob(".httpx-sync-*/previous/old.txt"))
        self.assertEqual(len(saved), 1, "failed rollback must preserve the original source")
        self.assertEqual(saved[0].read_text(), "obsolete")
        self.assertEqual(json.loads(self.record.read_text())["version"], "v1.9.0")

    def test_mismatched_request_and_invalid_checksum_do_not_write(self):
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "go.mod"):
            sync_httpx(self.repo, self.source, "v1.11.0", CHECKSUM)
        with self.assertRaisesRegex(ValueError, "checksum"):
            sync_httpx(self.repo, self.source, "v1.10.0", "not-a-go-checksum")
        self.assertEqual(self.snapshot(), before)

    def test_manifest_only_upgrade_fails_consistency_check(self):
        with self.assertRaisesRegex(ValueError, "source"):
            check_version(self.repo)
        self.set_required("v1.9.0")
        check_version(self.repo)


if __name__ == "__main__":
    unittest.main()
