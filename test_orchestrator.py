#!/usr/bin/env python3
"""
Unit and integration tests for Automated System Snapshot & Backup Orchestrator.
Uses standard library unittest for zero-dependency execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from backup_orchestrator import (
    ArchiveEngine,
    ConfigManager,
    IntegrityScanner,
    RetentionManager,
    TelegramAlerter,
)


class TestConfigManager(unittest.TestCase):
    """Tests for ConfigManager and environment variable interpolation."""

    def test_env_interpolation(self) -> None:
        with patch.dict(os.environ, {"SECRET_TOKEN": "my-secret-123", "CHAT_ID": "45678"}):
            interpolated = ConfigManager._interpolate_env({
                "telegram": {
                    "token": "${SECRET_TOKEN}",
                    "chat": "$CHAT_ID",
                    "plain": "constant_value",
                }
            })
            self.assertEqual(interpolated["telegram"]["token"], "my-secret-123")
            self.assertEqual(interpolated["telegram"]["chat"], "45678")
            self.assertEqual(interpolated["telegram"]["plain"], "constant_value")

    def test_missing_mandatory_keys(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("logging:\n  level: INFO\n")
            f_path = f.name
        try:
            with self.assertRaises(ValueError):
                ConfigManager.load_config(f_path)
        finally:
            os.unlink(f_path)


class TestIntegrityScanner(unittest.TestCase):
    """Tests for SHA-256 calculation and path scanning."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.file1 = self.root / "app.conf"
        self.file1.write_text("server { listen 80; }", encoding="utf-8")
        self.file2 = self.root / "temp.tmp"
        self.file2.write_text("temporary cache", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_sha256_computation(self) -> None:
        scanner = IntegrityScanner()
        expected_sha = hashlib.sha256(b"server { listen 80; }").hexdigest()
        actual_sha = scanner.compute_sha256(self.file1)
        self.assertEqual(actual_sha, expected_sha)

    def test_exclusion_patterns(self) -> None:
        scanner = IntegrityScanner(exclude_patterns=["*.tmp"])
        files, manifest, warnings = scanner.scan_targets([str(self.root)])
        file_names = [f.name for f in files]
        self.assertIn("app.conf", file_names)
        self.assertNotIn("temp.tmp", file_names)
        self.assertEqual(manifest["total_files"], 1)
        self.assertEqual(len(warnings), 0)


class TestArchiveEngine(unittest.TestCase):
    """Tests for archive generation, manifest embedding, and strict permissions."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.src_dir = self.root / "source"
        self.dest_dir = self.root / "dest"
        self.src_dir.mkdir()
        self.dest_dir.mkdir()

        self.sample_file = self.src_dir / "nginx.conf"
        self.sample_file.write_text("worker_processes 4;", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_create_archive_and_permissions(self) -> None:
        scanner = IntegrityScanner()
        files, manifest, _ = scanner.scan_targets([str(self.src_dir)])

        archive_path = ArchiveEngine.create_archive(
            destination_dir=self.dest_dir,
            prefix="test_backup",
            compression="gz",
            files=files,
            manifest=manifest,
            dry_run=False,
        )

        self.assertTrue(archive_path.exists())
        # Verify strict permissions 0600 (-rw-------)
        mode = stat.S_IMODE(archive_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

        # Verify archive structure
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            self.assertIn("manifest.json", members)
            manifest_file = tar.extractfile("manifest.json")
            self.assertIsNotNone(manifest_file)
            data = json.load(manifest_file)
            self.assertEqual(data["total_files"], 1)

    def test_dry_run_archive_creation(self) -> None:
        scanner = IntegrityScanner()
        files, manifest, _ = scanner.scan_targets([str(self.src_dir)])

        archive_path = ArchiveEngine.create_archive(
            destination_dir=self.dest_dir,
            prefix="dry_test",
            compression="gz",
            files=files,
            manifest=manifest,
            dry_run=True,
        )
        self.assertFalse(archive_path.exists())


class TestRetentionManager(unittest.TestCase):
    """Tests for backup rotation by age and count."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.dest_dir = Path(self.tmp_dir.name)

        # Create 4 dummy archive files with clear age boundaries (0.5d, 1.5d, 3.5d, 4.5d ago)
        self.archives: list[Path] = []
        now = time.time()
        ages_in_days = [0.5, 1.5, 3.5, 4.5]
        for idx, days in enumerate(ages_in_days):
            p = self.dest_dir / f"sys_snapshot-20261025_00000{idx}.tar.gz"
            p.touch()
            mtime = now - (days * 86400)
            os.utime(p, (mtime, mtime))
            self.archives.append(p)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_retention_by_max_backups(self) -> None:
        # Keep maximum 2 archives
        removed = RetentionManager.enforce_policy(
            destination_dir=self.dest_dir,
            prefix="sys_snapshot",
            retention_days=0,
            max_backups=2,
            dry_run=False,
        )
        self.assertEqual(len(removed), 2)
        remaining = list(self.dest_dir.glob("sys_snapshot-*.tar.gz"))
        self.assertEqual(len(remaining), 2)

    def test_retention_by_days(self) -> None:
        # Purge files older than 2 days (should remove 3.5d and 4.5d archives -> 2 files)
        removed = RetentionManager.enforce_policy(
            destination_dir=self.dest_dir,
            prefix="sys_snapshot",
            retention_days=2,
            max_backups=0,
            dry_run=False,
        )
        self.assertEqual(len(removed), 2)


class TestTelegramAlerter(unittest.TestCase):
    """Tests for Telegram alerter configuration handling."""

    def test_unconfigured_skips_safely(self) -> None:
        alerter = TelegramAlerter(bot_token="", chat_id="")
        self.assertFalse(alerter.is_configured)
        self.assertFalse(alerter.send_alert("SUCCESS", "test.tar.gz", 1.0, 0.5, 10, []))


class TestCLIIntegration(unittest.TestCase):
    """End-to-end integration test via CLI."""

    def test_cli_successful_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            src = tmp / "data"
            src.mkdir()
            (src / "test.txt").write_text("critical content", encoding="utf-8")
            dest = tmp / "backups"

            cfg_path = tmp / "test_config.yaml"
            cfg_path.write_text(f"""
backup:
  archive_prefix: "cli_backup"
  compression: "gz"
  destination_dir: "{dest}"
  targets:
    - "{src}"
retention:
  retention_days: 0
  max_backups: 5
logging:
  level: "DEBUG"
  log_to_console: false
telegram:
  enabled: false
""", encoding="utf-8")

            import subprocess
            res = subprocess.run(
                ["python3", "backup_orchestrator.py", "--config", str(cfg_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            created = list(dest.glob("cli_backup-*.tar.gz"))
            self.assertEqual(len(created), 1)


if __name__ == "__main__":
    unittest.main()

