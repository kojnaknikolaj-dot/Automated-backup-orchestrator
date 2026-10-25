#!/usr/bin/env python3
"""
Automated System Snapshot & Backup Orchestrator.

Production-grade backup automation for critical Linux system configuration
and directories with SHA-256 integrity checks, compression, retention policy,
and Telegram alerting.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml


class ConfigManager:
    """Handles configuration loading, schema validation, and env variable interpolation."""

    @staticmethod
    def _interpolate_env(val: Any) -> Any:
        """Recursively replaces ${VAR_NAME} or $VAR_NAME placeholders with environment variables."""
        if isinstance(val, str):
            pattern = re.compile(r"\$\{?([A-Za-z0-9_]+)\}?")

            def replace(match: re.Match) -> str:
                var_name = match.group(1)
                return os.environ.get(var_name, match.group(0))

            return pattern.sub(replace, val)
        elif isinstance(val, dict):
            return {k: ConfigManager._interpolate_env(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [ConfigManager._interpolate_env(item) for item in val]
        return val

    @classmethod
    def load_config(cls, config_path: str | Path) -> Dict[str, Any]:
        """Loads and validates YAML configuration file with environment interpolation."""
        path = Path(config_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_config = yaml.safe_load(f) or {}
        except yaml.YAMLError as err:
            raise ValueError(f"YAML parsing error in {path}: {err}") from err

        config = cls._interpolate_env(raw_config)

        # Validate mandatory keys
        if "backup" not in config:
            raise ValueError("Missing 'backup' section in configuration file.")
        if "targets" not in config["backup"] or not config["backup"]["targets"]:
            raise ValueError("'backup.targets' list must not be empty.")
        if "destination_dir" not in config["backup"]:
            raise ValueError("Missing 'backup.destination_dir' in configuration.")

        return config


class IntegrityScanner:
    """Performs filesystem scanning and SHA-256 hash manifest calculations."""

    CHUNK_SIZE = 64 * 1024  # 64 KB read buffer

    def __init__(self, exclude_patterns: Optional[List[str]] = None) -> None:
        self.exclude_patterns = exclude_patterns or []

    def _is_excluded(self, path_str: str) -> bool:
        """Checks if a given path matches any configured exclusion patterns."""
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(os.path.basename(path_str), pattern):
                return True
        return False

    def compute_sha256(self, file_path: Path) -> Optional[str]:
        """Calculates SHA-256 hash in a chunked streaming manner to avoid memory bloat."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as err:
            logging.warning("Unable to compute SHA-256 for '%s': %s", file_path, err)
            return None

    def scan_targets(self, targets: List[str]) -> Tuple[List[Path], Dict[str, Any], List[str]]:
        """
        Scans all target paths, filters non-regular files and excluded patterns,
        computes SHA-256 digests, and generates a structured manifest.
        """
        files_to_backup: List[Path] = []
        manifest_files: Dict[str, Dict[str, Any]] = {}
        warnings: List[str] = []

        for target in targets:
            target_path = Path(target)
            if not target_path.exists():
                warn_msg = f"Target does not exist: {target_path}"
                logging.warning(warn_msg)
                warnings.append(warn_msg)
                continue

            if target_path.is_file():
                if self._is_excluded(str(target_path)):
                    continue
                sha = self.compute_sha256(target_path)
                try:
                    st = target_path.stat()
                    files_to_backup.append(target_path)
                    manifest_files[str(target_path)] = {
                        "size_bytes": st.st_size,
                        "sha256": sha or "UNREADABLE",
                        "mode": oct(stat.S_IMODE(st.st_mode)),
                        "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                    }
                except OSError as err:
                    warn_msg = f"Cannot read metadata for '{target_path}': {err}"
                    logging.warning(warn_msg)
                    warnings.append(warn_msg)
            elif target_path.is_dir():
                for root, dirs, files in os.walk(target_path, followlinks=False):
                    # Filter directories matching exclusions in-place
                    dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]

                    for file_name in files:
                        full_path = Path(root) / file_name
                        if self._is_excluded(str(full_path)):
                            continue

                        # Skip sockets, FIFOs, and special character/block devices
                        try:
                            st = full_path.lstat()
                            if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                                logging.debug("Skipping special/non-regular file: %s", full_path)
                                continue

                            sha = self.compute_sha256(full_path) if stat.S_ISREG(st.st_mode) else "SYMLINK"
                            files_to_backup.append(full_path)
                            manifest_files[str(full_path)] = {
                                "size_bytes": st.st_size,
                                "sha256": sha or "UNREADABLE",
                                "mode": oct(stat.S_IMODE(st.st_mode)),
                                "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                            }
                        except OSError as err:
                            warn_msg = f"Failed to access '{full_path}': {err}"
                            logging.warning(warn_msg)
                            warnings.append(warn_msg)

        manifest = {
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_files": len(files_to_backup),
            "files": manifest_files,
            "warnings": warnings,
        }
        return files_to_backup, manifest, warnings


class ArchiveEngine:
    """Manages tar archive creation with atomic writes and strict permissions."""

    @staticmethod
    def create_archive(
        destination_dir: Path,
        prefix: str,
        compression: str,
        files: List[Path],
        manifest: Dict[str, Any],
        dry_run: bool = False,
    ) -> Path:
        """
        Creates a timestamped tar archive containing the target files and manifest.json.
        Uses a temporary file for atomic write safety and sets 0600 permissions.
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "tar.gz" if compression == "gz" else "tar.bz2"
        mode = "w:gz" if compression == "gz" else "w:bz2"
        archive_name = f"{prefix}-{timestamp}.{ext}"
        final_path = destination_dir / archive_name
        tmp_path = destination_dir / f".{archive_name}.tmp"

        if dry_run:
            logging.info("[DRY-RUN] Would create archive: %s with %d files", final_path, len(files))
            return final_path

        destination_dir.mkdir(parents=True, exist_ok=True)
        # Ensure destination dir has safe directory permissions (0700 or 0750)
        try:
            os.chmod(destination_dir, 0o750)
        except OSError:
            pass

        manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

        logging.info("Building archive: %s (mode: %s)", tmp_path, mode)
        try:
            with tarfile.open(tmp_path, mode=mode) as tar:
                # Add manifest as an in-memory tar member
                manifest_info = tarfile.TarInfo(name="manifest.json")
                manifest_info.size = len(manifest_json)
                manifest_info.mtime = int(time.time())
                manifest_info.mode = 0o600
                import io

                tar.addfile(manifest_info, fileobj=io.BytesIO(manifest_json))

                # Add files preserving absolute paths safely
                for file_path in files:
                    try:
                        # Arcname without root slash to avoid absolute path extraction warnings
                        arcname = str(file_path).lstrip(os.sep)
                        tar.add(file_path, arcname=arcname, recursive=False)
                    except (PermissionError, FileNotFoundError, OSError) as err:
                        logging.warning("Failed to append '%s' to archive: %s", file_path, err)

            # Atomic rename and restrict permissions to owner only
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, final_path)
            logging.info("Archive successfully created: %s (Size: %.2f MB)", final_path, final_path.stat().st_size / (1024 * 1024))
            return final_path
        except Exception:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise


class RetentionManager:
    """Enforces retention policies based on age (days) and maximum count."""

    @staticmethod
    def enforce_policy(
        destination_dir: Path,
        prefix: str,
        retention_days: int = 0,
        max_backups: int = 0,
        dry_run: bool = False,
    ) -> List[Path]:
        """
        Deletes old archives that exceed the retention days threshold or max_backups limit.
        Returns the list of removed files.
        """
        if not destination_dir.exists():
            return []

        # Find matching archives
        pattern = f"{prefix}-*.tar.*"
        archives = [p for p in destination_dir.glob(pattern) if p.is_file() and not p.name.startswith(".")]

        # Sort by modification time (newest first)
        archives.sort(key=lambda p: p.stat().st_mtime, reverse=True)

        removed: List[Path] = []
        now = time.time()
        max_age_seconds = retention_days * 86400 if retention_days > 0 else 0

        # Pass 1: Age-based purge
        surviving: List[Path] = []
        for arch in archives:
            arch_age = now - arch.stat().st_mtime
            if max_age_seconds > 0 and arch_age > max_age_seconds:
                logging.info("Purging expired backup (age: %.1f days): %s", arch_age / 86400, arch.name)
                if not dry_run:
                    arch.unlink(missing_ok=True)
                removed.append(arch)
            else:
                surviving.append(arch)

        # Pass 2: Count-based purge
        if max_backups > 0 and len(surviving) > max_backups:
            overflow = surviving[max_backups:]
            for arch in overflow:
                logging.info("Purging excess backup (quota limit: %d): %s", max_backups, arch.name)
                if not dry_run:
                    arch.unlink(missing_ok=True)
                removed.append(arch)

        return removed


class TelegramAlerter:
    """Sends structured execution reports to a Telegram chat."""

    def __init__(self, bot_token: Optional[str], chat_id: Optional[str], timeout: int = 10) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        """Returns True if bot token and chat_id are non-empty and not dummy placeholders."""
        return bool(self.bot_token and self.chat_id and not self.bot_token.startswith("${"))

    def send_alert(
        self,
        status: str,
        archive_name: str,
        archive_size_mb: float,
        duration_sec: float,
        files_count: int,
        warnings: List[str],
        error_msg: Optional[str] = None,
    ) -> bool:
        """Sends formatted Telegram message with execution statistics and status."""
        if not self.is_configured:
            logging.debug("Telegram alerting skipped: missing or unconfigured credentials.")
            return False

        emoji = "✅" if status == "SUCCESS" else ("⚠️" if status == "WARNING" else "❌")
        hostname = os.uname().nodename

        lines = [
            f"{emoji} *System Backup Report* ({hostname})",
            f"• *Status:* `{status}`",
            f"• *Archive:* `{archive_name}`",
            f"• *Size:* `{archive_size_mb:.2f} MB`",
            f"• *Files Count:* `{files_count}`",
            f"• *Duration:* `{duration_sec:.2f}s`",
        ]

        if warnings:
            lines.append(f"• *Warnings:* `{len(warnings)}`")
            for w in warnings[:3]:
                lines.append(f"  └ _{w}_")
            if len(warnings) > 3:
                lines.append(f"  └ _...and {len(warnings) - 3} more_")

        if error_msg:
            lines.append(f"• *Error:* `{error_msg}`")

        text = "\n".join(lines)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                logging.info("Telegram alert sent successfully.")
                return True
            else:
                logging.error("Telegram API error (%d): %s", resp.status_code, resp.text)
                return False
        except requests.RequestException as err:
            logging.error("Failed to send Telegram alert: %s", err)
            return False


def setup_logging(log_file: Optional[str] = None, level_str: str = "INFO", log_to_console: bool = True) -> None:
    """Configures root logger with file handler and console stdout handler."""
    log_level = getattr(logging, level_str.upper(), logging.INFO)
    handlers: List[logging.Handler] = []

    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        handlers.append(console_handler)

    if log_file:
        try:
            log_path = Path(log_file).resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(process)d] %(message)s"))
            handlers.append(file_handler)
            # Safe log file permissions: 0640
            try:
                os.chmod(log_path, 0o640)
            except OSError:
                pass
        except OSError as err:
            print(f"[ERROR] Could not initialize log file '{log_file}': {err}", file=sys.stderr)

    logging.basicConfig(level=log_level, handlers=handlers, force=True)


def parse_args() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Automated System Snapshot & Backup Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the backup run without creating archives or deleting files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force execution even if minor pre-flight checks fail",
    )
    return parser.parse_args()


def main() -> int:
    """Main execution orchestrator."""
    start_time = time.time()
    args = parse_args()

    # Load configuration
    try:
        config = ConfigManager.load_config(args.config)
    except Exception as err:
        print(f"[CRITICAL] Configuration failure: {err}", file=sys.stderr)
        return 1

    # Setup Logging
    log_cfg = config.get("logging", {})
    setup_logging(
        log_file=log_cfg.get("log_file"),
        level_str=log_cfg.get("level", "INFO"),
        log_to_console=log_cfg.get("log_to_console", True),
    )

    logging.info("Starting Backup Orchestrator (Dry-run: %s)", args.dry_run)

    # Initialize Telegram Alerter
    tg_cfg = config.get("telegram", {})
    alerter = TelegramAlerter(
        bot_token=tg_cfg.get("bot_token") if tg_cfg.get("enabled", False) else None,
        chat_id=tg_cfg.get("chat_id"),
        timeout=tg_cfg.get("timeout_seconds", 10),
    )

    backup_cfg = config["backup"]
    retention_cfg = config.get("retention", {})
    destination_dir = Path(backup_cfg["destination_dir"]).resolve()
    prefix = backup_cfg.get("archive_prefix", "sys_snapshot")
    compression = backup_cfg.get("compression", "gz")
    targets = backup_cfg.get("targets", [])
    exclude_patterns = backup_cfg.get("exclude_patterns", [])

    status = "SUCCESS"
    archive_path: Optional[Path] = None
    files_count = 0
    warnings: List[str] = []
    error_msg: Optional[str] = None

    try:
        # Pre-flight disk space check (ensure at least 500 MB free)
        try:
            if not args.dry_run:
                destination_dir.mkdir(parents=True, exist_ok=True)
            
            check_path = destination_dir if destination_dir.exists() else destination_dir.parent
            while not check_path.exists() and check_path != check_path.parent:
                check_path = check_path.parent

            stat_vfs = shutil.disk_usage(check_path)
            free_mb = stat_vfs.free / (1024 * 1024)
            if free_mb < 500 and not args.force:
                raise OSError(f"Insufficient disk space on destination filesystem: {free_mb:.1f} MB available (min 500 MB required)")
            logging.info("Destination filesystem at '%s': %.1f MB available", check_path, free_mb)
        except OSError as err:
            raise RuntimeError(f"Storage pre-flight error: {err}") from err

        # Step 1: Scan and SHA-256 integrity calculation
        logging.info("Scanning targets and calculating SHA-256 checksums...")
        scanner = IntegrityScanner(exclude_patterns=exclude_patterns)
        files_to_backup, manifest, warnings = scanner.scan_targets(targets)
        files_count = len(files_to_backup)

        if files_count == 0:
            warn_msg = "No valid files found in configured target paths."
            logging.warning(warn_msg)
            warnings.append(warn_msg)
            status = "WARNING"

        # Step 2: Create archive
        archive_path = ArchiveEngine.create_archive(
            destination_dir=destination_dir,
            prefix=prefix,
            compression=compression,
            files=files_to_backup,
            manifest=manifest,
            dry_run=args.dry_run,
        )

        # Step 3: Retention policy rotation
        removed = RetentionManager.enforce_policy(
            destination_dir=destination_dir,
            prefix=prefix,
            retention_days=retention_cfg.get("retention_days", 0),
            max_backups=retention_cfg.get("max_backups", 0),
            dry_run=args.dry_run,
        )
        if removed:
            logging.info("Retention policy purged %d old archives", len(removed))

        if warnings and status != "WARNING":
            status = "WARNING"

    except Exception as err:
        status = "FAILED"
        error_msg = str(err)
        logging.error("Backup execution failed: %s", err, exc_info=True)
    finally:
        duration = time.time() - start_time
        archive_name = archive_path.name if archive_path else "N/A"
        archive_size_mb = 0.0
        if archive_path and archive_path.exists():
            archive_size_mb = archive_path.stat().st_size / (1024 * 1024)

        logging.info(
            "Execution completed in %.2fs. Status: %s. Archive: %s (%.2f MB)",
            duration,
            status,
            archive_name,
            archive_size_mb,
        )

        # Send Telegram alert
        if alerter.is_configured:
            alerter.send_alert(
                status=status,
                archive_name=archive_name,
                archive_size_mb=archive_size_mb,
                duration_sec=duration,
                files_count=files_count,
                warnings=warnings,
                error_msg=error_msg,
            )

    return 0 if status in ("SUCCESS", "WARNING") else 1


if __name__ == "__main__":
    sys.exit(main())
