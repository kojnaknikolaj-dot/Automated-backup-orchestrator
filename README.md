# Automated System Snapshot & Backup Orchestrator

Production-grade automation tool for backing up critical Linux server configurations, system directories, and scripts with SHA-256 integrity verification, compression, retention policies, and Telegram alerts.

---

## 🚀 Features

- **Integrity Manifest (SHA-256):** Streaming checksum calculation for every file before archiving, embedded as `manifest.json` inside the archive.
- **Atomic Archival:** Compressed tar archives (`tar.gz` or `tar.bz2`) generated via a temporary `.tmp` file and atomically renamed.
- **Strict Security Permissions:** Automatic enforcement of `0600` permissions on created archives and `0640` on log files.
- **Retention Policy:** Automated cleanup of old backups by age threshold (`retention_days`) and total count limit (`max_backups`).
- **Telegram Alerting:** Detailed status notifications (`SUCCESS`, `WARNING`, `FAILED`), execution time, archive size, and warning lists.
- **Secret Safety:** Dynamic environment variable interpolation in `config.yaml` (`${TELEGRAM_BOT_TOKEN}`, `${TELEGRAM_CHAT_ID}`).
- **systemd Integration:** Production-ready `.service` and `.timer` unit templates for automated background execution.

---

## 📁 Project Structure

```text
sysadmin-backup-orchestrator/
├── config.yaml            # Main configuration file
├── backup_orchestrator.py # Executable Python orchestrator script (Python 3.10+)
├── test_orchestrator.py   # Built-in unit and integration test suite
├── requirements.txt       # Dependencies: PyYAML, requests
└── README.md              # Documentation and deployment guide
```

---

## 🛠️ Installation & Setup

### 1. Clone & Virtual Environment

```bash
cd /opt/sysadmin-backup-orchestrator  # or your workspace directory
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configuration (`config.yaml`)

Edit `config.yaml`:
- Specify target files and directories in `backup.targets`.
- Set destination path in `backup.destination_dir` (default: `/var/backups/sysadmin-orchestrator`).
- Adjust retention limits (`retention_days`, `max_backups`).
- Enable Telegram alerts if required: `telegram.enabled: true`.

> **Security Tip:** Pass tokens via environment variables:
> ```bash
> export TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrs"
> export TELEGRAM_CHAT_ID="987654321"
> ```

---

## 💻 Manual Execution & CLI

The script supports command-line flags:

```bash
# Dry-run simulation (no files created or deleted):
python3 backup_orchestrator.py --config config.yaml --dry-run

# Standard execution:
python3 backup_orchestrator.py --config config.yaml

# Force execution when disk space check is below threshold:
python3 backup_orchestrator.py --config config.yaml --force

# Run test suite:
python3 -m unittest -v test_orchestrator.py
```

---

## ⚙️ systemd Deployment

For scheduled runs on Linux systems (Ubuntu, Debian, Fedora, RHEL), configure `systemd.timer`.

### 1. Service: `/etc/systemd/system/backup-orchestrator.service`

```ini
[Unit]
Description=Automated System Snapshot & Backup Orchestrator
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/sysadmin-backup-orchestrator
Environment="PYTHONUNBUFFERED=1"
EnvironmentFile=-/etc/default/backup-orchestrator
ExecStart=/opt/sysadmin-backup-orchestrator/venv/bin/python3 /opt/sysadmin-backup-orchestrator/backup_orchestrator.py --config /opt/sysadmin-backup-orchestrator/config.yaml
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 2. Timer: `/etc/systemd/system/backup-orchestrator.timer`

Executes nightly at 03:00 with up to 10 minutes randomized delay:

```ini
[Unit]
Description=Nightly execution of Backup Orchestrator

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
```

### 3. Enable Timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now backup-orchestrator.timer

# Check timer status:
sudo systemctl list-timers backup-orchestrator.timer

# Manually trigger service for verification:
sudo systemctl start backup-orchestrator.service

# View execution logs:
sudo journalctl -u backup-orchestrator.service -f
```

---

## 🔍 Restoration & Manifest Verification

To inspect archive integrity:

```bash
# Extract archive to a temporary directory
mkdir /tmp/restore-test && cd /tmp/restore-test
tar -xzf /var/backups/sysadmin-orchestrator/sys_snapshot-YYYYMMDD_HHMMSS.tar.gz

# View manifest
cat manifest.json | jq .

# Verify specific file hash (e.g. hosts)
sha256sum etc/hosts
```
