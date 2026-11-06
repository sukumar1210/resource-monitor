#!/bin/bash
# Installs hmon on a systemd-based Linux host: a per-minute record of host, container and process usage
# that survives reboots, plus a persistent kernel log and Docker exit events for explaining crashes.
#
#   curl -fsSL https://github.com/OWNER/resource-monitor/releases/latest/download/install.sh | sudo bash
#   sudo ./install.sh                       the same from a clone; installs the hmon.py next to it
#   sudo RETENTION_DAYS=30 ./install.sh     keep a different number of days (default 14)
#   sudo ./install.sh uninstall             remove hmon; recorded data in /var/lib/hmon is left in place

set -euo pipefail

# Set by the release workflow, so a released install.sh fetches the hmon.py of the same release
REPO=${HMON_REPO:-sukumar1210/resource-monitor}
VERSION=dev

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
[ -d /run/systemd/system ] || { echo "This installer needs systemd; elsewhere, run 'hmon.py collect' from your init system"; exit 1; }

if [ "${1:-}" = uninstall ]; then
    for unit in hmon hmon-events; do
        systemctl disable --now "$unit" 2>/dev/null || true
    done
    rm -f /etc/systemd/system/hmon.service /etc/systemd/system/hmon-events.service /usr/local/bin/hmon \
          /etc/tmpfiles.d/hmon.conf /etc/systemd/journald.conf.d/hmon.conf
    systemctl daemon-reload
    echo "hmon removed; delete /var/lib/hmon to drop the recorded data"
    exit 0
fi

python3 -c 'import sys; sys.exit(sys.version_info < (3, 7))' 2>/dev/null || { echo "hmon needs Python 3.7+ as python3"; exit 1; }
# An update keeps the retention of the earlier install unless RETENTION_DAYS is given
previous_days=$(sed -n 's|^d /var/lib/hmon .* \([0-9][0-9]*\)d$|\1|p' /etc/tmpfiles.d/hmon.conf 2>/dev/null || true)
RETENTION_DAYS=${RETENTION_DAYS:-${previous_days:-14}}
previous_version=$(hmon --version 2>/dev/null || true)

# Persistent journal, so kernel OOM reports and container events survive a reboot
mkdir -p /etc/systemd/journald.conf.d /var/log/journal
printf '[Journal]\nSyncIntervalSec=30s\n' > /etc/systemd/journald.conf.d/hmon.conf
systemd-tmpfiles --create --prefix /var/log/journal
journalctl --flush

# The collector; systemd-tmpfiles creates the root-only data directory and deletes files older than RETENTION_DAYS
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/hmon.py" ]; then
    install -m 755 "$(dirname "${BASH_SOURCE[0]}")/hmon.py" /usr/local/bin/hmon
else  # piped from curl
    if [ "$VERSION" = dev ]; then
        url="https://github.com/$REPO/releases/latest/download/hmon.py"
    else
        url="https://github.com/$REPO/releases/download/$VERSION/hmon.py"
    fi
    download=$(mktemp)
    curl -fsSL "$url" -o "$download"
    install -m 755 "$download" /usr/local/bin/hmon
    rm -f "$download"
fi
echo "d /var/lib/hmon 0700 root root ${RETENTION_DAYS}d" > /etc/tmpfiles.d/hmon.conf
systemd-tmpfiles --create /etc/tmpfiles.d/hmon.conf
cat > /etc/systemd/system/hmon.service <<'EOF'
[Unit]
Description=hmon: per-minute host, container and process usage in /var/lib/hmon
After=docker.service

[Service]
ExecStart=/usr/local/bin/hmon collect
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
units=(hmon)

# Container exits with exit code / signal; docker inspect loses these once a restart policy kicks in
if command -v docker >/dev/null; then
    cat > /etc/systemd/system/hmon-events.service <<EOF
[Unit]
Description=hmon: log Docker container die/oom/kill events to the journal
After=docker.service

[Service]
ExecStart=$(command -v docker) events --filter type=container --filter event=die --filter event=oom --filter event=kill --format "{{.Actor.Attributes.name}} {{.Action}}{{with .Actor.Attributes.exitCode}} exitCode={{.}}{{end}}{{with .Actor.Attributes.signal}} signal={{.}}{{end}}"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    units+=(hmon-events)
fi

systemctl daemon-reload
systemctl enable "${units[@]}"
systemctl restart "${units[@]}"
for unit in "${units[@]}"; do
    echo "$unit: $(systemctl is-active "$unit" || true)"
done
version=$(hmon --version)
if [ -n "$previous_version" ] && [ "$previous_version" != "$version" ]; then
    echo "Updated $previous_version -> $version"
fi
echo "$version is recording to /var/lib/hmon (root only), kept ${RETENTION_DAYS} days. Open the viewer with: sudo hmon"
