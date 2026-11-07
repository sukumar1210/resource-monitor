#!/bin/bash
# Installs hmon on a systemd-based Linux host: a record of host, app, container and process usage that survives
# reboots, plus a persistent kernel log and Docker exit events for explaining crashes. A new install asks how often
# to sample and how many days to keep, showing the disk that takes; an update keeps the earlier answers, and
# INTERVAL and RETENTION_DAYS answer without asking.
#
#   curl -fsSL https://github.com/sukumar1210/resource-monitor/releases/latest/download/install.sh | sudo bash
#   sudo ./install.sh                                   the same from a clone; installs the hmon.py next to it
#   sudo INTERVAL=10 RETENTION_DAYS=3 ./install.sh      no questions: a sample every 10 s, kept 3 days
#   sudo ./install.sh uninstall                         remove hmon; recorded data in /var/lib/hmon is left in place

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
previous_version=$(/usr/local/bin/hmon --version 2>/dev/null || true)  # by path: sudo may leave /usr/local/bin off PATH

ask() {  # ask QUESTION DEFAULT: the answer typed at the terminal (even when this script comes through a pipe)
    local answer=''
    if { : < /dev/tty; } 2>/dev/null; then
        read -r -p "$1 [$2]: " answer < /dev/tty || true
    fi
    echo "${answer:-$2}"
}

mb_per_day() {  # mb_per_day SECONDS: ~150 bytes per process per sample
    echo $(( 86400 / $1 * processes * 150 / 1000000 ))
}

step() {  # step MESSAGE: what the installer is doing now, so a slow step shows where it is
    echo "==> $*"
}

# How often to sample and how long to keep it. An update keeps the earlier answers; only a new install asks.
previous_interval=$(sed -n 's|^Environment=HMON_INTERVAL=\([0-9][0-9]*\)$|\1|p' /etc/systemd/system/hmon.service 2>/dev/null || true)
previous_days=$(sed -n 's|^d /var/lib/hmon .* \([0-9][0-9]*\)d$|\1|p' /etc/tmpfiles.d/hmon.conf 2>/dev/null || true)
if [ -n "$previous_interval" ] && [ -n "$previous_days" ]; then
    INTERVAL=${INTERVAL:-$previous_interval}
    RETENTION_DAYS=${RETENTION_DAYS:-$previous_days}
fi
processes=$(awk '$2 > 0' /proc/[0-9]*/statm 2>/dev/null | wc -l)
if [ -z "${INTERVAL:-}" ] || [ -z "${RETENTION_DAYS:-}" ]; then
    echo "hmon records every process. This host runs about $processes, so one day of samples takes about:"
    for seconds in 10 30 60 300; do
        printf '  a sample every %4s s   %6s MB\n' "$seconds" "$(mb_per_day "$seconds")"
    done
    echo "The viewer can still zoom out to 15 min, 1 hour or 1 day; finer than the samples just shows gaps."
fi
INTERVAL=${INTERVAL:-$(ask "Seconds between samples" "${previous_interval:-60}")}
RETENTION_DAYS=${RETENTION_DAYS:-$(ask "Days to keep" "${previous_days:-14}")}
for answer in "$INTERVAL" "$RETENTION_DAYS"; do
    case $answer in
        ''|*[!0-9]*|0) echo "Expected a whole number above 0, got '$answer'"; exit 1 ;;
    esac
done
echo "Recording every ${INTERVAL} s and keeping ${RETENTION_DAYS} days: about $(( $(mb_per_day "$INTERVAL") * RETENTION_DAYS )) MB on disk."
echo "Change it any time in hmon's F2 Setup, or with: hmon configure --interval SECONDS --retention DAYS"

# Persistent journal, so kernel OOM reports and container events survive a reboot. Where journald keeps its log in
# memory on purpose (Storage=volatile, as log2ram setups do), it never confirms a flush, so don't wait for one.
step "Making the journal persistent"
mkdir -p /etc/systemd/journald.conf.d /var/log/journal
printf '[Journal]\nSyncIntervalSec=30s\n' > /etc/systemd/journald.conf.d/hmon.conf
journal_storage=$({ systemd-analyze cat-config systemd/journald.conf 2>/dev/null || true; } \
    | sed -n 's/^[[:space:]]*Storage[[:space:]]*=[[:space:]]*\([a-z]*\).*/\1/p' | tail -n 1)
if [ "$journal_storage" = volatile ] || [ "$journal_storage" = none ]; then
    echo "    journald is set to Storage=$journal_storage, so the kernel log won't survive a reboot; hmon's samples will."
else
    timeout 60 systemd-tmpfiles --create --prefix /var/log/journal || echo "    systemd-tmpfiles took too long; skipped"
    timeout 15 journalctl --flush || echo "    journald didn't confirm moving its log to disk; it will after the next reboot"
fi

# The collector; systemd-tmpfiles creates the data directory and deletes files older than RETENTION_DAYS
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/hmon.py" ]; then
    step "Installing hmon.py from $(dirname "${BASH_SOURCE[0]}")"
    install -m 755 "$(dirname "${BASH_SOURCE[0]}")/hmon.py" /usr/local/bin/hmon
else  # piped from curl
    if [ "$VERSION" = dev ]; then
        url="https://github.com/$REPO/releases/latest/download/hmon.py"
    else
        url="https://github.com/$REPO/releases/download/$VERSION/hmon.py"
    fi
    step "Downloading $url"
    download=$(mktemp)
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 "$url" -o "$download"
    install -m 755 "$download" /usr/local/bin/hmon
    rm -f "$download"
fi
step "Setting up /var/lib/hmon and the services"
# Like htop: everyone sees what /proc shows them. Where /proc hides other users' processes (hidepid), so does hmon.
if awk '$2 == "/proc" && $4 ~ /hidepid=(1|2|noaccess|invisible)/ { found = 1 } END { exit !found }' /proc/mounts; then
    data_mode=0700
else
    data_mode=0755
fi
echo "d /var/lib/hmon $data_mode root root ${RETENTION_DAYS}d" > /etc/tmpfiles.d/hmon.conf
systemd-tmpfiles --create /etc/tmpfiles.d/hmon.conf
if [ "$data_mode" = 0755 ]; then
    chmod -R go+rX /var/lib/hmon  # files from v0.1.0 were root-only
fi
cat > /etc/systemd/system/hmon.service <<EOF
[Unit]
Description=hmon: host, app, container and process usage in /var/lib/hmon
After=docker.service

[Service]
Environment=HMON_INTERVAL=${INTERVAL}
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

step "Starting ${units[*]}"
systemctl daemon-reload
systemctl enable --quiet "${units[@]}"
timeout 90 systemctl restart "${units[@]}" || echo "    the restart is taking long; see: systemctl status ${units[*]}"
for unit in "${units[@]}"; do
    echo "$unit: $(systemctl is-active "$unit" || true)"
done
version=$(/usr/local/bin/hmon --version)
if [ -n "$previous_version" ] && [ "$previous_version" != "$version" ]; then
    echo "Updated $previous_version -> $version"
fi
echo "$version is recording to /var/lib/hmon, kept ${RETENTION_DAYS} days."
if [ "$data_mode" = 0755 ]; then
    echo "Open the viewer with: hmon"
else
    echo "This host hides other users' processes (hidepid), so like htop, hmon needs root to show them: sudo /usr/local/bin/hmon"
fi
