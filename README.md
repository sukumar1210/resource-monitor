# resource-monitor (`hmon`)

`hmon` records what a Linux host, every Docker container and every process were using, once a minute, and keeps
it across reboots. When something crashes, open `hmon`, go back to just before it happened, and see what was
eating memory or CPU.

```
 hmon   [Memory]   CPU    1 min/column   times in UTC
100%│                                                                                                          ▃▇▇▇▇▇▇▇
    │                                                                                                        ▄▇████████
    │                                                                                                     ▁▅███████████
    │                                                                                              ▁▄██████████████████
    │██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
 50%│██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
    │██████████████████████████████████████████████████████████████████████████████████████████████████████████████████
  0%└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────▲
              01:30     01:40     01:50     02:00     02:10     02:20     02:30     02:40     02:50     03:00     03:10
 2026-11-06 03:14 UTC   memory used 99.2% of 7.63 GiB   cpu 76.2%   load 6.8   swap used 0.00 GiB

    PID    CPU%        MEM   MEM%  COMMAND   (average over the column, by MEM)
         100.1%   4.80 GiB  62.9%  ▾ web  (container, 12 pids)
   8123   98.0%   4.48 GiB  58.8%    ├─ python /opt/app/jobs/nightly_report.py
   2402    1.2%   0.15 GiB   1.9%    ├─ gunicorn app.wsgi -w 2 -b 0.0.0.0:8000
   2403    0.9%   0.14 GiB   1.9%    └─ gunicorn app.wsgi -w 2 -b 0.0.0.0:8000
           9.5%   2.23 GiB  29.2%  ▾ db  (container, 4 pids)
   2210    9.5%   2.20 GiB  28.8%    └─ mongod --bind_ip_all --wiredTigerCacheSizeGB 2
   1102    0.6%   0.09 GiB   1.2%  /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
     71   37.2%   0.00 GiB      -  [kswapd0]
 left/right time  g go to  up/down scroll  PgUp/PgDn  Home/End  +/- zoom  Tab mem/cpu  c fold  q quit
```

(An excerpt of the real screen on demo data: a job inside the `web` container grows until the host runs out of
memory at 03:14, and the kernel's swapper `kswapd0` is busy trying to free memory.)

## What it records

- **Host**: CPU %, 1-minute load, memory total / available, swap used.
- **Docker containers** (if Docker is installed): `docker stats` CPU, memory, memory limit, network, block I/O, pids.
- **Processes**: every process using memory or CPU, inside or outside containers, with its container, memory (RSS),
  CPU % over the last minute and command line.
- **Crash evidence**: the systemd journal is made persistent, so the kernel's OOM-killer reports survive a reboot,
  and Docker container exits (exit code, OOM, kill signal) are logged to it by the `hmon-events` service.

Samples are plain CSV in `/var/lib/hmon` (`host_`, `containers_`, `processes_` + UTC date), written and fsynced every
minute so the last rows before a crash survive it, and deleted after 14 days. Roughly 25 MB a day for 150 processes.

**Privacy.** Command lines can contain credentials, so the data directory is readable by root only, and values that
look like credentials (`user:password@` in URLs, `password=…`, `token=…`, `--password …`, `--api-key …`) are
replaced with `***` before they are written. The masking is pattern-based and misses forms such as `mysql -pSECRET`,
so treat the files as sensitive when you copy them off the host.

## Install

Needs Linux with systemd and Python 3.7+ (standard library only). Docker is optional.

```
curl -fsSL https://github.com/sukumar1210/resource-monitor/releases/latest/download/install.sh | sudo bash
```

This installs the latest release. Other forms:

- A specific release: `.../releases/download/v0.1.0/install.sh` in place of `.../releases/latest/download/install.sh`.
- Keep a different number of days (default 14): `... | sudo RETENTION_DAYS=30 bash`
- Update: run the same command again. It installs the latest release, restarts the service, keeps the recorded data
  and the retention you chose, and prints the old and new version. Updates are never automatic.
- Remove: `... | sudo bash -s -- uninstall` (the data in `/var/lib/hmon` is left for you to delete).
- From a clone: `sudo ./install.sh` installs the `hmon.py` next to it.
- Without systemd: run `python3 hmon.py collect` from your init system; set `HMON_DATA_DIR` to write elsewhere.

`hmon --version` shows which release is installed.

## Use

`sudo hmon` opens the viewer on the newest sample.

| Key | Action |
| --- | --- |
| Left / Right | move the marker one column back / forward in time |
| g | go to a time: `2026-11-06 08:44`, or `08:44` on the marker's date |
| PgUp / PgDn | move a screen width |
| Home / End | oldest / newest sample |
| + / - | zoom: 1, 5, 15 or 60 minutes per column (values are averages over the column) |
| Tab | switch the graph and the table's sort between memory and CPU |
| Up / Down | scroll the process table |
| c | fold / unfold containers to one row each |
| q | quit |

The table shows averages for the column under the marker: processes outside containers on their own rows, and each
container as a group (its `docker stats` totals) with its processes under it. CPU % is per core, like `top`.

`sudo hmon at "2026-11-06 08:44"` prints the nearest snapshot as text with 30-minute trend lines, for piping or
pasting.

**Time zone.** Times are shown and read in the host's time zone (see `timedatectl`). Pick another with `--tz`:
`sudo hmon --tz Asia/Kolkata`, `sudo hmon --tz UTC at "2026-11-06 03:14"`, or the standard `TZ` variable. A time typed
with an offset, like `2026-11-06T08:44+05:30`, is read as written. The CSV files are always UTC.

To browse elsewhere, copy the data off the host and point `hmon.py` at it:

```
sudo tar czf hmon-data.tgz -C /var/lib/hmon .
mkdir hmon-data && tar xzf hmon-data.tgz -C hmon-data && python3 hmon.py --tz Asia/Kolkata hmon-data
```

## After an incident

1. Did the host reboot? `last -x reboot shutdown | head`. A line ending in `crash` means it went down without a
   clean shutdown. `sudo journalctl --list-boots` shows when each boot's log ends.
2. Which container died, and how? `sudo journalctl -u hmon-events --since "2026-11-06 08:15"`.
   Exit code 137 = killed (usually out of memory), 143 = stopped, 139 = segfault.
3. What did the kernel kill for memory?
   `sudo journalctl _TRANSPORT=kernel --since "2026-11-06 08:15" | grep -iE 'oom|out of memory'`.
4. What grew? `sudo hmon`, press `g` and enter a time just before it. When memory runs out the kernel kills the
   biggest process, which is not necessarily the one that grew, so look at what climbed in the minutes before.

## Data

| File | Columns |
| --- | --- |
| `host_YYYY-MM-DD.csv` | ts, cpu_percent, load_1m, mem_total_bytes, mem_available_bytes, swap_used_bytes |
| `containers_YYYY-MM-DD.csv` | ts, container, cpu_percent, mem_bytes, mem_limit_bytes, net_rx_bytes, net_tx_bytes, block_read_bytes, block_write_bytes, pids |
| `processes_YYYY-MM-DD.csv` | ts, pid, container, name, rss_bytes, cpu_percent, cmdline |

All three share the same `ts` (UTC) per sample. They load directly into DuckDB, pandas or a spreadsheet, e.g. to
Parquet: `duckdb -c "COPY (FROM read_csv('processes_*.csv')) TO 'processes.parquet'"`. Filter times with an explicit
offset (`'2026-11-06 02:45:00+00'`) so DuckDB doesn't read them in your local time zone.

## Tests and releases

`python3 -m unittest` runs the tests (Linux or macOS; no dependencies). GitHub Actions runs them on Python 3.7 and a
current Python for every push and pull request.

To release, push a version tag: `git tag v0.1.0 && git push origin v0.1.0`. The workflow tests, then publishes a GitHub
release with `install.sh` and `hmon.py` stamped with the repository and version, which is what the install command
downloads.
