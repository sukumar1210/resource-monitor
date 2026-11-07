# resource-monitor (`hmon`)

`hmon` is htop for the past. A small service records what every app, Docker container and process on a Linux host
uses, and keeps it across reboots. When something crashes, open `hmon`, go back to just before it happened, and see
what was eating memory or CPU. The newest column is live: at 10 s and 1 min bars, like htop, it shows what runs
now; longer bars keep their statistic, so today's peak stays in the table.

```
 CPU[|||||||||||||                          20.5%]    Tasks: 27 processes in 13 apps, 2 containers
 Mem[||||||||||||||||||||||||||       5.58G/11.6G]    Load average: 0.82 0.76 0.68
 Swp[||||||||||                        300M/2.00G]    Time: 2026-11-06 17:30 IST

  Memory   CPU   Load   Swap     Average per 1 min, times in IST
 100%│                                                                           │
  50%│▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂
     │█████████████████████████████████████████████████████████████████████████████
   0%└───────────────────────────────────────────────────────────────────────────▲
       16:20     16:30     16:40     16:50     17:00     17:10     17:20     17:30

    PID    RES   CPU%  MEM%▽ App / Process
         1820M    6.2  15.3  + claude    8 processes
          923M    4.0   7.8  ─ docker    7 processes, 2 containers
          610M    3.5   5.1  ├+ openalgo    2 processes
   1092   200M    0.1   1.7  ├─ /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
 942434  10240    0.0   0.1  │  └─ /usr/bin/docker-proxy -proto tcp -host-port 5000 -container-port 5000
         53248    0.3   0.4  ├+ redis    1 process
    931  40960    0.1   0.3  ├─ /usr/bin/containerd
 942377  11264    0.0   0.1  └─ /usr/bin/containerd-shim-runc-v2 -namespace moby -id 7526c2cf3b57
          330M    0.0   2.8  + market-recorder    1 process
          180M    0.0   1.5  + actions.runner.homelab    2 processes
F1 Help  F2 Setup  F3 Search  F4 Filter  F5 List  F6 SortBy  F10 Quit  ← / → Time  [ / ] Zoom  s Stat  g GoTo  Tab Graph
```

(A real screen on demo data, trimmed to fit: `docker` unfolded, its containers folded. Memory figures are htop's:
`10240` is KiB, `1820M` is MiB.)

## What it records

- **Host**: CPU %, load average, memory and swap.
- **Docker containers** (if Docker is installed): `docker stats` CPU, memory, limit, network, block I/O, pids.
- **Every process** using memory or CPU, with its parent, container and systemd unit, memory (RSS), CPU % and
  command line.
- **Crash evidence**: the journal is made persistent, so the kernel's OOM-killer reports survive a reboot, and Docker
  container exits (exit code, OOM, kill signal) are logged to it by the `hmon-events` service.

Samples are plain CSV in `/var/lib/hmon`, one file per kind per UTC day, fsynced on every write so the last samples
before a crash survive it, and deleted after the retention you choose.

## Install

Linux with systemd and Python 3.7+ (standard library only). Docker is optional.

```
curl -fsSL https://github.com/sukumar1210/resource-monitor/releases/latest/download/install.sh | sudo bash
```

On a new install it shows how much disk a day of samples takes on this host at 10 s, 30 s, 1 min and 5 min, then asks
how often to sample and how many days to keep. Finer samples cost more disk; the viewer can always zoom out. Each step
is printed as it runs (`==> ...`).

- No questions: `... | sudo INTERVAL=60 RETENTION_DAYS=14 bash`
- A specific release: `.../releases/download/v0.2.2/install.sh` in place of `.../releases/latest/download/install.sh`.
- Update: `hmon update` (it asks for sudo) runs the newest release's installer, which keeps your answers and the data
  without asking; change the answers in F2 Setup or with `hmon configure --interval SECONDS --retention DAYS`.
  When a newer release is out, the viewer says so at the bottom right.
- If journald keeps its log in memory (`Storage=volatile`, as with log2ram), the installer says so and moves on: the
  kernel's OOM reports then won't survive a reboot, though hmon's own samples do.
- Remove: `hmon uninstall` (it asks for sudo, then separately whether the recorded samples in `/var/lib/hmon` and
  the settings go too; each stays unless you say yes). Without hmon: `... | sudo bash -s -- uninstall`.
- From a clone: `sudo ./install.sh`. Without systemd: run `python3 hmon.py collect` from your init system
  (`HMON_DATA_DIR` and `HMON_INTERVAL` set where and how often).

## Use

`hmon` opens the viewer, like htop: no sudo needed. Hosts that hide other users' processes (`/proc` mounted with
`hidepid`) keep the data root-only, as htop needs root there too: `sudo /usr/local/bin/hmon` (by path, since sudo
leaves `/usr/local/bin` off its PATH on some systems, such as Amazon Linux).

- **Meters** (CPU, Mem, Swp, tasks, load, time) and the **table** show the column under the marker.
- **The graph** plots memory, CPU, load or swap over time, one column per 10 s, 1 min, 5 min, 15 min, 30 min,
  1 hour or 1 day, reduced with a CloudWatch-style statistic: Average, Maximum, Minimum, p50, p90 or p99.
  Apps and containers are totalled per sample before the statistic, so a Maximum is a real peak.
- **The table groups processes into apps**, folded until you open them: containers sit under `docker`, system
  services take their systemd unit's name, and anything else is named after the program at the top of its process
  tree (so every `claude` process is one app). Inside an app, processes nest under their parents as in htop's tree.

| Keys | |
| --- | --- |
| Left / Right, Shift+Left / Right | move the marker a column / a screen width |
| `^` `$` | oldest sample / newest (live) |
| `g` | go to a time: `12/10/2026 14:30 IST`, `2 Feb 2025 UTC`, `Oct 12 2026 2:30 pm`, `14:30` (dates are day first); Esc or a click cancels |
| `[` `]` | coarser / finer columns |
| `s` | statistic |
| Tab, Shift+Tab | graph memory, CPU, load or swap (Shift+Tab goes back) |
| Space, Esc | a range of bars from the marker, stretched with Left / Right: the table shows each bar as a column (RES, or CPU% on the CPU graph; `-` where a process wasn't running); Esc goes back to one bar |
| Up / Down, PgUp / PgDn, Home / End | select a row |
| `+` / `-`, Enter, `*` | unfold / fold the selected app or container, toggle it, toggle everything |
| F3 `/`, F4 `\` | search, filter (case-insensitive; `\|` separates terms) |
| F5 `t` | tree or list view |
| F6 `<` `>`, `M` `P` `N`, `I` | sort column, sort by MEM% / CPU% / PID, reverse |
| F2 | setup: time zone, statistic, granularity, graph, refresh delay, view, and the recording |
| F1 `h` `?`, F10 `q`, Ctrl+C | help, quit |

The mouse acts when the button is released: click a row, a fold marker, a column title (again to reverse), a graph
tab, a point on the graph, or a function-bar item; the wheel scrolls the table, or moves through time over the graph.
Drag across the graph to pick a range of bars for the table, as Space does.

**Copying text.** A terminal hands every click and drag to a program that uses the mouse, so it can't select text
itself. hmon does the selecting instead: hold the button and drag, and what you drag over is highlighted and copied
when you let go. It reaches the clipboard through the terminal (OSC 52), which iTerm2 (Settings › General › Selection ›
Applications in terminal may access clipboard), kitty, WezTerm, Alacritty, Windows Terminal and tmux (`set -g
set-clipboard on`) accept, and macOS Terminal doesn't. Where that doesn't work, use the terminal's own selection: turn
the mouse off in F2 Setup (saved) or for one run with `-M`, or hold **Shift** as you drag (Option in iTerm2; Fn in
macOS Terminal).

**Setup (F2).** Enter or a click opens a setting's dropdown, where typing filters by anything a row shows: `kolk`,
`ist` or `+05:30` all find `Asia/Kolkata` among the system's time zones, each shown with its UTC offset and
abbreviation. Left/Right steps through the choices.
Settings are saved to `~/.config/hmon/hmonrc`; `--tz` or `TZ` override the time zone for one run.

The **Recording** section holds what the installer asked: how often to sample and how many days to keep, with the
disk each choice takes on this host. Changing them rewrites the hmon service and restarts it, so as root it applies
when you leave Setup; otherwise Setup shows the command, which also works on its own and asks for sudo:
`hmon configure --interval 10 --retention 3` (`hmon configure` alone prints the current values).

Options, as in htop: `-C` monochrome (also `NO_COLOR`), `-U` ASCII only, `-F FILTER`, `-s COLUMN`, `-d DELAY`
(tenths of a second for the live refresh), `-M` no mouse, `-V` version.

**Memory.** Like htop, which holds only the current process list, the viewer holds only what is on screen: it keeps
a small index of where each sample starts in a day's file and reads just the samples of the column under the marker,
one at a time. A long column (a day, or an hour of 10 s samples) reads at most 240 samples, evenly spread, for the
table, and the title says so; the graph uses every sample. A day of 10 s samples for 100 processes (98 MB) is browsed
in about 10 MB, where loading the file would take about 120 MB. `export` and `sql` stream through temporary files.

## Dumps and queries

Take a dump of an instance and analyse it anywhere:

```
hmon export --from "12/10/2026 13:00 IST" --to "12/10/2026 15:00 IST" -o incident.tar.gz
hmon incident.tar.gz
```

Or query it with SQL (SQLite is built into Python; tables `host`, `containers`, `processes`, where every process row
also has its `app`):

```
hmon sql "SELECT app, max(rss) / 1048576 AS peak_mib FROM processes GROUP BY app ORDER BY peak_mib DESC" incident.tar.gz
hmon export --sqlite incident.db --from "12/10/2026 13:00 IST"
```

`export` and `sql` cover the last 24 hours unless `--from` / `--to` say otherwise. `hmon at "12/10/2026 14:30 IST"`
prints one snapshot as text, for pasting.

## After an incident

1. Did the host reboot? `last -x reboot shutdown | head`. A line ending in `crash` means it went down without a
   clean shutdown.
2. Which container died, and how? `sudo journalctl -u hmon-events --since "2026-10-12 14:00"`.
   Exit code 137 = killed (usually out of memory), 143 = stopped, 139 = segfault.
3. What did the kernel kill for memory? `sudo journalctl -k -b -1 | grep -iE 'oom|out of memory'`.
4. What grew? `hmon`, `g`, a time just before it, `s` for Maximum. When memory runs out the kernel kills the
   biggest process, which is not necessarily the one that grew, so look at what climbed in the minutes before.

## Privacy

Like `/proc`, the recorded command lines are readable by the host's users. Values that look like credentials
(`user:password@` in URLs, `password=…`, `token=…`, `--password …`, `--api-key …`) are replaced with `***` before
they are written. The masking is pattern-based and misses forms such as `mysql -pSECRET`, so treat dumps as sensitive.

The viewer asks GitHub's API (`api.github.com`) once when it starts whether a newer release is out; nothing about the
host is sent. Without network access the check gives up quietly. The collector service never connects anywhere.

## Data

| File | Columns |
| --- | --- |
| `host_YYYY-MM-DD.csv` | ts, cpu_percent, load_1m, mem_total_bytes, mem_available_bytes, swap_used_bytes, load_5m, load_15m, swap_total_bytes |
| `containers_YYYY-MM-DD.csv` | ts, container, cpu_percent, mem_bytes, mem_limit_bytes, net_rx_bytes, net_tx_bytes, block_read_bytes, block_write_bytes, pids, id |
| `processes_YYYY-MM-DD.csv` | ts, pid, container, name, rss_bytes, cpu_percent, cmdline, ppid, cgroup |

All three share `ts` (UTC) per sample. New columns are only ever added at the end, so older files stay readable.

## Tests and releases

`python3 -m unittest` runs the end-to-end tests: a fake host is sampled, then the real viewer is driven with keys and
the mouse, and the data is exported and queried. GitHub Actions runs them on Python 3.7 and a current Python.

To release, push a version tag: `git tag v0.2.0 && git push origin v0.2.0`. The workflow tests, then publishes a
GitHub release with `install.sh` and `hmon.py` stamped with the repository and version.
