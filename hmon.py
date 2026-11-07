#!/usr/bin/env python3
"""hmon: htop for the past. Records host, app, container and process usage and lets you browse it.

Run `hmon --help` for options; inside the viewer, F1 shows the keys and F2 the settings.
"""
import argparse
import atexit
import base64
import calendar
import contextlib
import csv
import glob
import io
import json
import locale
import logging
import math
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from array import array
from bisect import bisect_left
from collections import defaultdict, namedtuple
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from itertools import groupby, islice

try:
    import curses
except ImportError:  # some minimal Python builds; only the viewer needs it
    curses = None

VERSION = 'dev'  # set from the git tag by the release workflow
REPO = 'sukumar1210/resource-monitor'  # where releases come from, set by the release workflow
DATA_DIR = os.environ.get('HMON_DATA_DIR', '/var/lib/hmon')
INTERVAL_SECONDS = int(os.environ.get('HMON_INTERVAL', '60'))  # the service's sampling interval, set by install.sh
SYSTEM_TZ = os.environ.get('TZ')
CONFIG_PATH = os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config'),
                           'hmon', 'hmonrc')
CLOCK_TICKS = os.sysconf('SC_CLK_TCK')
PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
SIZE_UNITS = {'B': 1, 'kB': 10**3, 'KB': 10**3, 'MB': 10**6, 'GB': 10**9, 'TB': 10**12,
              'KiB': 2**10, 'MiB': 2**20, 'GiB': 2**30, 'TiB': 2**40}
CONTAINER_ID = re.compile(r'[0-9a-f]{64}')
# Credentials masked in command lines before they're stored. Pattern-based, so it misses forms like mysql's -pSECRET.
SECRETS = [
    (re.compile(r'(\w+://[^:@/\s]+:)[^@\s]+@'), r'\1***@'),                                      # scheme://user:PASSWORD@host
    (re.compile(r'(?i)((?:pass|pwd|secret|token|key|auth)[\w-]*=)[^\s&]+'), r'\1***'),            # password=X, ?token=X
    (re.compile(r'(?i)(-[\w-]*(?:pass|pwd|secret|token|key|auth)[\w-]*\s+)[^\s-]\S*'), r'\1***'),  # --password X
]

# Columns are only ever added at the end, and readers take the columns they know by position, so files written
# before and after an update stay readable.
HOST_FIELDS = ['ts', 'cpu_percent', 'load_1m', 'mem_total_bytes', 'mem_available_bytes', 'swap_used_bytes',
               'load_5m', 'load_15m', 'swap_total_bytes']
CONTAINER_FIELDS = ['ts', 'container', 'cpu_percent', 'mem_bytes', 'mem_limit_bytes', 'net_rx_bytes',
                    'net_tx_bytes', 'block_read_bytes', 'block_write_bytes', 'pids', 'id']
PROCESS_FIELDS = ['ts', 'pid', 'container', 'name', 'rss_bytes', 'cpu_percent', 'cmdline', 'ppid', 'cgroup']

Process = namedtuple('Process', 'name rss_bytes cpu_ticks ppid')


# ---------------------------------------------------------------- collecting

def to_bytes(size):
    """'1.5GiB' / '3.4kB' / '0B' -> bytes; '--' (container restarting) -> None."""
    match = re.fullmatch(r'([\d.]+)\s*([a-zA-Z]+)', size.strip())
    if not match or match.group(2) not in SIZE_UNITS:
        return None
    return round(float(match.group(1)) * SIZE_UNITS[match.group(2)])


def read_text(path):
    """File contents, or '' if the process exited before we got to it."""
    try:
        with open(path, 'rb') as f:
            return f.read().decode(errors='replace')
    except OSError:
        return ''


def cgroup_path(text):
    """The unified (v2) or systemd (v1) path from /proc/PID/cgroup, e.g. /system.slice/docker.service."""
    for line in text.splitlines():
        hierarchy, _, rest = line.partition(':')
        controllers, _, path = rest.partition(':')
        if (hierarchy == '0' and not controllers) or controllers == 'name=systemd':
            return path
    return ''


def sample_host(ts, prev_cpu_ticks):
    with open('/proc/stat') as f:
        ticks = [int(v) for v in f.readline().split()[1:9]]
    cpu_ticks = (sum(ticks), ticks[3] + ticks[4])  # (total, idle + iowait)
    cpu_percent = None
    if prev_cpu_ticks and cpu_ticks[0] > prev_cpu_ticks[0]:
        total = cpu_ticks[0] - prev_cpu_ticks[0]
        idle = cpu_ticks[1] - prev_cpu_ticks[1]
        cpu_percent = round(100 * (1 - idle / total), 1)
    with open('/proc/meminfo') as f:
        mem = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in f}
    with open('/proc/loadavg') as f:
        load_1m, load_5m, load_15m = (float(v) for v in f.read().split()[:3])
    row = [ts, cpu_percent, load_1m, mem['MemTotal'], mem['MemAvailable'], mem['SwapTotal'] - mem['SwapFree'],
           load_5m, load_15m, mem['SwapTotal']]
    return row, cpu_ticks


def sample_containers(ts):
    """docker stats rows, plus a full container id -> name map used to tag processes."""
    out = subprocess.run(
        ['docker', 'stats', '--no-stream', '--no-trunc', '--format',
         '{{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}'],
        stdout=subprocess.PIPE, universal_newlines=True, timeout=30, check=True).stdout
    rows, names = [], {}
    for line in out.splitlines():
        container_id, name, cpu, mem, net, block, pids = line.split('\t')
        mem_used, mem_limit = mem.split('/')
        net_rx, net_tx = net.split('/')
        block_read, block_write = block.split('/')
        names[container_id] = name
        rows.append([ts, name, None if cpu == '--' else float(cpu.rstrip('%')),
                     to_bytes(mem_used), to_bytes(mem_limit), to_bytes(net_rx), to_bytes(net_tx),
                     to_bytes(block_read), to_bytes(block_write), pids if pids.isdigit() else None, container_id])
    return rows, names


def sample_processes(ts, prev, container_names):
    """Every process using memory or CPU, biggest first, with its container ('' = not in one), parent and cgroup."""
    procs = {}  # keyed by (pid, start_time) so a reused pid doesn't inherit the old process's CPU
    for pid in filter(str.isdigit, os.listdir('/proc')):
        stat = read_text(f'/proc/{pid}/stat')
        if not stat:
            continue
        # "pid (name) state ...": the name can contain spaces or ')', so split after the last ')'
        name = stat[stat.index('(') + 1:stat.rindex(')')]
        fields = stat[stat.rindex(')') + 2:].split()
        ppid, utime, stime, start_time, rss_pages = fields[1], fields[11], fields[12], fields[19], fields[21]  # 4, 14, 15, 22, 24
        procs[(int(pid), start_time)] = Process(name, int(rss_pages) * PAGE_SIZE, int(utime) + int(stime), int(ppid))
    read_at = time.monotonic()

    cpu_percent = {}
    if prev:
        prev_procs, prev_read_at = prev
        for key, proc in procs.items():
            if key in prev_procs:
                cpu_seconds = (proc.cpu_ticks - prev_procs[key].cpu_ticks) / CLOCK_TICKS
                cpu_percent[key] = round(100 * cpu_seconds / (read_at - prev_read_at), 1)

    rows = []
    for key in sorted(procs, key=lambda key: procs[key].rss_bytes, reverse=True):
        pid, proc = key[0], procs[key]
        if not proc.rss_bytes and not cpu_percent.get(key):
            continue  # idle kernel thread
        cgroup = read_text(f'/proc/{pid}/cgroup')
        match = CONTAINER_ID.search(cgroup)
        container = container_names.get(match.group(0), match.group(0)[:12]) if match else ''
        cmdline = read_text(f'/proc/{pid}/cmdline').replace('\0', ' ').replace('\n', ' ').strip()  # one row per line
        for pattern, replacement in SECRETS:
            cmdline = pattern.sub(replacement, cmdline)
        rows.append([ts, pid, container, proc.name, proc.rss_bytes, cpu_percent.get(key), cmdline[:200], proc.ppid,
                     cgroup_path(cgroup)])
    return rows, (procs, read_at)


def append(kind, fields, rows, day):
    """Append and fsync per sample, so the rows just before a crash survive it."""
    path = os.path.join(DATA_DIR, f'{kind}_{day}.csv')
    is_new = not os.path.exists(path)
    with open(path, 'a', newline='') as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(fields)
        writer.writerows(rows)
        f.flush()
        os.fsync(f.fileno())


def collect():
    os.umask(0o022)  # readable by everyone, like /proc; the installer makes the directory root-only where /proc is
    os.makedirs(DATA_DIR, exist_ok=True)
    has_docker = shutil.which('docker') is not None
    prev_cpu_ticks, prev_procs, container_names = None, None, {}
    while True:
        started = time.monotonic()
        now = datetime.now(timezone.utc)
        ts, day = now.strftime('%Y-%m-%dT%H:%M:%SZ'), now.strftime('%Y-%m-%d')
        try:
            row, prev_cpu_ticks = sample_host(ts, prev_cpu_ticks)
            append('host', HOST_FIELDS, [row], day)
        except Exception:
            logging.exception('host sample failed')
        if has_docker:
            try:
                rows, container_names = sample_containers(ts)
                append('containers', CONTAINER_FIELDS, rows, day)
            except Exception:
                logging.exception('container sample failed')
        try:
            rows, prev_procs = sample_processes(ts, prev_procs, container_names)
            append('processes', PROCESS_FIELDS, rows, day)
        except Exception:
            logging.exception('process sample failed')
        time.sleep(max(0, INTERVAL_SECONDS - (time.monotonic() - started)))


# ---------------------------------------------------------------- times and zones
# Files and timestamps are UTC; everything shown or typed is in the display time zone (TZ).

def label(t, fmt):
    """Seconds since the epoch -> text in the display time zone."""
    return time.strftime(fmt, time.localtime(t))


@lru_cache(maxsize=4096)
def to_second(ts):
    """'2026-11-06T03:14:27Z' -> seconds since the epoch."""
    return calendar.timegm(time.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S'))


# Minutes east of UTC for zone abbreviations people type; IST is India's.
ZONE_OFFSETS = {'UTC': 0, 'GMT': 0, 'Z': 0, 'IST': 330, 'EST': -300, 'EDT': -240, 'CST': -360, 'CDT': -300,
                'MST': -420, 'MDT': -360, 'PST': -480, 'PDT': -420, 'BST': 60, 'CET': 60, 'CEST': 120, 'EET': 120,
                'EEST': 180, 'MSK': 180, 'GST': 240, 'PKT': 300, 'SGT': 480, 'HKT': 480, 'JST': 540, 'KST': 540,
                'AEST': 600, 'AEDT': 660, 'NZST': 720, 'NZDT': 780}
OFFSET = re.compile(r'^([+-])(\d{1,2}):?(\d{2})$')
# Day first when a date is ambiguous: 12/10/2026 is 12 October; 2/13/2026 still reads as 13 February.
DATE_FORMATS = ['%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%d/%m/%y', '%m/%d/%y', '%d-%m-%Y', '%d-%m-%y', '%d.%m.%Y',
                '%d.%m.%y', '%d %b %Y', '%d %B %Y', '%b %d %Y', '%B %d %Y']
CLOCK_FORMATS = ['', ' %H:%M', ' %H:%M:%S', ' %I:%M %p', ' %I:%M%p', ' %I %p', ' %I%p']
ZONEINFO_DIRS = ['/usr/share/zoneinfo', '/usr/lib/zoneinfo', '/usr/share/lib/zoneinfo']


def valid_zone(name):
    return (name == 'system' or name.upper() in ZONE_OFFSETS or bool(OFFSET.match(name))
            or (re.fullmatch(r'[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*', name) is not None
                and any(os.path.isfile(os.path.join(d, name)) for d in ZONEINFO_DIRS)))


def posix_zone(name):
    """A TZ value for a zone name: IANA names pass through; IST or +05:30 become the POSIX 'IST-05:30'."""
    offset = ZONE_OFFSETS.get(name.upper())
    match = OFFSET.match(name)
    if match:
        sign, hours, minutes = match.groups()
        offset = (int(hours) * 60 + int(minutes)) * (1 if sign == '+' else -1)
    if offset is None:
        return name
    abbreviation = name.upper() if name.upper() in ZONE_OFFSETS else 'UTC' + name.replace(':', '')
    return f'{abbreviation}{"-" if offset >= 0 else "+"}{abs(offset) // 60:02d}:{abs(offset) % 60:02d}'


def zone_seconds(fields, zone):
    """(year, month, day, hour, minute) in `zone` (None = the display zone) -> seconds since the epoch."""
    moment = tuple(fields) + (0, 0, 0, -1)
    if zone is None:
        return int(time.mktime(moment))
    saved = os.environ.get('TZ')
    os.environ['TZ'] = posix_zone(zone)
    time.tzset()
    try:
        return int(time.mktime(moment))
    finally:
        if saved is None:
            os.environ.pop('TZ')
        else:
            os.environ['TZ'] = saved
        time.tzset()


def parse_time(text, around=None):
    """A typed date and time -> seconds since the epoch, or None if unreadable.

    Takes ISO ('2026-11-06T08:44+05:30'), dates like 12/10/2026 (day first), '12 Oct 2026' or 'Oct 12 2026' with an
    optional time ('14:30', '2:30 pm'; midnight if left out), or a bare 'HH:MM' on the date of `around`; then an
    optional zone: UTC, IST and other common abbreviations, '+05:30' or 'Asia/Kolkata'. No zone means the display zone.
    """
    text = ' '.join(text.replace(',', ' ').split())
    try:
        moment = datetime.fromisoformat(text[:-1] + '+00:00' if text.endswith('Z') else text)
        return int(moment.timestamp() if moment.tzinfo else time.mktime(moment.timetuple()))
    except ValueError:
        pass
    zone, words = None, text.split(' ')
    if len(words) > 1 and (words[-1].upper() in ZONE_OFFSETS or OFFSET.match(words[-1])
                           or re.fullmatch(r'[A-Za-z_]+(/[A-Za-z_+-]+)+', words[-1])):
        zone, text = words[-1], ' '.join(words[:-1])
    try:
        clock = time.strptime(text, '%H:%M')
        day = time.localtime(around or 0)
        return zone_seconds((day.tm_year, day.tm_mon, day.tm_mday, clock.tm_hour, clock.tm_min), zone)
    except ValueError:
        pass
    for date_format in DATE_FORMATS:
        for clock_format in CLOCK_FORMATS:
            try:
                parsed = time.strptime(text, date_format + clock_format)
            except ValueError:
                continue
            return zone_seconds((parsed.tm_year, parsed.tm_mon, parsed.tm_mday, parsed.tm_hour, parsed.tm_min), zone)
    return None


# ---------------------------------------------------------------- reading the samples

def gib(value):
    return '-' if value in (None, '') else f'{float(value) / 2**30:.2f} GiB'


def pct(value):
    return '-' if value in (None, '') else f'{float(value):.1f}%'


def number(value):
    return None if value in (None, '') else float(value)


def field(row, index):
    """A column that older files may not have."""
    return row[index] if len(row) > index else ''


def show_snapshot(at, csv_dir=DATA_DIR):
    """Prints usage at the sample nearest to `at`, with a trend for the minutes before it."""
    target_second = parse_time(at)
    if target_second is None:
        sys.exit(f'Could not read the time "{at}"; try "12/10/2026 14:30 IST" or "2026-10-12 14:30".')
    target = datetime.fromtimestamp(target_second, timezone.utc).replace(tzinfo=None)  # naive UTC, like ts
    days = [f'{target - timedelta(days=1):%Y-%m-%d}', f'{target:%Y-%m-%d}']  # the trend window can cross midnight

    def read(kind, keep=lambda row: True):
        rows = []
        for day in days:
            path = os.path.join(csv_dir, f'{kind}_{day}.csv')
            if os.path.exists(path):
                with open(path, newline='') as f:
                    rows += (row for row in csv.DictReader(f) if keep(row))
        return rows

    hosts = read('host')
    if not hosts:
        sys.exit(f'No samples around {label(target_second, "%Y-%m-%d %H:%M %Z")} in {csv_dir}')
    host = min(hosts, key=lambda row: abs(datetime.fromisoformat(row['ts'].rstrip('Z')) - target))
    ts = host['ts']
    end = datetime.fromisoformat(ts.rstrip('Z'))
    minutes = [f'{end - timedelta(minutes=m):%Y-%m-%dT%H:%M}' for m in reversed(range(30))]
    window = set(minutes)
    containers = read('containers', lambda row: row['ts'][:16] in window)
    processes = read('processes', lambda row: row['ts'][:16] in window)

    def trends(rows, key, column):
        """{key(row): sparkline of `column` per minute}, all keys on one scale; blank = no sample that minute."""
        series = {}
        for row in rows:
            if row['ts'][:16] in window and row[column]:
                series.setdefault(key(row), {})[row['ts'][:16]] = float(row[column])
        top = max((value for values in series.values() for value in values.values()), default=0) or 1
        return {k: ''.join(BLOCKS[min(7, int(values[m] / top * 8))] if m in values else ' ' for m in minutes)
                for k, values in series.items()}

    host_cpu = trends(hosts, lambda r: 'host', 'cpu_percent').get('host', '')
    host_mem = trends(hosts, lambda r: 'host', 'mem_available_bytes').get('host', '')
    container_mem = trends(containers, lambda r: r['container'], 'mem_bytes')
    process_mem = trends(processes, lambda r: r['pid'], 'rss_bytes')
    used = 100 * (1 - int(host['mem_available_bytes']) / int(host['mem_total_bytes']))

    away = abs(end - target).total_seconds()
    print(f'Snapshot {label(to_second(ts), "%Y-%m-%d %H:%M:%S %Z")}  '
          f'({away:.0f}s from {label(target_second, "%H:%M")})   trends: last 30 min, oldest -> newest\n')
    print(f"host  cpu {pct(host['cpu_percent']):>9}  {host_cpu}   load {host['load_1m']}")
    print(f"      available {gib(host['mem_available_bytes']):>9}  {host_mem}   "
          f"of {gib(host['mem_total_bytes'])} ({pct(used)} used)   swap used {gib(host['swap_used_bytes'])}\n")

    print(f"{'container':<20}{'cpu':>9}{'memory':>12}{'limit':>12}{'pids':>6}  memory trend")
    for row in sorted((r for r in containers if r['ts'] == ts), key=lambda r: -int(r['mem_bytes'] or 0)):
        print(f"{row['container']:<20}{pct(row['cpu_percent']):>9}{gib(row['mem_bytes']):>12}"
              f"{gib(row['mem_limit_bytes']):>12}{row['pids'] or '-':>6}  {container_mem.get(row['container'], '')}")

    print(f"\n{'pid':<8}{'container':<20}{'memory':>12}{'cpu':>9}  {'memory trend':<30}  command")
    for row in sorted((r for r in processes if r['ts'] == ts), key=lambda r: -int(r['rss_bytes'] or 0)):
        print(f"{row['pid']:<8}{row['container'] or 'host':<20}{gib(row['rss_bytes']):>12}{pct(row['cpu_percent']):>9}  "
              f"{process_mem.get(row['pid'], ''):<30}  {row['cmdline'] or '[' + row['name'] + ']'}")


HostSample = namedtuple('HostSample', 'cpu load_1m load_5m load_15m mem_used mem_total swap_used swap_total')
ProcRow = namedtuple('ProcRow', 'pid ppid container name command cgroup mem cpu')
# Like htop, the viewer holds what's on screen rather than the history behind it.
LIVE_HOST_SECONDS = 900  # the viewer's own live host samples kept for the graph
LIVE_PROCESS_SECONDS = 60  # and its live process samples, which are much bigger
SAMPLE_LIMIT = 240  # samples a column reads for the table at most, evenly spread; the graph stays exact
COLUMN_CACHE = 64  # columns kept computed
NOW_ZOOM = 60  # live bars this short show what runs now; longer ones keep their statistic, so a peak stays findable
RELOAD_SECONDS = 30


def host_sample(row):
    """A host CSV row (strings, or the collector's values) -> HostSample; columns newer than the file are None."""
    ts, cpu, load_1m, total, available, swap_used, load_5m, load_15m, swap_total = (list(row) + [''] * 9)[:9]
    return HostSample(number(cpu), number(load_1m), number(load_5m), number(load_15m),
                      int(total) - int(available), int(total), number(swap_used), number(swap_total))


def load_host(csv_dir):
    """{time: HostSample} for every host sample on disk."""
    host = {}
    for path in sorted(glob.glob(os.path.join(csv_dir, 'host_*.csv'))):
        with open(path, newline='') as f:
            for row in islice(csv.reader(f), 1, None):
                host[to_second(row[0])] = host_sample(row)
    return host


class DayFile:
    """Where each sample starts in one day's containers or processes CSV, so a column reads just its own samples.
    Only the offsets stay in memory, and the index grows with the file."""

    def __init__(self, path):
        self.path, self.times, self.offsets, self.size = path, array('q'), array('q'), 0

    def refresh(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size <= self.size:
            return
        position = self.size
        with open(self.path, 'rb') as f:
            f.seek(position)
            for line in f:
                if not line.endswith(b'\n'):
                    break  # a sample still being written
                if line[:1].isdigit():  # not the header
                    t = to_second(line[:19].decode())
                    if not self.times or t != self.times[-1]:
                        self.times.append(t)
                        self.offsets.append(position)
                position += len(line)
        self.size = position

    def samples(self, lo, hi, step):
        """(time, rows) for samples lo, lo + step, ... below hi, read one at a time."""
        with open(self.path, 'rb') as f:
            for i in range(lo, hi, step):
                end = self.offsets[i + 1] if i + 1 < len(self.offsets) else self.size
                f.seek(self.offsets[i])
                yield self.times[i], list(csv.reader(f.read(end - self.offsets[i]).decode(errors='replace').splitlines()))


class Store:
    """The recorded samples plus the viewer's own recent live samples, by time range."""

    def __init__(self, csv_dir):
        self.csv_dir = csv_dir
        self.files = {}
        self.live_host, self.live_rows = {}, {}  # time -> HostSample / process rows shaped like the CSV's
        self.reload()

    def reload(self):
        self.host = load_host(self.csv_dir)
        self.times = sorted(set(self.host) | set(self.live_host))

    def add_live(self, t, host_row, process_rows):
        self.live_host[t] = host_sample(host_row)
        self.live_rows[t] = [['' if value is None else str(value) for value in row] for row in process_rows]
        for old in [s for s in self.live_host if s < t - LIVE_HOST_SECONDS]:
            del self.live_host[old]
        for old in [s for s in self.live_rows if s < t - LIVE_PROCESS_SECONDS]:
            del self.live_rows[old]
        self.times = sorted(set(self.host) | set(self.live_host))

    def host_samples(self, start, end):
        times = self.times[bisect_left(self.times, start):bisect_left(self.times, end)]
        return [self.live_host.get(t) or self.host[t] for t in times]

    def day_file(self, kind, day):
        path = os.path.join(self.csv_dir, f'{kind}_{day}.csv')
        if path not in self.files:
            self.files[path] = DayFile(path)
        self.files[path].refresh()
        return self.files[path]

    def samples(self, kind, start, end, limit=None):
        """(step, iterator of (time, rows)) for the processes or containers sampled in [start, end), reading every
        `step`-th sample so that at most `limit` are read, one at a time."""
        spans, day = [], start - start % 86400
        while day < end:
            f = self.day_file(kind, time.strftime('%Y-%m-%d', time.gmtime(day)))
            lo, hi = bisect_left(f.times, start), bisect_left(f.times, end)
            if lo < hi:
                spans.append((f, lo, hi))
            day += 86400
        step = max(1, math.ceil(sum(hi - lo for _, lo, hi in spans) / limit)) if limit else 1
        live = sorted(self.live_rows.items()) if kind == 'processes' else []

        def read():
            for f, lo, hi in spans:
                yield from f.samples(lo, hi, step)
            yield from ((t, rows) for t, rows in live if start <= t < end)
        return step, read()


class LiveSampler:
    """Reads /proc directly for the newest samples, as htop does; it needs no root unless /proc hides processes."""

    def __init__(self, store):
        self.store = store
        self.prev_ticks = self.prev_procs = None

    def sample(self):
        """(time, host row, process rows) for now; CPU % is over the time since the previous call."""
        now = datetime.now(timezone.utc)
        ts = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        day = self.store.day_file('containers', now.strftime('%Y-%m-%d'))
        names = {}
        for _, rows in day.samples(max(0, len(day.times) - 1), len(day.times), 1):  # the latest docker stats
            names.update((field(row, 10), row[1]) for row in rows if field(row, 10))
        host_row, self.prev_ticks = sample_host(ts, self.prev_ticks)
        rows, self.prev_procs = sample_processes(ts, self.prev_procs, names)
        return int(now.timestamp()), host_row, rows


# ---------------------------------------------------------------- statistics, like a CloudWatch graph

STATISTICS = ['Average', 'Maximum', 'Minimum', 'p50', 'p90', 'p99']
METRICS = ['Memory', 'CPU', 'Load', 'Swap']
ZOOM_LEVELS = [10, 60, 300, 900, 1800, 3600, 86400]  # seconds per graph column
ZOOM_NAMES = {10: '10 s', 60: '1 min', 300: '5 min', 900: '15 min', 1800: '30 min', 3600: '1 hour', 86400: '1 day'}
LABEL_EVERY = {10: 120, 60: 600, 300: 3600, 900: 14400, 1800: 21600, 3600: 43200, 86400: 604800}


class Stat:
    """A running statistic: Average, Maximum and Minimum in constant memory; percentiles keep the values compactly
    and are nearest-rank, as in CloudWatch."""
    __slots__ = ('statistic', 'count', 'total', 'high', 'low', 'values')

    def __init__(self, statistic):
        self.statistic, self.count, self.total, self.high, self.low = statistic, 0, 0.0, None, None
        self.values = array('d') if statistic.startswith('p') else None

    def add(self, value):
        if value is None:
            return
        self.count += 1
        self.total += value
        self.high = value if self.high is None else max(self.high, value)
        self.low = value if self.low is None else min(self.low, value)
        if self.values is not None:
            self.values.append(value)

    def result(self):
        if not self.count:
            return None
        if self.statistic == 'Average':
            return self.total / self.count
        if self.statistic == 'Maximum':
            return self.high
        if self.statistic == 'Minimum':
            return self.low
        ordered = sorted(self.values)
        return ordered[max(0, math.ceil(int(self.statistic[1:]) / 100 * len(ordered)) - 1)]


def aggregate(values, statistic):
    stat = Stat(statistic)
    for value in values:
        stat.add(value)
    return stat.result()


def metric_value(sample, metric):
    if metric == 'Memory':
        return 100 * sample.mem_used / sample.mem_total
    if metric == 'CPU':
        return sample.cpu
    if metric == 'Load':
        return sample.load_1m
    return 100 * sample.swap_used / sample.swap_total if sample.swap_used is not None and sample.swap_total else None


Column = namedtuple('Column', 'host procs apps groups pids step')


def column_data(store, start, end, statistic):
    """What the meters and the table show for one graph column: each process's values, and each app's and container's
    totals per sample, reduced across the column's samples with `statistic` (so a Maximum is a real peak). Samples
    are read and folded in one at a time, so memory follows the number of processes, not the length of the column."""
    container_stats, pids = defaultdict(list), {}
    for t, rows in store.samples('containers', start, end, SAMPLE_LIMIT)[1]:
        for row in rows:
            container_stats[t].append((row[1], number(row[3]) or 0, number(row[2]) or 0))
            pids[row[1]] = field(row, 9)
    latest, mem, cpu, apps = {}, {}, {}, {}
    groups = defaultdict(lambda: (Stat(statistic), Stat(statistic)))
    step, samples = store.samples('processes', start, end, SAMPLE_LIMIT)
    for t, rows in samples:
        by_pid = {row[1]: ProcRow(row[1], field(row, 7), row[2], row[3], row[6], field(row, 8), None, None)
                  for row in rows}
        totals = defaultdict(lambda: [0.0, 0.0])
        for row in rows:
            key = (row[1], row[6])  # pid + command: a reused pid is a different process
            if key not in apps:
                apps[key] = app_of(by_pid[row[1]], by_pid)
                mem[key], cpu[key] = Stat(statistic), Stat(statistic)
            latest[key] = row
            row_mem, row_cpu = number(row[4]), number(row[5])
            mem[key].add(row_mem)
            cpu[key].add(row_cpu)
            for group in [('app', apps[key])] + ([('container', row[2])] if row[2] else []):
                totals[group][0] += row_mem or 0
                totals[group][1] += row_cpu or 0
        for name, stats_mem, stats_cpu in container_stats.get(t, ()):  # docker stats also counts the page cache
            counted = totals.get(('container', name), [0.0, 0.0])
            totals[('app', 'docker')][0] += stats_mem - counted[0]
            totals[('app', 'docker')][1] += stats_cpu - counted[1]
            totals[('container', name)] = [stats_mem, stats_cpu]
        for group, (group_mem, group_cpu) in totals.items():
            groups[group][0].add(group_mem)
            groups[group][1].add(group_cpu)
    procs = [ProcRow(row[1], field(row, 7), row[2], row[3], row[6], field(row, 8), mem[key].result(),
                     cpu[key].result()) for key, row in latest.items()]
    host = store.host_samples(start, end)
    host = HostSample(*(aggregate(values, statistic) for values in zip(*host))) if host else None
    return Column(host, procs, apps, {group: (m.result(), c.result()) for group, (m, c) in groups.items()}, pids, step)


# ---------------------------------------------------------------- grouping into apps

SESSION_PROGRAMS = {'bash', 'sh', 'dash', 'zsh', 'fish', 'ksh', 'tcsh', 'login', 'su', 'sudo', 'sshd', 'sshd-session',
                    'tmux', 'screen', 'systemd', 'init', 'mosh-server'}
DOCKER_PROGRAMS = {'docker', 'dockerd', 'containerd', 'containerd-shim', 'containerd-shim-runc-v2', 'docker-proxy',
                   'docker-init', 'runc'}
INTERPRETER = re.compile(r'^(python[\d.]*|node(js)?[\d.]*|ruby[\d.]*|perl[\d.]*|php[\d.]*|java|bun|deno|sh|bash)$')
SCRIPT_SUFFIXES = ('.py', '.js', '.mjs', '.ts', '.rb', '.pl', '.php', '.jar', '.sh')
GENERIC_DIRS = {'bin', 'sbin', 'lib', 'libexec', 'versions', 'venv', '.venv', 'current', 'releases', 'share', 'local',
                'usr', 'opt'}
SERVICE_UNIT = re.compile(r'/system\.slice/(?:[^/]+\.slice/)*([^/]+)\.service(?:/|$)')


def program_name(name, command):
    """A readable program name: the executable, or the script an interpreter runs; skips bin and version dirs."""
    words = command.split()
    if not words:
        return name
    path = words[0].rstrip(':').lstrip('-')  # a login shell shows as "-bash"
    if INTERPRETER.match(os.path.basename(path)):
        if '-m' in words[1:-1]:
            return words[words.index('-m') + 1]
        script = next((w for w in words[1:] if not w.startswith('-') and ('/' in w or w.endswith(SCRIPT_SUFFIXES))), None)
        if script:
            return os.path.splitext(os.path.basename(script))[0]
    for part in reversed(path.split('/')):
        if re.search('[A-Za-z]', part) and part not in GENERIC_DIRS:
            return part
    return name


def app_of(proc, by_pid):
    """The app a process belongs to: 'docker' for containers and the engine, the systemd unit for a system service,
    otherwise the program at the top of its process tree, below shells, sessions and init."""
    if proc.container:
        return 'docker'
    unit = SERVICE_UNIT.search(proc.cgroup)
    if unit:
        return 'docker' if unit.group(1) in ('docker', 'containerd') else unit.group(1)
    if proc.pid == '1' or proc.cgroup.endswith('/init.scope'):
        return 'systemd'
    if not proc.command:
        return 'kernel'
    root, seen = proc, {proc.pid}
    while True:
        parent = by_pid.get(root.ppid)
        if (parent is None or parent.pid in seen or parent.pid in ('0', '1')
                or program_name(parent.name, parent.command) in SESSION_PROGRAMS):
            break
        seen.add(parent.pid)
        root = parent
    name = program_name(root.name, root.command)
    if name in DOCKER_PROGRAMS:
        return 'docker'
    return 'sessions' if name in SESSION_PROGRAMS else name


Node = namedtuple('Node', 'kind key label pid mem cpu count children')
TableRow = namedtuple('TableRow', 'key kind pid label mem cpu count containers tree has_children is_open group app')
MouseEvent = namedtuple('MouseEvent', 'kind x y step')  # kind: click or wheel; step: -1 up, 1 down


def sort_value(sort_key):
    return {'PID': lambda n: int(n.pid or 0), 'RES': lambda n: n.mem or 0, 'MEM%': lambda n: n.mem or 0,
            'CPU%': lambda n: n.cpu or 0}[sort_key]


def process_forest(procs, sort_key, descending):
    """htop's tree: each process under its parent when the parent is in the same group, siblings sorted."""
    pids = {p.pid for p in procs}
    children = defaultdict(list)
    for p in procs:
        children[p.ppid if p.ppid in pids and p.ppid != p.pid else None].append(p)
    placed = set()

    def build(p):
        placed.add(id(p))
        kids = [build(c) for c in children.get(p.pid, ()) if id(c) not in placed]
        return Node('process', ('process', p.pid, p.command), p.command or f'[{p.name}]', p.pid, p.mem, p.cpu, 0,
                    sorted(kids, key=sort_value(sort_key), reverse=descending))

    roots = [build(p) for p in children[None]]
    roots += [build(p) for p in procs if id(p) not in placed]  # parent loops from a reused pid
    return roots


def build_tree(column, sort_key, descending):
    """(app nodes, {(pid, command): app label}): each app with its process tree, biggest first; 'docker' holds the
    engine's processes and one node per container."""
    members, app_labels = defaultdict(list), {}
    for p in column.procs:
        app = column.apps[(p.pid, p.command)]
        members[app].append(p)
        app_labels[(p.pid, p.command)] = f'docker/{p.container}' if p.container else app
    if column.pids:
        members.setdefault('docker', [])
    order = sort_value(sort_key)
    nodes = []
    for app, procs in members.items():
        children = process_forest([p for p in procs if not p.container], sort_key, descending)
        if app == 'docker':
            by_container = defaultdict(list)
            for p in procs:
                if p.container:
                    by_container[p.container].append(p)
            for name in set(by_container) | set(column.pids):
                kids = by_container.get(name, [])
                mem, cpu = column.groups.get(('container', name), (None, None))
                children.append(Node('container', ('container', name), name, '', mem, cpu, len(kids),
                                     process_forest(kids, sort_key, descending)))
        mem, cpu = column.groups.get(('app', app), (None, None))
        nodes.append(Node('app', ('app', app), app, '', mem, cpu, len(procs),
                          sorted(children, key=order, reverse=descending)))
    return sorted(nodes, key=order, reverse=descending), app_labels


def merge_columns(columns):
    """One column with every process seen in any of `columns`; where several have one, the last column's values win."""
    procs, apps, groups, pids = {}, {}, {}, {}
    for column in columns:
        procs.update(((p.pid, p.command), p) for p in column.procs)
        apps.update(column.apps)
        groups.update(column.groups)
        pids.update(column.pids)
    return columns[-1]._replace(procs=list(procs.values()), apps=apps, groups=groups, pids=pids)


def bar_values(column):
    """(memory, CPU) by table row key for one bar: its processes, apps and containers."""
    values = {('process', p.pid, p.command): (p.mem, p.cpu) for p in column.procs}
    values.update(column.groups)  # keyed ('app', name) and ('container', name), like their rows
    return values


def matches(pattern, *texts):
    """htop's search and filter test: case-insensitive substring, '|' separating alternatives; '' matches all."""
    terms = [term.strip().lower() for term in pattern.split('|') if term.strip()]
    return not terms or any(term in text.lower() for term in terms for text in texts)


def filter_nodes(nodes, pattern):
    """Nodes that match, whole, and the parents of nodes that match deeper down."""
    if not pattern:
        return nodes
    kept = []
    for node in nodes:
        if matches(pattern, node.label):
            kept.append(node)
        else:
            children = filter_nodes(node.children, pattern)
            if children:
                kept.append(node._replace(children=children))
    return kept


def flatten(nodes, toggled, force_open, glyphs, depth=0, prefix='', group=None, app='', rows=None):
    """Visible rows with htop's tree lines. Apps and containers start folded and processes open; `toggled` holds the
    keys flipped from that, and `force_open` (an active filter) opens everything."""
    rows = [] if rows is None else rows
    for i, node in enumerate(nodes):
        app = node.label if depth == 0 else app
        last = i == len(nodes) - 1
        is_open = bool(node.children) and (force_open or (node.kind == 'process') != (node.key in toggled))
        mark = glyphs['open'] if node.children and not is_open else glyphs['shut']
        tree = f'{mark} ' if depth == 0 else prefix + (glyphs['bend'] if last else glyphs['tee']) + mark + ' '
        own_group = group if node.kind == 'process' else node.key
        containers = sum(1 for child in node.children if child.kind == 'container')
        rows.append(TableRow(node.key, node.kind, node.pid, node.label, node.mem, node.cpu, node.count, containers,
                             tree, bool(node.children), is_open, own_group, app))
        if is_open:
            child_prefix = prefix + ('   ' if last else glyphs['vert'] + '  ') if depth else ''
            flatten(node.children, toggled, force_open, glyphs, depth + 1, child_prefix, own_group, app, rows)
    return rows


def list_rows(procs, app_labels, sort_key, descending, pattern):
    """htop's list view: every process, sorted, with the app (or docker/container) it belongs to."""
    rows = []
    for p in procs:
        app = app_labels.get((p.pid, p.command), '')
        command = p.command or f'[{p.name}]'
        if matches(pattern, command, app):
            rows.append(TableRow(('process', p.pid, p.command), 'process', p.pid, command, p.mem, p.cpu, 0, 0, '',
                                 False, False, None, app))
    return sorted(rows, key=sort_value(sort_key), reverse=descending)


# ---------------------------------------------------------------- htop's formatting

UNIT_PREFIXES = 'KMGTPEZYRQ'
SORT_COLUMNS = {'PID': False, 'RES': True, 'CPU%': True, 'MEM%': True}  # column -> descending by default, as in htop
BLOCKS = '▁▂▃▄▅▆▇█'
GLYPHS = dict(bars=BLOCKS, vert='│', hline='─', corner='└', marker='▲', tee='├', bend='└', open='+', shut='─',
              asc='△', desc='▽', left_right='← / →', up_down='↑ / ↓')
ASCII_GLYPHS = dict(bars='.:-=+*#@', vert='|', hline='-', corner='+', marker='^', tee='`', bend='`', open='+',
                    shut='-', asc='+', desc='-', left_right='Lt / Rt', up_down='Up / Dn')


def kbytes_segments(kib):
    """htop's Row_printKBytes: a 6-column memory figure as [(text, style)], digits colored by magnitude."""
    if kib is None:
        return [('  N/A ', 'shadow')]
    magnitude = ['normal', 'mega', 'giga', 'large']
    if kib < 1000:
        return [(f'{kib:5d} ', 'normal')]
    if kib < 100000:
        return [(f'{kib // 1000:2d}', 'mega'), (f'{kib % 1000:03d} ', 'normal')]
    unit = 1
    hundredths = (kib // 256) * 25 + (kib % 256) * 25 // 256  # KiB -> 1/100 MiB
    while hundredths >= 1000000:
        hundredths //= 1024
        unit += 1
    color, prev_color, next_color = (magnitude[min(u, 3)] for u in (unit, unit - 1, unit + 1))
    whole, hundredths = divmod(hundredths, 100)
    prefix = UNIT_PREFIXES[unit]
    if whole < 100:
        fraction = f'.{hundredths:02d}' if whole < 10 else f'.{hundredths // 10}'
        return [(str(whole), color), (fraction, prev_color), (f'{prefix} ', color)]
    if whole < 1000:
        return [(f'{whole:4d}{prefix} ', color)]
    return [(str(whole // 1000), next_color), (f'{whole % 1000:03d}{prefix} ', color)]


def human_unit(kib):
    """htop's Meter_humanUnit: '0K', '1023K', '98.7M', '1.23G'."""
    unit = 0
    while kib >= 1024 and unit < len(UNIT_PREFIXES) - 1:
        kib /= 1024
        unit += 1
    precision = 0
    if unit:
        precision = 2 if kib <= 9.99 else 1 if kib <= 99.9 else 0
        if precision < 2:
            kib = max(kib, 10.0 if precision == 1 else 100.0)
    return f'{kib:.{precision}f}{UNIT_PREFIXES[unit]}'


def percent_segment(value, width):
    """htop's Row_printPercentage: (text, style) with a trailing space; MEM%'s 4 columns show 100 above 99.9."""
    if value is None:
        return f'{"N/A":>{width}} ', 'shadow'
    style = 'shadow' if value < 0.05 else 'mega' if value >= 99.9 else 'normal'
    if width == 4 and value > 99.9:
        return ' 100 ', style
    return f'{value:{width}.1f} ', style


def plural(count, word, words):
    return f'{count} {word if count == 1 else words}'


def row_segments(row, widths, mem_total, tree_mode):
    """One table row as [(text, style)]: PID, RES, CPU%, MEM%, then the app column (list view) and the command."""
    pid_w, cpu_w, app_w = widths
    segments = [(f' {row.pid:>{pid_w}}  ', 'normal')]
    segments += kbytes_segments(None if row.mem is None else int(row.mem) // 1024)
    segments += [(' ', 'normal'), percent_segment(row.cpu, cpu_w), (' ', 'normal')]
    segments += [percent_segment(100 * row.mem / mem_total if row.mem is not None and mem_total else None, 4),
                 (' ', 'normal')]
    return segments + name_segments(row, app_w, tree_mode)


def name_segments(row, app_w, tree_mode):
    """The end of a table row: the app column (list view), then the tree and the command or app."""
    segments = []
    if not tree_mode:
        segments.append((f'{row.app[:app_w]:<{app_w}}  ', 'normal'))
    segments.append((row.tree, 'tree'))
    if row.kind == 'process':
        segments.append((row.label, 'normal'))
    else:
        detail = plural(row.count, 'process', 'processes')
        if row.containers:
            detail += ', ' + plural(row.containers, 'container', 'containers')
        segments += [(row.label, 'app' if row.kind == 'app' else 'container'), (f'    {detail}', 'shadow')]
    return segments


def bar_row_segments(row, widths, bars, cell_w, use_cpu, tree_mode):
    """A row with bars side by side: PID, the row's RES (CPU% on the CPU graph) in each bar, '-' where it wasn't
    running, then the app and command."""
    pid_w, _, app_w = widths
    segments = [(f' {row.pid:>{pid_w}}  ', 'normal')]
    for values in bars:
        pair = values.get(row.key)
        value = None if pair is None else pair[1] if use_cpu else pair[0]
        text = '-' if pair is None else 'N/A' if value is None else f'{value:.1f}' if use_cpu else human_unit(value / 1024)
        segments.append((f'{text:>{cell_w - 1}} ', 'shadow' if value is None else 'normal'))
    return segments + [(' ', 'normal')] + name_segments(row, app_w, tree_mode)


def bar_header_segments(widths, labels, marked, cell_w, descending, tree_mode, glyphs):
    """Titles with bars side by side as (text, style, bar start); the marker's bar, which orders the rows, gets the
    sort arrow."""
    pid_w, _, app_w = widths
    arrow = glyphs['desc'] if descending else glyphs['asc']
    segments = [(f' {"PID":>{pid_w}}  ', 'header', None)]
    for start, text in labels:
        segments.append((f'{text:>{cell_w - 1}}' + (arrow if start == marked else ' '),
                         'sort' if start == marked else 'header', start))
    segments.append((' ', 'header', None))
    if not tree_mode:
        segments.append((f'{"APP":<{app_w}}  ', 'header', None))
    return segments + [('App / Process' if tree_mode else 'Command', 'header', None)]


def bar_format(zoom):
    """How a bar's time is written, under the graph and above its table column."""
    return '%H:%M' if zoom < 900 else '%d %b %H:%M' if zoom < 86400 else '%d %b'


def header_segments(widths, sort_key, descending, tree_mode, glyphs):
    """The column titles as (text, style, sort column); the sort column gets htop's ▽/△ for its trailing space."""
    pid_w, cpu_w, app_w = widths
    titles = [(None, ' '), ('PID', f'{"PID":>{pid_w}} '), (None, ' '), ('RES', '  RES '), (None, ' '),
              ('CPU%', f'{"CPU%":>{cpu_w}} '), (None, ' '), ('MEM%', 'MEM% '), (None, ' ')]
    if not tree_mode:
        titles.append((None, f'{"APP":<{app_w}}  '))
    titles.append((None, 'Command' if not tree_mode else 'App / Process'))
    return [(title[:-1] + (glyphs['desc'] if descending else glyphs['asc']), 'sort', column) if column == sort_key
            else (title, 'header', column) for column, title in titles]


# ---------------------------------------------------------------- settings (F2), saved like htop's htoprc

DELAYS = [5, 10, 15, 20, 30, 50, 100]  # live refresh, tenths of a second
# What the installer asks, kept in the service's unit and tmpfiles rule; Setup and `hmon configure` change them.
UNIT_PATH = '/etc/systemd/system/hmon.service'
TMPFILES_PATH = '/etc/tmpfiles.d/hmon.conf'
INTERVALS = [5, 10, 15, 30, 60, 120, 300, 600]  # seconds between samples
RETENTIONS = [1, 2, 3, 7, 14, 30, 60, 90, 180, 365]  # days kept
SAMPLE_BYTES = 150  # on disk per process per sample, as the installer estimates


def time_zones():
    """'system', 'UTC' and every zone in the system's zone database, for the time zone dropdown."""
    zones = set()
    for folder in ZONEINFO_DIRS:
        for table in ('zone1970.tab', 'zone.tab'):
            zones.update(line.split('\t')[2] for line in read_text(os.path.join(folder, table)).splitlines()
                         if not line.startswith('#') and line.count('\t') >= 2)
        if zones:
            break
    return ['system', 'UTC'] + sorted(zones)


def set_zone(name):
    """Make `name` (or the system's zone) the process's time zone."""
    if name == 'system':
        if SYSTEM_TZ is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = SYSTEM_TZ
    else:
        os.environ['TZ'] = posix_zone(name)
    time.tzset()


@lru_cache(maxsize=None)
def zone_label(name):
    """'UTC+05:30 IST' for a zone, as of now: its offset, then its abbreviation where it has a lettered one."""
    saved = os.environ.get('TZ')
    set_zone(name)
    now = time.localtime()
    offset, abbreviation = now.tm_gmtoff, time.strftime('%Z', now)
    if saved is None:
        os.environ.pop('TZ', None)
    else:
        os.environ['TZ'] = saved
    time.tzset()
    text = f'UTC{"+" if offset >= 0 else "-"}{abs(offset) // 3600:02d}:{abs(offset) % 3600 // 60:02d}'
    return text + (f' {abbreviation}' if abbreviation.isalpha() and abbreviation != 'UTC' else '')


def recording():
    """(seconds between samples, days kept) of the installed service, or (None, None) where it isn't installed."""
    unit = read_text(UNIT_PATH)
    if not unit:
        return None, None
    interval = re.search(r'^Environment=HMON_INTERVAL=(\d+)$', unit, re.M)
    days = re.search(r' (\d+)d$', read_text(TMPFILES_PATH).strip())
    return int(interval.group(1)) if interval else 60, int(days.group(1)) if days else 14


def configure_recording(interval, days):
    """Rewrites the service's sampling interval and the retention, then restarts the collector. Needs root."""
    unit = read_text(UNIT_PATH)
    if re.search(r'^Environment=HMON_INTERVAL=', unit, re.M):
        unit = re.sub(r'^Environment=HMON_INTERVAL=\d+$', f'Environment=HMON_INTERVAL={interval}', unit, flags=re.M)
    else:
        unit = unit.replace('[Service]\n', f'[Service]\nEnvironment=HMON_INTERVAL={interval}\n', 1)
    rule = re.sub(r' \d+d$', f' {days}d', read_text(TMPFILES_PATH).strip()) + '\n'  # read before opening to write
    with open(UNIT_PATH, 'w') as f:
        f.write(unit)
    with open(TMPFILES_PATH, 'w') as f:
        f.write(rule)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'restart', 'hmon'], check=True)


def megabytes_per_day(interval, processes):
    return 86400 / interval * processes * SAMPLE_BYTES / 1e6
DEFAULTS = {'tz': 'system', 'statistic': 'Average', 'granularity': '60', 'graph': 'Memory', 'delay': '15',
            'view': 'tree', 'sort': 'MEM%', 'mouse': 'on'}
VALID = {'tz': valid_zone, 'statistic': lambda v: v in STATISTICS,
         'granularity': lambda v: v.isdigit() and int(v) in ZOOM_LEVELS, 'graph': lambda v: v in METRICS,
         'delay': lambda v: v.isdigit() and int(v) > 0, 'view': lambda v: v in ('tree', 'list'),
         'sort': lambda v: v in SORT_COLUMNS, 'mouse': lambda v: v in ('on', 'off')}


def load_settings():
    """DEFAULTS overlaid with CONFIG_PATH's key=value lines; anything unreadable or invalid keeps its default."""
    settings = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            for line in f:
                key, sep, value = line.strip().partition('=')
                if sep and key in settings and VALID[key](value.strip()):
                    settings[key] = value.strip()
    except OSError:
        pass
    return settings


def save_settings(settings):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        f.write('# hmon settings, written by the F2 Setup screen\n')
        f.writelines(f'{key}={value}\n' for key, value in settings.items())


def cycle(options, current, step):
    options = options if current in options else [current] + options
    return options[(options.index(current) + step) % len(options)]


# ---------------------------------------------------------------- the viewer

class Viewer:
    """htop for the past: meters and a graph for the column under the marker, and its apps and processes below."""

    def __init__(self, screen, store, settings, sampler=None, use_color=True, unicode=True, filter_text='', mouse=True):
        self.screen, self.store, self.sampler = screen, store, sampler
        self.mouse, self.mouse_on = mouse, settings.get('mouse', 'on') == 'on'  # -M turns it off for this run only
        self.regions, self.row_top, self.tree_x = [], 0, 0  # clickable areas of the last frame
        self.shown, self.pressed_at, self.dragged_to, self.held = {}, None, None, False
        self.update_available = False
        self.anchor, self.bar_starts, self.graph_area = None, None, None  # a range of bars, from anchor to the marker
        self.glyphs = GLYPHS if unicode else ASCII_GLYPHS
        self.styles = self.make_styles(use_color and curses.has_colors())
        self.columns, self.graph_values = {}, {}  # caches, by column start and the settings that shape them
        self.statistic, self.metric = settings['statistic'], settings['graph']
        self.zoom, self.delay, self.tree = int(settings['granularity']), int(settings['delay']), settings['view'] == 'tree'
        self.sort_key = settings['sort']
        self.descending = SORT_COLUMNS[self.sort_key]
        self.apply_tz(settings['tz'])
        self.toggled, self.group_keys = set(), set()
        self.filter, self.mode, self.search, self.search_failed, self.notice = filter_text, None, '', False, ''
        self.index, self.selected, self.scroll, self.page = 0, None, 0, 10
        self.rows, self.width, self.graph_w, self.table_top, self.cursor_x = [], 80, 10, 0, 0
        self.live_t, self.step, self.live_cache = None, 1, (None, None)
        self.next_reload = time.monotonic() + RELOAD_SECONDS
        self.cursor = self.view_end = self.align(self.store.times[-1])

    @staticmethod
    def make_styles(use_color):
        """htop's default color scheme (CRT.c), or its monochrome one."""
        if use_color:
            try:
                curses.use_default_colors()
                pairs = [(curses.COLOR_CYAN, -1), (curses.COLOR_GREEN, -1), (curses.COLOR_RED, -1),
                         (curses.COLOR_BLACK, curses.COLOR_GREEN), (curses.COLOR_BLACK, curses.COLOR_CYAN),
                         (curses.COLOR_WHITE, -1), (curses.COLOR_YELLOW, -1), (curses.COLOR_BLACK, -1),
                         (curses.COLOR_RED, curses.COLOR_CYAN), (curses.COLOR_BLUE, -1),
                         (curses.COLOR_BLACK, curses.COLOR_YELLOW)]
                for pair, (fg, bg) in enumerate(pairs, start=1):
                    curses.init_pair(pair, fg, bg)
            except curses.error:
                use_color = False
        bold, reverse = curses.A_BOLD, curses.A_REVERSE
        if not use_color:
            return dict(normal=0, shadow=curses.A_DIM, mega=0, giga=bold, large=bold, caption=0, value=bold,
                        bracket=bold, bar=0, swap=0, header=reverse, sort=reverse | bold, selected=reverse, tree=0,
                        app=bold, container=bold, graph=0, marker=bold, key=0, label=reverse, failed=reverse | bold,
                        live=bold, tab=reverse, update=reverse | bold)
        cyan, green, red, header, selected, white, yellow, gray, failed, blue, update = (curses.color_pair(n)
                                                                                         for n in range(1, 12))
        return dict(normal=0, shadow=gray | bold, mega=cyan, giga=green, large=red | bold, caption=cyan,
                    value=cyan | bold, bracket=bold, bar=green, swap=red, header=header, sort=selected,
                    selected=selected, tree=cyan, app=bold, container=blue | bold, graph=cyan,
                    marker=yellow | bold, key=white, label=selected, failed=failed, live=green | bold, tab=selected,
                    update=update)

    def settings(self):
        return {'tz': self.tz, 'statistic': self.statistic, 'granularity': str(self.zoom), 'graph': self.metric,
                'delay': str(self.delay), 'view': 'tree' if self.tree else 'list', 'sort': self.sort_key,
                'mouse': 'on' if self.mouse_on else 'off'}

    def apply_mouse(self):
        """Mouse on: clicks go to hmon and a drag selects text through hmon; holding Shift (Option in iTerm2) lets the
        terminal select instead. Mouse off: the terminal selects text as usual."""
        on = self.mouse and self.mouse_on
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION if on else 0)
            curses.mouseinterval(0)  # report presses at once instead of waiting to tell clicks from double-clicks
            self.screen.refresh()  # ncurses' own mouse switch goes out first, or it would undo the next line
            sys.stdout.write('\033[?1002h' if on else '\033[?1002l')  # report drags too, so hmon can select text
            sys.stdout.flush()
        except curses.error:
            pass

    def apply_tz(self, name):
        if name == 'system':
            if SYSTEM_TZ is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = SYSTEM_TZ
        else:
            os.environ['TZ'] = posix_zone(name)
        time.tzset()
        # Columns follow the zone's clock. ponytail: today's offset, so across a DST change older hour and day
        # columns sit an hour off the clock.
        self.tz, self.shift = name, time.localtime().tm_gmtoff
        self.columns.clear()
        self.graph_values.clear()

    def align(self, t):
        return (t + self.shift) // self.zoom * self.zoom - self.shift

    def erase(self):
        self.screen.erase()
        self.graph_area = None
        self.shown = {}  # what's on screen by (row, column), so a mouse drag can copy it

    def refresh(self):
        if self.dragged_to:  # a redraw mid-drag keeps the selection showing
            self.paint(self.selection(self.pressed_at, self.dragged_to), curses.A_REVERSE)
        self.screen.refresh()

    def put(self, y, x, text, style='normal'):
        height, width = self.screen.getmaxyx()
        if 0 <= y < height and 0 <= x < width - 1 and text:
            text = text[:width - 1 - x]
            self.screen.addstr(y, x, text, self.styles[style])
            for i, char in enumerate(text):
                self.shown[(y, x + i)] = char, style

    def put_segments(self, y, x, segments):
        for text, style in segments:
            self.put(y, x, text, style)
            x += len(text)
        return x

    def put_keys(self, y, items, limit=None):
        """A bar of (key, what it does) along row `y`: `F1 Help  F2 Setup`, leaving off the items that won't fit
        whole before column `limit` (the screen's edge by default). Returns where each drawn item starts and ends."""
        limit = self.screen.getmaxyx()[1] - 1 if limit is None else limit
        spans, x = [], 0
        for key, name in items:
            if x + len(key) + 1 + len(name) > limit:
                break
            end = self.put_segments(y, x, [(key, 'key'), (f' {name}', 'label')])
            spans.append((x, end))
            x = end + 2
        return spans

    # ---- data

    def column_at(self, start):
        """A bar's column for the meters and the table. On a short live bar that's the newest live sample alone, so
        they show what's running now, as htop does; other bars reduce their samples with the statistic."""
        if self.live_t is not None and start <= self.live_t < start + self.zoom <= start + NOW_ZOOM:
            if self.live_cache[0] != (self.live_t, self.statistic):
                self.live_cache = ((self.live_t, self.statistic),
                                   column_data(self.store, self.live_t, self.live_t + 1, self.statistic))
            return self.live_cache[1]
        return self.column(start)

    def column(self, start):
        key = (start, self.zoom, self.statistic)
        if key not in self.columns:
            if len(self.columns) >= COLUMN_CACHE:
                del self.columns[next(iter(self.columns))]  # the oldest
            self.columns[key] = column_data(self.store, start, start + self.zoom, self.statistic)
        return self.columns[key]

    def graph_value(self, start):
        key = (start, self.zoom, self.statistic, self.metric)
        if key not in self.graph_values:
            samples = self.store.host_samples(start, start + self.zoom)
            self.graph_values[key] = aggregate([metric_value(s, self.metric) for s in samples], self.statistic)
        return self.graph_values[key]

    def tick(self):
        """Every refresh delay: a live sample (htop-style), and every RELOAD_SECONDS the newly recorded ones."""
        last = self.store.times[-1]
        following = self.cursor == self.align(last)
        if self.sampler:
            try:
                self.live_t, host_row, rows = self.sampler.sample()
                self.store.add_live(self.live_t, host_row, rows)
            except OSError:
                self.sampler = self.live_t = None  # no /proc here
        if time.monotonic() >= self.next_reload:
            self.store.reload()
            self.columns.clear()
            self.graph_values.clear()
            self.next_reload = time.monotonic() + RELOAD_SECONDS
        else:  # only columns that can hold the new samples change
            self.columns = {k: v for k, v in self.columns.items() if k[0] + k[1] <= last}
            self.graph_values = {k: v for k, v in self.graph_values.items() if k[0] + k[1] <= last}
        if following:
            self.cursor = self.align(self.store.times[-1])

    def is_live(self):
        return self.live_t is not None and self.cursor <= self.live_t < self.cursor + self.zoom

    # ---- drawing

    def draw(self):
        height, width = self.screen.getmaxyx()
        self.width, self.graph_w = width, max(10, width - 8)
        first, last = self.align(self.store.times[0]), self.align(self.store.times[-1])
        self.cursor = min(max(self.align(self.cursor), first), last)
        self.view_end = min(max(self.align(self.view_end), self.cursor), self.cursor + (self.graph_w - 1) * self.zoom)
        column = self.column_at(self.cursor)
        self.step = column.step
        self.bar_starts = self.bars()
        if self.bar_starts:  # every process seen in the range, ordered by the marker's bar
            column = merge_columns([self.column_at(start) for start in self.bar_starts if start != self.cursor] + [column])
        nodes, app_labels = build_tree(column, self.sort_key, self.descending)
        self.group_keys = {n.key for n in nodes} | {c.key for n in nodes for c in n.children if c.kind == 'container'}
        if self.tree:
            self.rows = flatten(filter_nodes(nodes, self.filter), self.toggled, bool(self.filter), self.glyphs)
        else:
            self.rows = list_rows(column.procs, app_labels, self.sort_key, self.descending, self.filter)

        self.erase()
        self.regions = []  # (y0, y1, x0, x1, action(x, y)) for mouse clicks, rebuilt with every frame
        container_count = sum(1 for n in nodes for c in n.children if c.kind == 'container')
        self.draw_meters(width, column.host, len(column.procs), len(nodes), container_count)
        graph_h = max(4, (height - 13) // 3)
        self.draw_graph(4, graph_h)
        self.table_top = 8 + graph_h
        self.draw_table(self.table_top, height - self.table_top - 1, width, column.host)
        self.draw_function_bar(height - 1, width)
        self.refresh()

    def bars(self):
        """The bars the table shows side by side, from the anchor to the marker: as many as fit, nearest the marker."""
        if self.anchor is None:
            return None
        low, high = sorted((self.align(self.anchor), self.cursor))
        starts = list(range(int(low), int(high) + 1, self.zoom))
        fit = max(1, (self.width - 40) // (max(6, len(label(low, bar_format(self.zoom)))) + 2))
        return starts[-fit:] if self.cursor == high else starts[:fit]

    def draw_meters(self, width, host, process_count, app_count, container_count):
        half = width // 2
        cpu = host.cpu if host else None
        self.meter(0, 1, half - 3, 'CPU', (cpu or 0) / 100, 'N/A' if cpu is None else f'{cpu:.1f}%', 'bar')
        if host:
            self.meter(1, 1, half - 3, 'Mem', host.mem_used / host.mem_total,
                       f'{human_unit(host.mem_used / 1024)}/{human_unit(host.mem_total / 1024)}', 'bar')
        else:
            self.meter(1, 1, half - 3, 'Mem', 0, 'N/A', 'bar')
        if host and host.swap_used is not None:
            swap_text = human_unit(host.swap_used / 1024)
            if host.swap_total is not None:
                swap_text += '/' + human_unit(host.swap_total / 1024)
            self.meter(2, 1, half - 3, 'Swp', host.swap_used / host.swap_total if host.swap_total else 0, swap_text,
                       'swap')
        else:
            self.meter(2, 1, half - 3, 'Swp', 0, 'N/A', 'swap')
        x = half + 2
        self.put_segments(0, x, [('Tasks: ', 'caption'), (f'{process_count}', 'value'),
                                 (' process in ' if process_count == 1 else ' processes in ', 'caption'),
                                 (f'{app_count}', 'value'), (' app, ' if app_count == 1 else ' apps, ', 'caption'),
                                 (f'{container_count}', 'value'),
                                 (' container' if container_count == 1 else ' containers', 'caption')])
        loads = 'N/A'
        if host:
            loads = ' '.join(f'{v:.2f}' for v in (host.load_1m, host.load_5m, host.load_15m) if v is not None)
        self.put_segments(1, x, [('Load average: ', 'caption'), (loads, 'value')])
        when = [('Time: ', 'caption'), (self.span(), 'value')]
        if self.is_live():
            when.append(('   live', 'live'))
        elif not host:
            when.append(('   no samples', 'shadow'))
        self.put_segments(2, x, when)

    def meter(self, y, x, width, caption, fraction, text, fill_style):
        """htop's bar meter: Mem[|||||      3.20G/7.60G], the text right-aligned inside the bar."""
        inner = max(1, width - len(caption) - 2)
        filled = min(inner, math.ceil(max(0.0, fraction) * inner))
        text = text.rjust(inner)[-inner:]
        self.put(y, x, caption, 'caption')
        self.put(y, x + len(caption), '[', 'bracket')
        start = x + len(caption) + 1
        self.put(y, start, ''.join('|' if c == ' ' else c for c in text[:filled]), fill_style)
        self.put(y, start + filled, text[filled:], 'shadow')
        self.put(y, start + inner, ']', 'bracket')

    def span(self):
        c, zoom = self.cursor, self.zoom
        if self.is_live():
            return time.strftime('%Y-%m-%d %H:%M:%S %Z')
        if zoom < 60:
            text = label(c, '%Y-%m-%d %H:%M:%S') + label(c + zoom - 1, '-%H:%M:%S')
        elif zoom < 86400:
            text = label(c, '%Y-%m-%d %H:%M') + (label(c + zoom - 1, '-%H:%M') if zoom > 60 else '')
        else:
            text = label(c, '%a %d %b %Y')
        return text + label(c, ' %Z')

    def draw_graph(self, top, graph_h):
        g = self.glyphs
        x = 1
        for metric in METRICS:
            tab_x = x
            x = self.put_segments(top, x, [(f' {metric} ', 'tab' if metric == self.metric else 'normal'), (' ', 'normal')])
            self.regions.append((top, top, tab_x, x - 1, lambda cx, cy, m=metric: self.set_metric(m)))
        thinned = f'; table reads 1 in {self.step} samples' if self.step > 1 else ''
        low, high = sorted((self.align(self.anchor), self.cursor)) if self.anchor is not None else (None, None)
        if low is not None:
            count = (high - low) // self.zoom + 1
            shown = f'{len(self.bar_starts)} of {count}' if len(self.bar_starts) < count else f'{count}'
            thinned += f'; {shown} {"bar" if count == 1 else "bars"} in the table, Esc for one'
        self.put(top, x + 3, f'{self.statistic} per {ZOOM_NAMES[self.zoom]}, times in {label(self.cursor, "%Z")}{thinned}',
                 'shadow')
        starts = [self.view_end - (self.graph_w - 1 - col) * self.zoom for col in range(self.graph_w)]
        values = [self.graph_value(start) for start in starts]
        if self.metric == 'Load':  # load has no ceiling: scale to the busiest column in view
            ceiling = float(math.ceil(max([1.0] + [v for v in values if v is not None])))
            marks = (f'{ceiling:g}', f'{ceiling / 2:g}', '0')
        else:
            ceiling, marks = 100.0, ('100%', '50%', '0%')
        axis = top + 1 + graph_h
        self.put(top + 1, 1, f'{marks[0]:>4}')
        self.put(top + 1 + graph_h // 2, 1, f'{marks[1]:>4}')
        self.put(axis, 1, f'{marks[2]:>4}' + g['corner'] + g['hline'] * self.graph_w)
        for row in range(top + 1, axis):
            self.put(row, 5, g['vert'])
        self.regions.append((top + 1, axis + 1, 6, 6 + self.graph_w, lambda cx, cy: self.click_bar(starts[cx - 6])))
        self.graph_area = (top + 1, axis, starts)
        time_format = bar_format(self.zoom)
        for col, (start, value) in enumerate(zip(starts, values)):
            eighths = round(min(value, ceiling) / ceiling * graph_h * 8) if value is not None else 0
            is_marker = start == self.cursor
            style = 'marker' if is_marker else 'selected' if low is not None and low <= start <= high else 'graph'
            for row in range(graph_h):
                filled = eighths - (graph_h - 1 - row) * 8
                char = g['bars'][7] if filled >= 8 else g['bars'][filled - 1] if filled > 0 else (g['vert'] if is_marker else ' ')
                self.put(top + 1 + row, 6 + col, char, style)
            if is_marker:
                self.put(axis, 6 + col, g['marker'], 'marker')
            elif style == 'selected':
                self.put(axis, 6 + col, g['hline'], style)
            if (start + self.shift) % LABEL_EVERY[self.zoom] == 0:
                self.put(axis + 1, 6 + col, label(start, time_format), 'shadow')

    def draw_table(self, top, available, width, host):
        rows = self.rows
        widths = (max([5] + [len(r.pid) for r in rows]),
                  max([5] + [len(f'{r.cpu:.1f}') for r in rows if r.cpu is not None]),
                  min(24, max([3] + [len(r.app) for r in rows])))
        mem_total = host.mem_total if host else None
        bars = self.bar_starts
        if bars:  # one column per bar of the range: click a bar's title to order the rows by it
            time_format = bar_format(self.zoom)
            cell_w = max(6, len(label(bars[0], time_format))) + 2
            header = bar_header_segments(widths, [(start, label(start, time_format)) for start in bars], self.cursor,
                                         cell_w, self.descending, self.tree, self.glyphs)
            values = [bar_values(self.column_at(start)) for start in bars]
            segments_of = lambda row: bar_row_segments(row, widths, values, cell_w, self.metric == 'CPU', self.tree)
        else:  # htop: click a column title to sort by it, again to reverse
            header = header_segments(widths, self.sort_key, self.descending, self.tree, self.glyphs)
            segments_of = lambda row: row_segments(row, widths, mem_total, self.tree)
        self.put(top, 0, ' ' * (width - 1), 'header')
        x = 0
        for text, style, column in header:
            self.put(top, x, text, style)
            if column is not None:
                action = self.click_bar_title if bars else self.click_header
                self.regions.append((top, top, x, x + len(text), lambda cx, cy, c=column, act=action: act(c)))
            x += len(text)
        self.tree_x = x - len('App / Process' if self.tree else 'Command')

        keys = [row.key for row in rows]
        if self.selected in keys:
            self.index = keys.index(self.selected)
        self.index = min(max(self.index, 0), max(0, len(rows) - 1))
        self.selected = keys[self.index] if keys else None
        visible = max(1, available - 1)
        self.page = visible
        self.scroll = min(max(self.scroll, self.index - visible + 1), self.index)
        self.scroll = max(0, min(self.scroll, len(rows) - visible))

        self.row_top = top + 1
        self.regions.append((top + 1, top + visible, 0, width, self.click_row))
        for i, row in enumerate(rows[self.scroll:self.scroll + visible]):
            segments = segments_of(row)
            if self.scroll + i == self.index:
                self.put(top + 1 + i, 0, ''.join(text for text, _ in segments).ljust(width - 1), 'selected')
            else:
                self.put_segments(top + 1 + i, 0, segments)

    def draw_function_bar(self, y, width):
        """The keys along the bottom, each clickable; search and filter take over the bar."""
        g = self.glyphs
        if self.mode == 'search':
            items = [('F3', 'Next', curses.KEY_F3), ('S-F3', 'Prev', curses.KEY_F15), ('Esc', 'Cancel', 27)]
            prompt, text = ' Search: ', self.search
        elif self.mode == 'filter':
            items, prompt, text = [('Enter', 'Done', 10), ('Esc', 'Clear', 27)], ' Filter: ', self.filter
        else:
            items = [('F1', 'Help', curses.KEY_F1), ('F2', 'Setup', curses.KEY_F2), ('F3', 'Search', curses.KEY_F3),
                     ('F4', 'FILTER' if self.filter else 'Filter', curses.KEY_F4),
                     ('F5', 'List' if self.tree else 'Tree', curses.KEY_F5), ('F6', 'SortBy', curses.KEY_F6),
                     ('F10', 'Quit', curses.KEY_F10), (g['left_right'], 'Time', None), ('[ / ]', 'Zoom', ord('[')),
                     ('s', 'Stat', ord('s')), ('g', 'GoTo', ord('g')), ('Tab', 'Graph', ord('\t'))]
            prompt = text = None
        self.put(y, 0, ' ' * (width - 1), 'label')
        if self.notice and not self.mode:
            self.put(y, 0, f' {self.notice}', 'label')
            return
        update = ' New update available, Run: "hmon update" ' if self.update_available and prompt is None else ''
        right = width - 1 - len(update)  # the notice sits at the bottom right, and keys that would reach it make way
        spans = self.put_keys(y, [(key, name) for key, name, _ in items], right - 3)
        for (x0, x1), (_, _, code) in zip(spans, items):
            if code is not None:
                self.regions.append((y, y, x0, x1, lambda cx, cy, c=code: self.press(c)))
        if update:  # on yellow, set off from the bar by a gap
            self.put(y, right - 2, '  ', 'normal')
            self.put(y, right, update, 'update')
        if prompt is not None:
            x = self.put_segments(y, (spans[-1][1] if spans else 0) + 1, [(prompt, 'label')])
            self.put(y, x, text, 'failed' if self.mode == 'search' and self.search_failed else 'label')
            self.cursor_x = x + len(text)

    # ---- dialogs

    def blocking(self, on):
        self.screen.timeout(-1 if on else self.delay * 100)

    def show_cursor(self, visible):
        try:
            curses.curs_set(visible)
        except curses.error:  # terminals without cursor control
            pass

    def ask(self, y, question):
        """A line of typed input on row `y`: Enter accepts; Esc or a click cancels (None); Backspace and Ctrl+U
        edit. Ctrl+C quits hmon, as everywhere else."""
        text = ''
        self.blocking(True)
        self.show_cursor(1)
        try:
            while True:
                width = self.screen.getmaxyx()[1]
                self.put(y, 0, (question + text).ljust(width - 1), 'label')
                self.screen.move(y, min(len(question) + len(text), width - 2))
                self.refresh()
                key = self.screen.getch()
                if key in (10, 13, curses.KEY_ENTER):
                    return text.strip()
                if key == 27:
                    return None
                if key == curses.KEY_MOUSE:
                    event = self.mouse_event()
                    if event and event.kind == 'click':
                        return None
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    text = text[:-1]
                elif key == 21:  # Ctrl+U
                    text = ''
                elif 32 <= key < 127:
                    text += chr(key)
        finally:
            self.show_cursor(0)
            self.blocking(False)

    def show_help(self):
        """htop's help screen: title, what the meters show, then the keys in two columns."""
        g = self.glyphs
        self.blocking(True)
        self.erase()
        self.put(0, 1, f'hmon {VERSION} - htop for the past: what every app, container and process used, over time',
                 'value')
        self.put(1, 1, 'Meters and the table show the chosen statistic over the column under the marker; on the '
                       'newest column at 10 s or 1 min, what runs now.', 'value')
        self.put_segments(3, 1, [('CPU ', 'caption'), ('[', 'bracket'), ('used%', 'bar'), (']   ', 'bracket'),
                                 ('Mem ', 'caption'), ('[', 'bracket'), ('used/total', 'bar'), (']   ', 'bracket'),
                                 ('Swp ', 'caption'), ('[', 'bracket'), ('used/total', 'swap'), (']', 'bracket')])
        self.put_segments(4, 1, [('Memory: ', 'normal'), ('K', 'normal'), (' / ', 'shadow'), ('M', 'mega'),
                                 (' / ', 'shadow'), ('G', 'giga'), (' / ', 'shadow'), ('T', 'large'),
                                 ('   apps and containers add up their processes; ', 'shadow'),
                                 ('docker', 'app'), (' holds the containers', 'shadow')])
        left = [(g['left_right'], 'move the marker one column'), ('S-' + g['left_right'], 'move a screen width'),
                ('^ ^A', 'oldest sample'), ('$ ^E', 'newest sample (live)'), ('g', 'go to 12/10/2026 14:30 IST'),
                ('[ ]', 'coarser / finer: 10 s .. 1 day'), ('s', 'statistic: avg max min p50/90/99'),
                ('Tab S-Tab', 'graph: memory, CPU, load, swap'), ('Space', 'a range of bars, a table column each'),
                ('Esc', 'back to one bar'), ('F2', 'setup: zone, defaults, recording')]
        right = [(g['up_down'], 'select a row'), ('PgUp PgDn', 'page through the rows'), ('Home End', 'first / last row'),
                 ('+ -', 'unfold / fold the selected app'), ('Enter', 'unfold or fold it'),
                 ('* c', 'fold / unfold everything'),
                 ('F3 /', 'search'), ('F4 \\', 'filter (\'|\' separates terms)'), ('F5 t', 'tree / list view'),
                 ('F6 < >', 'choose the sort column'), ('M P N', 'sort by MEM% / CPU% / PID'),
                 ('I', 'invert the sort order'), ('F1 h ?', 'this help'), ('F10 q', 'quit')]
        for x, items in ((1, left), (48, right)):
            for i, (key, text) in enumerate(items):
                self.put(6 + i, x, f'{key:>9}: ', 'value')
                self.put(6 + i, x + 11, text, 'normal')
        height = self.screen.getmaxyx()[0]
        self.put(height - 1, 1, 'Press any key or click to return.', 'normal')
        self.refresh()
        while self.screen.getch() == curses.KEY_MOUSE and not self.mouse_event():
            pass  # the release of the click that opened help, or a press: wait for a whole click or a key
        self.blocking(False)

    SETTINGS = ['Time zone', 'Statistic', 'Granularity', 'Graph', 'Refresh delay', 'View', 'Mouse', 'Sample every',
                'Keep']
    RECORDING = SETTINGS.index('Sample every')  # where Setup's Recording section starts

    @classmethod
    def setting_row(cls, i):
        """The screen row of setting i in Setup; the Recording section has a heading above it."""
        return 4 + i + (1 if i >= cls.RECORDING else 0)

    def mouse_text(self, value):
        if not self.mouse:
            return f'{value}   (off for this run: -M)'
        return f'{value}   ' + ('clicks act; a drag highlights text and copies it' if value == 'on'
                                else 'the terminal selects text as usual; keys still work')

    def setting_options(self, name):
        """(options, current, name of an option, how its row in the dropdown reads) for one setting."""
        def disk(interval):
            return megabytes_per_day(interval, self.process_count)

        if name == 'Time zone':
            return time_zones(), self.tz, str, lambda z: f'{z:<34}{zone_label(z)}'
        if name == 'Statistic':
            return STATISTICS, self.statistic, str, str
        if name == 'Granularity':
            return ZOOM_LEVELS, self.zoom, lambda z: f'{ZOOM_NAMES[z]} per column', lambda z: f'{ZOOM_NAMES[z]} per column'
        if name == 'Graph':
            return METRICS, self.metric, str, str
        if name == 'Refresh delay':
            return DELAYS, self.delay, lambda d: f'{d / 10:g} s', lambda d: f'{d / 10:g} s between live samples'
        if name == 'View':
            return ['tree', 'list'], 'tree' if self.tree else 'list', str, str
        if name == 'Mouse':
            return ['on', 'off'], 'on' if self.mouse_on else 'off', str, self.mouse_text
        interval, days = self.recording
        if interval is None:
            return [], None, str, str
        if name == 'Sample every':
            return (INTERVALS, interval, lambda s: f'{s} s',
                    lambda s: f'{s} s'.ljust(8) + f'about {disk(s):,.0f} MB a day')
        return (RETENTIONS, days, lambda d: f'{d} days',
                lambda d: f'{d} days'.ljust(10) + f'about {disk(interval) * d:,.0f} MB in all')

    def setting_text(self, name):
        options, current, short, _ = self.setting_options(name)
        if name in ('Sample every', 'Keep') and current is None:
            return 'the hmon service is not installed here'
        if name == 'Time zone':
            return f'{self.tz}   ({zone_label(self.tz)})'
        if name == 'Mouse':
            return self.mouse_text(current)
        if name == 'Sample every':
            return f'{short(current)}   about {megabytes_per_day(current, self.process_count):,.0f} MB a day'
        if name == 'Keep':
            interval = self.recording[0]
            return f'{short(current)}   about {megabytes_per_day(interval, self.process_count) * current:,.0f} MB in all'
        return short(current)

    def apply_setting(self, name, value):
        if name == 'Time zone':
            self.apply_tz(value)
        elif name == 'Statistic':
            self.statistic = value
        elif name == 'Granularity':
            self.set_zoom(ZOOM_LEVELS.index(value) - ZOOM_LEVELS.index(self.zoom))
        elif name == 'Graph':
            self.set_metric(value)
        elif name == 'Refresh delay':
            self.delay = value
        elif name == 'View':
            self.tree = value == 'tree'
        elif name == 'Mouse':
            self.mouse_on = value == 'on'
            self.apply_mouse()
        elif name == 'Sample every':
            self.recording[0] = value
        else:
            self.recording[1] = value

    def choose(self, y, x, title, options, current, describe=str, backdrop=None):
        """A dropdown at (y, x) over what `backdrop()` draws: arrows, PgUp/PgDn, Home/End or the wheel move, typing
        filters by anything a row shows (a zone's name, offset or abbreviation: kolk, +05:30 or ist), Enter or a click
        picks, Esc or a click outside cancels. Returns the pick, or None."""
        query, index, top = '', options.index(current) if current in options else 0, 0
        while True:
            if backdrop:
                backdrop()  # repainted each time, so a list that shrinks while filtering uncovers the screen
            height, width = self.screen.getmaxyx()
            shown = [option for option in options if query.lower() in describe(option).lower()]
            rows = max(1, min(len(shown), height - y - 3))
            box = min(width - x - 1, max([len(title) + 24] + [len(describe(o)) + 3 for o in shown]))
            index = min(max(index, 0), max(0, len(shown) - 1))
            top = max(0, min(max(top, index - rows + 1), index, len(shown) - rows))
            heading = f' {title}: {query}' if query else f' {title}   (type to filter)'
            self.put(y, x, heading[:box].ljust(box), 'header')
            for i in range(rows):
                text = f' {describe(shown[top + i])}' if top + i < len(shown) else ' no match'
                self.put(y + 1 + i, x, text[:box].ljust(box), 'selected' if shown and top + i == index else 'normal')
            self.put(height - 1, 0, ' ' * (width - 1), 'label')
            end = self.put_keys(height - 1, [('Enter', 'Pick'), ('Esc', 'Cancel')])[-1][1]
            self.put(height - 1, end + 2, 'type to filter', 'label')
            self.refresh()
            key = self.screen.getch()
            if key in (curses.KEY_UP, curses.KEY_DOWN):
                index += 1 if key == curses.KEY_DOWN else -1
            elif key in (curses.KEY_PPAGE, curses.KEY_NPAGE):
                index += rows if key == curses.KEY_NPAGE else -rows
            elif key in (curses.KEY_HOME, curses.KEY_END):
                index = 0 if key == curses.KEY_HOME else len(shown) - 1
            elif key in (10, 13, curses.KEY_ENTER):
                return shown[index] if shown else None
            elif key == 27:
                return None
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                query, index = query[:-1], 0
            elif 32 <= key < 127:
                query, index = query + chr(key), 0
            elif key == curses.KEY_MOUSE:
                event = self.mouse_event()
                if not event:
                    continue
                if event.kind == 'wheel':
                    index += 3 * event.step
                elif y < event.y <= y + rows and x <= event.x < x + box:
                    return shown[top + event.y - y - 1] if top + event.y - y - 1 < len(shown) else None
                else:
                    return None

    def setup(self):
        """htop's F2 Setup. Enter or a click opens a setting's dropdown, Left/Right steps through it. Saved to
        CONFIG_PATH on leaving; the recording settings (the installer's questions) change the hmon service."""
        names = self.SETTINGS
        self.recording = list(recording())
        installed = tuple(self.recording)
        self.process_count = max(1, len(self.column(self.cursor).procs))
        choice = 0
        self.blocking(True)

        def draw():
            height, width = self.screen.getmaxyx()
            self.erase()
            self.put(0, 0, ' Setup'.ljust(width - 1), 'header')
            self.put(2, 2, 'Up/Down choose a setting. Enter or a click opens its list (type to filter); Left/Right '
                           'steps through it.', 'shadow')
            for i, name in enumerate(names):
                if i == self.RECORDING:
                    self.put(4 + i, 2, 'Recording (what the installer asked; changing it restarts the hmon service)',
                             'shadow')
                self.put(self.setting_row(i), 1, f'  {name:<16}{self.setting_text(name)}'.ljust(72),
                         'selected' if i == choice else 'normal')
            self.put(self.setting_row(len(names)) + 1, 2, f'Saved to {CONFIG_PATH} when you leave this screen.', 'shadow')
            self.put(height - 1, 0, ' ' * (width - 1), 'label')
            self.put_keys(height - 1, [('Enter', 'Pick'), ('Esc', 'Done')])

        while True:
            height, width = self.screen.getmaxyx()
            draw()
            self.refresh()
            key = self.screen.getch()
            pick = False
            if key == curses.KEY_UP:
                choice = max(0, choice - 1)
            elif key == curses.KEY_DOWN:
                choice = min(len(names) - 1, choice + 1)
            elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
                options, current, _, _ = self.setting_options(names[choice])
                if options:
                    self.apply_setting(names[choice], cycle(options, current, 1 if key == curses.KEY_RIGHT else -1))
            elif key in (10, 13, curses.KEY_ENTER):
                pick = True
            elif key == curses.KEY_MOUSE:
                event = self.mouse_event()
                if event and event.kind == 'click':
                    click_x, click_y = event.x, event.y
                    row = next((i for i in range(len(names)) if self.setting_row(i) == click_y), None)
                    if row is not None:  # a setting: select it, then open its list
                        pick, choice = row == choice, row
                    elif click_y == height - 1:
                        if click_x >= len('Enter Pick  '):  # on Esc Done
                            break
                        pick = True
            elif key in (27, ord('q'), curses.KEY_F2, curses.KEY_F10):
                break
            if pick:
                options, current, _, describe = self.setting_options(names[choice])
                if options:
                    value = self.choose(self.setting_row(choice) + 1, 18, names[choice], options, current, describe,
                                        draw)
                    if value is not None:
                        self.apply_setting(names[choice], value)
        notices = []
        if self.recording[0] is not None and tuple(self.recording) != installed:
            interval, days = self.recording
            if os.geteuid() == 0:
                try:
                    configure_recording(interval, days)
                    notices.append(f'Recording every {interval} s, kept {days} days; the hmon service restarted.')
                except (OSError, subprocess.CalledProcessError) as error:
                    notices.append(f'Could not change the recording: {error}.')
            else:
                notices.append(f'To record every {interval} s and keep {days} days, run: '
                               f'sudo hmon configure --interval {interval} --retention {days}')
        try:
            save_settings(self.settings())
            notices.append(f'Settings saved to {CONFIG_PATH}.')
        except OSError as error:
            notices.append(f'Could not save the settings: {error}.')
        self.notice = '  '.join(notices)
        self.blocking(False)

    def pick_sort(self):
        """htop's Sort by panel."""
        options = list(SORT_COLUMNS)
        choice = options.index(self.sort_key)
        self.blocking(True)
        while True:
            height, width = self.screen.getmaxyx()
            self.put(self.table_top, 0, ' Sort by'.ljust(14), 'header')
            for i, option in enumerate(options):
                self.put(self.table_top + 1 + i, 0, f' {option}'.ljust(14), 'selected' if i == choice else 'normal')
            self.put(height - 1, 0, ' ' * (width - 1), 'label')
            self.put_keys(height - 1, [('Enter', 'Sort'), ('Esc', 'Cancel')])
            self.refresh()
            key = self.screen.getch()
            if key == curses.KEY_UP:
                choice = max(0, choice - 1)
            elif key == curses.KEY_DOWN:
                choice = min(len(options) - 1, choice + 1)
            elif key == curses.KEY_MOUSE:
                event = self.mouse_event()
                if not event or event.kind != 'click':
                    continue  # a press, a drag, or the wheel
                row = event.y - self.table_top - 1
                if 0 <= row < len(options):
                    self.set_sort(options[row])
                break
            elif key in (10, 13, curses.KEY_ENTER):
                self.set_sort(options[choice])
                break
            elif key in (27, ord('q')):
                break
        self.blocking(False)

    def go_to(self):
        height = self.screen.getmaxyx()[0]
        text = self.ask(height - 1, f' Go to (e.g. 12/10/2026 14:30 IST, or 14:30 on {label(self.cursor, "%d %b")}): ')
        if not text:
            return
        moment = parse_time(text, self.cursor)
        if moment is None:
            self.notice = f'Could not read "{text}"; try 12/10/2026 14:30 IST, 2 Feb 2025 UTC or 14:30'
            return
        self.cursor = self.view_end = moment
        if self.store.times[0] <= moment <= self.store.times[-1]:
            self.notice = f'Went to {label(moment, "%d %b %Y %H:%M %Z")}'
        else:
            self.notice = f'No data at {label(moment, "%d %b %Y %H:%M %Z")}; showing the nearest end of the recording'

    # ---- keys

    def set_sort(self, column):
        self.sort_key, self.descending = column, SORT_COLUMNS[column]
        if column in ('RES', 'MEM%'):
            self.metric = 'Memory'
        elif column == 'CPU%':
            self.metric = 'CPU'

    def set_metric(self, metric):
        self.metric = metric
        if self.metric in ('Memory', 'CPU'):
            self.sort_key = 'MEM%' if self.metric == 'Memory' else 'CPU%'
            self.descending = True

    def set_zoom(self, step):
        level = min(max(ZOOM_LEVELS.index(self.zoom) + step, 0), len(ZOOM_LEVELS) - 1)
        self.zoom = ZOOM_LEVELS[level]
        self.cursor = self.align(self.cursor)
        self.view_end = max(self.cursor, min(self.cursor + self.graph_w // 2 * self.zoom,
                                             self.align(self.store.times[-1])))

    def move_selection(self, delta):
        self.index += delta
        self.selected = None

    def fold(self, unfold=None):
        """+ unfolds, - folds, Enter toggles the selected row; on a process with nothing under it, - and Enter fold
        the app or container around it."""
        if not self.tree or not self.rows:
            return
        row = self.rows[self.index]
        if row.has_children:
            key, is_open = row.key, row.is_open
        elif row.group and unfold is not True:
            key, is_open = row.group, True
        else:
            return
        if (not is_open if unfold is None else unfold) != is_open:
            self.toggled ^= {key}  # toggled holds the rows flipped from their default
        self.selected = key

    def toggle_all(self):
        if self.group_keys & self.toggled:
            self.toggled -= self.group_keys
            if self.tree and self.rows:
                self.selected = ('app', self.rows[self.index].app)  # its row stays visible once everything folds
        else:
            self.toggled |= self.group_keys

    def find(self, direction, start):
        for step in range(len(self.rows)):
            i = (start + direction * step) % len(self.rows)
            if matches(self.search, self.rows[i].label):
                self.index, self.selected, self.search_failed = i, None, False
                return
        self.search_failed = bool(self.search)

    # ---- mouse: clicks act on release, drags select text

    def mouse_event(self):
        """A finished click or a wheel turn as a MouseEvent, else None. A click is a press and a release on the same
        cell, acted on at the release. A press dragged to another cell selects text instead, highlighted as it goes
        and copied at the release, and never clicks anything."""
        try:
            _, x, y, _, state = curses.getmouse()
        except curses.error:
            return None
        if state & curses.BUTTON4_PRESSED:
            return MouseEvent('wheel', x, y, -1)
        if state & getattr(curses, 'BUTTON5_PRESSED', 0):  # missing from older ncurses builds
            return MouseEvent('wheel', x, y, 1)
        if state & curses.REPORT_MOUSE_POSITION:
            if not self.pressed_at and not hasattr(curses, 'BUTTON5_PRESSED'):
                return MouseEvent('wheel', x, y, 1)  # how ncurses' old mouse ABI (no button 5) reports the wheel down
            if self.pressed_at:
                old = set(self.selection(self.pressed_at, self.dragged_to)) if self.dragged_to else set()
                self.dragged_to = (x, y)
                new = set(self.selection(self.pressed_at, self.dragged_to))
                self.paint(old - new, 0)  # only the cells that changed, so a long drag keeps up with the mouse
                self.paint(new - old, curses.A_REVERSE)
                self.screen.refresh()
            return None
        if state & curses.BUTTON1_PRESSED:
            self.pressed_at, self.dragged_to = (x, y), None
            return None
        if state & curses.BUTTON1_RELEASED:
            start, dragged = self.pressed_at, self.dragged_to
            self.pressed_at = self.dragged_to = None
            if dragged:
                self.paint(self.selection(start, dragged), 0)
            if start and start != (x, y):
                if self.on_graph(start):
                    self.anchor, self.cursor = self.bar_at(start[0]), self.bar_at(x)
                else:
                    self.copy_text(self.selection(start, (x, y)))
                return None
            return MouseEvent('click', x, y, 0)
        if state & curses.BUTTON1_CLICKED:
            return MouseEvent('click', x, y, 0)
        return None

    def selection(self, start, end):
        """The cells from one (x, y) to another in reading order, line by line as a terminal selects text."""
        if self.on_graph(start):  # a drag that starts on the graph picks bars: whole columns of it, not text
            top, axis, starts = self.graph_area
            x0, x1 = sorted(min(max(x, 6), 5 + len(starts)) for x in (start[0], end[0]))
            return [(y, x) for y in range(top, axis + 1) for x in range(x0, x1 + 1)]
        (x0, y0), (x1, y1) = sorted([start, end], key=lambda cell: (cell[1], cell[0]))
        last = self.screen.getmaxyx()[1] - 2  # put() never writes the last column
        return [(y, x) for y in range(y0, y1 + 1)
                for x in range(x0 if y == y0 else 0, min(x1 if y == y1 else last, last) + 1)]

    def on_graph(self, cell):
        if self.graph_area is None:
            return False
        top, axis, starts = self.graph_area
        return top <= cell[1] <= axis and 6 <= cell[0] < 6 + len(starts)

    def bar_at(self, x):
        """The start of the graph's bar in screen column `x`, or of the nearest one at either end."""
        starts = self.graph_area[2]
        return starts[min(max(x - 6, 0), len(starts) - 1)]

    def paint(self, cells, attr):
        """Redraws `cells` as they were put, with `attr` added: A_REVERSE shows a selection, 0 takes it down."""
        for y, x in cells:
            char, style = self.shown.get((y, x), (' ', 'normal'))
            try:
                self.screen.addstr(y, x, char, self.styles[style] | attr)
            except curses.error:
                pass  # off a screen made smaller mid-drag

    def copy_text(self, cells):
        """Puts the text in `cells` on the clipboard through the terminal's OSC 52 escape, which iTerm2 (with
        "Applications in terminal may access clipboard"), kitty, WezTerm, Alacritty, Windows Terminal and tmux (with
        set-clipboard on) honour. Others ignore it, so the notice names the ways that always work."""
        text = '\n'.join(''.join(self.shown.get(cell, ' ')[0] for cell in row).rstrip()
                         for _, row in groupby(cells, key=lambda cell: cell[0])).strip('\n')
        if not text.strip():
            return
        sys.stdout.write(f'\033]52;c;{base64.b64encode(text.encode()).decode()}\a')
        sys.stdout.flush()
        preview = ' '.join(text.split())
        preview = preview if len(preview) <= 30 else preview[:29] + '…'
        self.notice = f'Copied "{preview}". Not pasting? Turn Mouse off in F2, or hold Shift (Option in iTerm2) to drag.'

    def click(self):
        """A click runs whatever was drawn under it; the wheel scrolls the table, or moves in time over the graph.
        Returns False to quit (a click on F10)."""
        event = self.mouse_event()
        self.held = not event and self.pressed_at is not None  # a press or a drag in the main view
        if not event:
            return True
        if event.kind == 'wheel':
            if event.y >= self.row_top:
                self.move_selection(3 * event.step)
            else:
                self.cursor += event.step * self.zoom
            return True
        for y0, y1, x0, x1, action in self.regions:
            if y0 <= event.y <= y1 and x0 <= event.x < x1:
                return action(event.x, event.y) is not False
        return True

    def press(self, key):
        """A function-bar click: the same as pressing its key."""
        if self.mode:
            self.edit(key)
            return True
        return self.handle(key)

    def click_bar(self, start):
        self.cursor, self.anchor = start, None

    def click_bar_title(self, start):
        self.cursor = start

    def click_header(self, column):
        if column == self.sort_key:
            self.descending = not self.descending
        else:
            self.set_sort(column)

    def click_row(self, x, y):
        """Select the row; a click on its fold marker, or on an already selected app, folds or unfolds it."""
        index = self.scroll + y - self.row_top
        if index >= len(self.rows):
            return
        row = self.rows[index]
        on_marker = self.tree_x <= x < self.tree_x + len(row.tree)
        if row.has_children and (on_marker or index == self.index):
            self.index = index
            self.fold()
        else:
            self.index, self.selected = index, None

    def edit(self, key):
        """Typing into the search or filter bar, as in htop's IncSet."""
        if key == curses.KEY_MOUSE:
            self.click()
            return
        if key == 27:  # Esc
            if self.mode == 'filter':
                self.filter = ''
            self.mode = None
        elif key in (10, 13, curses.KEY_ENTER):
            self.mode = None
        elif self.mode == 'search' and key in (curses.KEY_F3, curses.KEY_F15):
            step = 1 if key == curses.KEY_F3 else -1
            self.find(step, self.index + step)
        elif key in (curses.KEY_BACKSPACE, 127, 8) or 32 <= key < 127:
            text = self.search if self.mode == 'search' else self.filter
            text = text[:-1] if key in (curses.KEY_BACKSPACE, 127, 8) else text + chr(key)
            if self.mode == 'search':
                self.search = text
                self.find(1, 0)
            else:
                self.filter = text
        if self.mode is None:
            self.show_cursor(0)

    def handle(self, key):
        """Returns False to quit. htop's keys for the table; keys htop leaves free move through time."""
        char = chr(key) if 0 <= key < 256 else ''
        if char in ('q', 'Q') or key == curses.KEY_F10:
            return False
        if key == curses.KEY_F1 or char in ('h', '?'):
            self.show_help()
        elif key == curses.KEY_F2:
            self.setup()
        elif key == curses.KEY_F3 or char == '/':
            self.mode, self.search, self.search_failed = 'search', '', False
        elif key == curses.KEY_F4 or char == '\\':
            self.mode = 'filter'
        elif key == curses.KEY_F5 or char == 't':
            self.tree = not self.tree
        elif key == curses.KEY_F6 or char in ('<', '>', ',', '.'):
            self.pick_sort()
        elif char in ('M', 'P', 'N'):
            self.set_sort({'M': 'MEM%', 'P': 'CPU%', 'N': 'PID'}[char])
        elif char == 'I':
            self.descending = not self.descending
        elif char == '\t' or key == curses.KEY_BTAB:  # Shift+Tab goes the other way
            self.set_metric(cycle(METRICS, self.metric, 1 if char == '\t' else -1))
        elif key == curses.KEY_MOUSE:
            return self.click()
        elif char == 's':
            self.statistic = cycle(STATISTICS, self.statistic, 1)
        elif key == curses.KEY_LEFT:
            self.cursor -= self.zoom
        elif key == curses.KEY_RIGHT:
            self.cursor += self.zoom
        elif key == curses.KEY_SLEFT:
            self.cursor -= self.graph_w * self.zoom
        elif key == curses.KEY_SRIGHT:
            self.cursor += self.graph_w * self.zoom
        elif char in ('^', '\x01'):
            self.cursor = self.store.times[0]
        elif char in ('$', '\x05'):
            self.cursor = self.store.times[-1]
        elif char == ' ':  # a range of bars from here, which the marker's moves stretch
            self.anchor = None if self.anchor is not None else self.cursor
        elif key == 27:
            self.anchor = None
        elif char == 'g':
            self.go_to()
        elif char in ('[', ']'):
            self.set_zoom(1 if char == '[' else -1)
        elif key == curses.KEY_UP:
            self.move_selection(-1)
        elif key == curses.KEY_DOWN:
            self.move_selection(1)
        elif key == curses.KEY_PPAGE:
            self.move_selection(-self.page)
        elif key == curses.KEY_NPAGE:
            self.move_selection(self.page)
        elif key == curses.KEY_HOME:
            self.move_selection(-len(self.rows))
        elif key == curses.KEY_END:
            self.move_selection(len(self.rows))
        elif char in ('+', '='):
            self.fold(unfold=True)
        elif char == '-':
            self.fold(unfold=False)
        elif char in ('\n', '\r') or key == curses.KEY_ENTER:
            self.fold()
        elif char in ('*', 'c'):
            self.toggle_all()
        return True

    def check_for_update(self):
        newest = newest_release(timeout=10)
        self.update_available = bool(newest and is_newer(newest))

    def run(self):
        self.show_cursor(0)
        self.blocking(False)
        self.apply_mouse()
        self.tick()
        if VERSION != 'dev':  # a release asks GitHub once, in the background, whether there's a newer one
            threading.Thread(target=self.check_for_update, daemon=True).start()
        while True:
            if not self.held:  # mid-drag only the highlight changes, and mouse_event has painted it
                self.draw()
            self.held = False
            if self.mode:
                self.show_cursor(1)
                self.screen.move(self.screen.getmaxyx()[0] - 1, min(self.cursor_x, self.width - 2))
            key = self.screen.getch()
            if key != -1:
                self.notice = ''
            if key == -1:  # the refresh delay passed
                self.tick()
            elif self.mode:
                self.edit(key)
            elif not self.handle(key):
                return


# ---------------------------------------------------------------- dumps and queries

DUMP_MEMBER = re.compile(r'(host|containers|processes)_\d{4}-\d{2}-\d{2}\.csv|hmon-info\.txt')


def open_source(source):
    """A data directory, or a dump from `hmon export`, unpacked to a temporary directory removed at exit."""
    if not (os.path.isfile(source) and source.endswith(('.tar.gz', '.tgz'))):
        return source
    folder = tempfile.mkdtemp(prefix='hmon-dump-')
    atexit.register(shutil.rmtree, folder, True)
    with tarfile.open(source) as archive:
        for member in archive.getmembers():
            if member.isfile() and DUMP_MEMBER.fullmatch(member.name):  # plain names only, nothing outside folder
                with open(os.path.join(folder, member.name), 'wb') as f:
                    f.write(archive.extractfile(member).read())
    return folder


def files_in_range(csv_dir, kind, start, end):
    """(file name, path) for each CSV of `kind` whose day overlaps [start, end]."""
    for path in sorted(glob.glob(os.path.join(csv_dir, f'{kind}_*.csv'))):
        day_start = calendar.timegm(time.strptime(os.path.basename(path)[len(kind) + 1:-4], '%Y-%m-%d'))
        if day_start + 86400 > start and day_start <= end:
            yield os.path.basename(path), path


def rows_in_range(path, start, end):
    """The rows of one CSV sampled in [start, end], read one at a time; the header is skipped."""
    with open(path, newline='') as f:
        for row in islice(csv.reader(f), 1, None):
            if row and start <= to_second(row[0]) <= end:
                yield row


def write_dump(csv_dir, start, end, output):
    """A .tar.gz of the samples in [start, end], to open anywhere with `hmon FILE` or unpack for other tools.
    Rows stream through a temporary file per day, so memory stays flat whatever the range."""
    with tempfile.TemporaryDirectory() as folder, tarfile.open(output, 'w:gz') as archive:
        for kind in ('host', 'containers', 'processes'):
            for name, path in files_in_range(csv_dir, kind, start, end):
                copy, count = os.path.join(folder, name), 0
                with open(path, newline='') as source, open(copy, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(next(csv.reader(source), []))
                    for row in rows_in_range(path, start, end):
                        writer.writerow(row)
                        count += 1
                if count:
                    archive.add(copy, arcname=name)
                os.remove(copy)
        info = os.path.join(folder, 'hmon-info.txt')
        with open(info, 'w') as f:
            f.write(f'host: {socket.gethostname()}\nkernel: {os.uname().release}\nhmon: {VERSION}\n'
                    f'from: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(start))}\n'
                    f'to: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(end))}\n')
        archive.add(info, arcname='hmon-info.txt')


SCHEMA = '''
CREATE TABLE host (ts TEXT, time INTEGER, cpu_percent REAL, load_1m REAL, load_5m REAL, load_15m REAL,
                   mem_total INTEGER, mem_available INTEGER, mem_used INTEGER, swap_used INTEGER, swap_total INTEGER);
CREATE TABLE containers (ts TEXT, time INTEGER, container TEXT, cpu_percent REAL, mem INTEGER, mem_limit INTEGER,
                         net_rx INTEGER, net_tx INTEGER, block_read INTEGER, block_write INTEGER, pids INTEGER);
CREATE TABLE processes (ts TEXT, time INTEGER, pid INTEGER, ppid INTEGER, app TEXT, container TEXT, name TEXT,
                        rss INTEGER, cpu_percent REAL, command TEXT, cgroup TEXT);
CREATE INDEX processes_by_app ON processes (app, time);
CREATE INDEX processes_by_time ON processes (time);
'''


def to_sqlite(csv_dir, start, end, path):
    """The samples in [start, end] as SQLite tables host, containers and processes; each process row carries the
    app hmon groups it under, so `GROUP BY app` works."""
    def host_values(row):
        ts, cpu, load_1m, total, available, swap_used, load_5m, load_15m, swap_total = (row + [''] * 9)[:9]
        return (ts, to_second(ts), number(cpu), number(load_1m), number(load_5m), number(load_15m), int(total),
                int(available), int(total) - int(available), number(swap_used), number(swap_total))

    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA)
    for _, csv_path in files_in_range(csv_dir, 'host', start, end):
        connection.executemany('INSERT INTO host VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                               (host_values(row) for row in rows_in_range(csv_path, start, end)))
    for _, csv_path in files_in_range(csv_dir, 'containers', start, end):
        connection.executemany('INSERT INTO containers VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                               ((row[0], to_second(row[0]), row[1]) + tuple(number(v) for v in (row + [''] * 10)[2:10])
                                for row in rows_in_range(csv_path, start, end)))
    for _, csv_path in files_in_range(csv_dir, 'processes', start, end):
        for ts, sample in groupby(rows_in_range(csv_path, start, end), key=lambda row: row[0]):  # one sample at a time
            sample = list(sample)
            procs = [ProcRow(row[1], field(row, 7), row[2], row[3], row[6], field(row, 8), None, None) for row in sample]
            by_pid = {p.pid: p for p in procs}
            connection.executemany('INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                   [(ts, to_second(ts), int(row[1]), number(field(row, 7)), app_of(p, by_pid), row[2],
                                     row[3], number(row[4]), number(row[5]), row[6], field(row, 8))
                                    for row, p in zip(sample, procs)])
    connection.commit()
    return connection


def run_query(connection, query):
    """Prints a query's result as an aligned table."""
    cursor = connection.execute(query)
    names = [column[0] for column in cursor.description or []]
    rows = [['' if value is None else f'{value:g}' if isinstance(value, float) else str(value) for value in row]
            for row in cursor.fetchall()]
    widths = [max([len(name)] + [len(row[i]) for row in rows]) for i, name in enumerate(names)]
    print('  '.join(name.ljust(width) for name, width in zip(names, widths)).rstrip())
    for row in rows:
        print('  '.join(value.ljust(width) for value, width in zip(row, widths)).rstrip())


def check_readable(csv_dir):
    if os.path.isdir(csv_dir) and not os.access(csv_dir, os.R_OK | os.X_OK):
        sys.exit(f"{csv_dir} is readable by root only, because this host hides other users' processes in /proc "
                 '(hidepid). Run hmon with sudo, as htop needs root to see them too.')


# ---------------------------------------------------------------- updates

def newest_release(timeout):
    """The newest release's version, e.g. 0.2.5, or None when GitHub can't be reached."""
    try:
        with urllib.request.urlopen(f'https://api.github.com/repos/{REPO}/releases/latest', timeout=timeout) as reply:
            return json.load(reply)['tag_name'].lstrip('v')
    except Exception:  # offline, firewalled or rate limited: no news, and nothing to show for it
        return None


def is_newer(version):
    """Whether `version` is a later release than this one; a build from source is never behind."""
    try:
        return tuple(map(int, version.split('.'))) > tuple(map(int, VERSION.split('.')))
    except ValueError:
        return False


INSTALLED_FILES = ['/etc/systemd/system/hmon.service', '/etc/systemd/system/hmon-events.service', '/usr/local/bin/hmon',
                   '/etc/tmpfiles.d/hmon.conf', '/etc/systemd/journald.conf.d/hmon.conf']  # what install.sh puts in place


def as_root(command):
    """Runs `hmon COMMAND` again under sudo; it doesn't return."""
    try:
        os.execvp('sudo', ['sudo', sys.executable, os.path.abspath(sys.argv[0]), command])
    except OSError:
        sys.exit(f'sudo is missing here; run `hmon {command}` as root.')


def confirm(question):
    """A yes/no question at the terminal; anything but yes, or no terminal to answer from, is no."""
    try:
        return input(f'{question} [y/N] ').strip().lower() in ('y', 'yes')
    except EOFError:
        return False


def uninstall():
    """Stops and removes the hmon services, the command and the installer's system files; asks separately whether
    the recorded samples and the settings go too, each kept unless the answer is yes."""
    if os.geteuid() != 0:
        as_root('uninstall')
    configs = {os.path.dirname(CONFIG_PATH)}
    if os.environ.get('SUDO_USER'):  # the settings of whoever ran `hmon uninstall`, not just root's
        configs.add(os.path.join(os.path.expanduser('~' + os.environ['SUDO_USER']), '.config', 'hmon'))
    samples = [DATA_DIR] if os.path.exists(DATA_DIR) else []
    settings = [path for path in sorted(configs) if os.path.exists(path)]
    deleted = []
    if samples:
        size = sum(os.path.getsize(os.path.join(folder, name)) for folder, _, names in os.walk(DATA_DIR) for name in names)
        if confirm(f'Delete the recorded samples in {DATA_DIR} ({size / 1e6:.0f} MB)?'):
            deleted += samples
    if settings and confirm(f'Delete the settings in {", ".join(settings)}?'):
        deleted += settings
    for unit in ('hmon', 'hmon-events'):
        subprocess.run(['systemctl', 'disable', '--now', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in INSTALLED_FILES:
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)
    subprocess.run(['systemctl', 'daemon-reload'])
    for path in deleted:
        shutil.rmtree(path, ignore_errors=True)
    kept = [path for path in samples + settings if path not in deleted]
    print('hmon removed.' + (f' Deleted {", ".join(deleted)}.' if deleted else '') + (f' Kept {", ".join(kept)}.' if kept else ''))


def update():
    """Runs the newest release's installer, which keeps the sampling interval and retention already set. Says what
    it's doing before each step that waits on the network, so a slow one shows where it is."""
    print('Checking GitHub for a newer hmon...', flush=True)
    newest = newest_release(timeout=15)
    if newest is None:
        sys.exit(f'Could not reach GitHub to look up the newest release of {REPO}.')
    if not is_newer(newest):
        print(f'hmon {VERSION} is up to date.')
        return
    if os.geteuid() != 0:  # the installer replaces /usr/local/bin/hmon and restarts the service
        print(f'hmon {newest} is out (this is {VERSION}); updating needs sudo.', flush=True)
        as_root('update')
    url = f'https://github.com/{REPO}/releases/download/v{newest}/install.sh'
    print(f'Downloading the hmon {newest} installer...', flush=True)
    try:
        with urllib.request.urlopen(url, timeout=120) as reply:
            installer = reply.read()
    except OSError as error:
        sys.exit(f'Could not download {url}: {error}')
    print(f'Updating hmon {VERSION} to {newest}:', flush=True)
    sys.exit(subprocess.run(['bash'], input=installer).returncode)


def main(argv):
    parser = argparse.ArgumentParser(
        prog='hmon',
        usage='%(prog)s [options] [SOURCE]\n'
              '       %(prog)s [options] at "12/10/2026 14:30 IST" [SOURCE]\n'
              '       %(prog)s [options] export [--from TIME] [--to TIME] [-o FILE.tar.gz | --sqlite FILE.db] [SOURCE]\n'
              '       %(prog)s [options] sql "SELECT ..." [--from TIME] [--to TIME] [SOURCE]\n'
              '       %(prog)s configure [--interval SECONDS] [--retention DAYS]\n'
              '       %(prog)s update\n'
              '       %(prog)s uninstall\n'
              '       %(prog)s collect',
        description=f'hmon {VERSION} - htop for the past: what every app, container and process used, over time, '
                    'recorded by the hmon service and browsed here.',
        epilog=f'SOURCE is a data directory (default {DATA_DIR}) or a dump made by `hmon export`. export and sql '
               f'cover the last 24 hours unless --from/--to say otherwise. Inside hmon, F1 shows the keys and F2 the '
               f'settings ({CONFIG_PATH}).')
    parser.add_argument('-C', '--no-color', action='store_true', help='use a monochrome color scheme (also NO_COLOR)')
    parser.add_argument('-d', '--delay', type=int, metavar='DELAY', help='live refresh delay in tenths of seconds')
    parser.add_argument('-F', '--filter', default='', metavar='FILTER',
                        help="show only matching apps and processes ('|' separates terms)")
    parser.add_argument('-M', '--no-mouse', action='store_true', help='disable the mouse')
    parser.add_argument('-s', '--sort-key', metavar='COLUMN',
                        help="sort by COLUMN: PID, RES, CPU%% or MEM%%; 'help' lists them")
    parser.add_argument('-U', '--no-unicode', action='store_true', help='draw with plain ASCII')
    parser.add_argument('-V', '--version', action='version', version=f'hmon {VERSION}')
    parser.add_argument('--tz', metavar='ZONE', help='show and read times in ZONE, e.g. Asia/Kolkata, UTC or IST')
    parser.add_argument('--from', dest='start', metavar='TIME', help='export/sql: start, e.g. "12/10/2026 14:00 IST"')
    parser.add_argument('--to', dest='end', metavar='TIME', help='export/sql: end (default now)')
    parser.add_argument('-o', '--output', metavar='FILE', help='export: the .tar.gz dump to write')
    parser.add_argument('--sqlite', metavar='FILE', help='export: write a SQLite database instead of a dump')
    parser.add_argument('--interval', type=int, metavar='SECONDS', help='configure: seconds between samples (root)')
    parser.add_argument('--retention', type=int, metavar='DAYS', help='configure: days of samples to keep (root)')
    parser.add_argument('words', nargs='*', help=argparse.SUPPRESS)
    args = parser.parse_intermixed_args(argv)  # options may come before or after SOURCE

    settings = load_settings()
    if args.tz:
        if not valid_zone(args.tz):
            parser.error(f'unknown time zone "{args.tz}"; try Asia/Kolkata, UTC, IST or +05:30')
        settings['tz'] = args.tz
    if args.delay:
        settings['delay'] = str(max(1, args.delay))
    if args.sort_key:
        sort_key = {'MEM': 'MEM%', 'CPU': 'CPU%'}.get(args.sort_key.upper(), args.sort_key.upper())
        if sort_key == 'HELP':
            print('\n'.join(SORT_COLUMNS))
            return
        if sort_key not in SORT_COLUMNS:
            parser.error(f'invalid column "{args.sort_key}"; choose from {", ".join(SORT_COLUMNS)}')
        settings['sort'] = sort_key
    if settings['tz'] != 'system':
        os.environ['TZ'] = posix_zone(settings['tz'])
    time.tzset()

    def source(word):
        check_readable(word or DATA_DIR)
        return open_source(word or DATA_DIR)

    def time_range():
        end = parse_time(args.end) if args.end else int(time.time())
        start = parse_time(args.start) if args.start else end - 86400
        if start is None or end is None:
            parser.error('could not read --from/--to; try "12/10/2026 14:30 IST" or "2026-10-12 14:30"')
        return start, end

    words = args.words
    if words == ['collect']:
        collect()
    elif words == ['update']:
        update()
    elif words == ['uninstall']:
        uninstall()
    elif words == ['configure']:
        interval, days = recording()
        if interval is None:
            sys.exit('The hmon service is not installed here; run the installer first.')
        if args.interval is None and args.retention is None:
            print(f'Recording every {interval} s, kept {days} days.')
            return
        if any(value is not None and value < 1 for value in (args.interval, args.retention)):
            parser.error('--interval and --retention take a whole number above 0')
        if os.geteuid() != 0:
            sys.exit('Changing the recording rewrites the hmon service; run this with sudo.')
        configure_recording(args.interval or interval, args.retention or days)
        print(f'Recording every {args.interval or interval} s, kept {args.retention or days} days; '
              'the hmon service restarted.')
    elif words[:1] == ['at'] and len(words) in (2, 3):
        show_snapshot(words[1], source(field(words, 2)))
    elif words[:1] == ['export'] and len(words) <= 2:
        csv_dir, (start, end) = source(field(words, 1)), time_range()
        output = args.sqlite or args.output or f'hmon-{socket.gethostname()}-{time.strftime("%Y%m%d-%H%M")}.tar.gz'
        if os.path.exists(output):
            sys.exit(f'{output} already exists; choose another name with -o or --sqlite.')
        if args.sqlite:
            to_sqlite(csv_dir, start, end, output).close()
        else:
            write_dump(csv_dir, start, end, output)
        print(f'Wrote {output}: {label(start, "%Y-%m-%d %H:%M")} to {label(end, "%Y-%m-%d %H:%M %Z")}')
    elif words[:1] == ['sql'] and len(words) in (2, 3):
        csv_dir, (start, end) = source(field(words, 2)), time_range()
        handle, database = tempfile.mkstemp(prefix='hmon-', suffix='.db')  # on disk, so memory stays flat
        os.close(handle)
        atexit.register(os.remove, database)
        try:
            with contextlib.closing(to_sqlite(csv_dir, start, end, database)) as connection:
                run_query(connection, words[1])
        except sqlite3.Error as error:
            sys.exit(f'SQL error: {error}. Tables: host, containers, processes (see `hmon export --sqlite`).')
    elif len(words) <= 1 and words[:1] != ['at']:
        if curses is None:
            parser.error('the viewer needs the Python curses module; `hmon at TIME` works without it')
        csv_dir = source(field(words, 0))
        store = Store(csv_dir)
        if not store.times:
            sys.exit(f'No samples in {csv_dir} yet (the first one lands a minute after the service starts).')
        live = os.path.isdir('/proc/self') and os.path.realpath(csv_dir) == os.path.realpath(DATA_DIR)
        locale.setlocale(locale.LC_ALL, '')
        os.environ.setdefault('ESCDELAY', '25')
        use_color = not (args.no_color or os.environ.get('NO_COLOR'))
        unicode = not args.no_unicode and locale.getpreferredencoding(False).lower().replace('-', '') == 'utf8'
        try:
            curses.wrapper(lambda screen: Viewer(screen, store, settings, LiveSampler(store) if live else None,
                                                 use_color, unicode, args.filter, not args.no_mouse).run())
        finally:
            sys.stdout.write('\033[?1002l')  # drag reports off, should the terminal keep them past ncurses' reset
            sys.stdout.flush()
    else:
        parser.error('expected SOURCE, at TIME [SOURCE], export [SOURCE], sql QUERY [SOURCE], or collect')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(130)  # Ctrl+C: quit quietly, with the shell's usual status for SIGINT
