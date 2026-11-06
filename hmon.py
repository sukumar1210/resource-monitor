#!/usr/bin/env python3
"""hmon: records host, container and process resource usage every minute, and lets you browse it afterwards.

usage:
  hmon [--tz ZONE] [CSV_DIR]                        interactive viewer: usage over time, every process at the marker
  hmon [--tz ZONE] at "YYYY-MM-DD HH:MM" [CSV_DIR]  print the snapshot nearest to that time
  hmon collect                                      sample every minute into daily CSVs (what the hmon service runs)

Times are shown and read in the system time zone, or ZONE (e.g. Asia/Kolkata) from --tz or the TZ variable.
"""
import calendar
import csv
import glob
import locale
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict, namedtuple
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from itertools import islice
from statistics import mean

try:
    import curses
except ImportError:  # some minimal Python builds; only the viewer needs it
    curses = None

VERSION = 'dev'  # set from the git tag by the release workflow
DATA_DIR = os.environ.get('HMON_DATA_DIR', '/var/lib/hmon')
INTERVAL_SECONDS = 60
CLOCK_TICKS = os.sysconf('SC_CLK_TCK')
PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
SIZE_UNITS = {'B': 1, 'kB': 10**3, 'KB': 10**3, 'MB': 10**6, 'GB': 10**9, 'TB': 10**12,
              'KiB': 2**10, 'MiB': 2**20, 'GiB': 2**30, 'TiB': 2**40}
CONTAINER_ID = re.compile(r'[0-9a-f]{64}')
# Credentials masked in command lines before they're stored. Pattern-based, so it misses forms like mysql's
# -pSECRET; the data directory is root-only for that reason.
SECRETS = [
    (re.compile(r'(\w+://[^:@/\s]+:)[^@\s]+@'), r'\1***@'),                                      # scheme://user:PASSWORD@host
    (re.compile(r'(?i)((?:pass|pwd|secret|token|key|auth)[\w-]*=)[^\s&]+'), r'\1***'),            # password=X, ?token=X
    (re.compile(r'(?i)(-[\w-]*(?:pass|pwd|secret|token|key|auth)[\w-]*\s+)[^\s-]\S*'), r'\1***'),  # --password X
]
TREND_MINUTES = 30
BLOCKS = '▁▂▃▄▅▆▇█'
ZOOM_LEVELS = [1, 5, 15, 60]  # minutes per graph column
LABEL_MINUTES = {1: 10, 5: 60, 15: 240, 60: 720}  # time-axis label spacing per zoom

# Columns are only ever added at the end, and readers take the columns they know by position, so files written
# before and after an update stay readable.
HOST_FIELDS = ['ts', 'cpu_percent', 'load_1m', 'mem_total_bytes', 'mem_available_bytes', 'swap_used_bytes']
CONTAINER_FIELDS = ['ts', 'container', 'cpu_percent', 'mem_bytes', 'mem_limit_bytes', 'net_rx_bytes',
                    'net_tx_bytes', 'block_read_bytes', 'block_write_bytes', 'pids']
PROCESS_FIELDS = ['ts', 'pid', 'container', 'name', 'rss_bytes', 'cpu_percent', 'cmdline']

Process = namedtuple('Process', 'name rss_bytes cpu_ticks')


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
        load_1m = float(f.read().split()[0])
    row = [ts, cpu_percent, load_1m, mem['MemTotal'], mem['MemAvailable'], mem['SwapTotal'] - mem['SwapFree']]
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
                     to_bytes(block_read), to_bytes(block_write), pids if pids.isdigit() else None])
    return rows, names


def sample_processes(ts, prev, container_names):
    """Every process using memory or CPU, biggest first, tagged with its container ('' = not in one)."""
    procs = {}  # keyed by (pid, start_time) so a reused pid doesn't inherit the old process's CPU
    for pid in filter(str.isdigit, os.listdir('/proc')):
        stat = read_text(f'/proc/{pid}/stat')
        if not stat:
            continue
        # "pid (name) state ...": the name can contain spaces or ')', so split after the last ')'
        name = stat[stat.index('(') + 1:stat.rindex(')')]
        fields = stat[stat.rindex(')') + 2:].split()
        utime, stime, start_time, rss_pages = fields[11], fields[12], fields[19], fields[21]  # stat fields 14, 15, 22, 24
        procs[(int(pid), start_time)] = Process(name, int(rss_pages) * PAGE_SIZE, int(utime) + int(stime))
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
        match = CONTAINER_ID.search(read_text(f'/proc/{pid}/cgroup'))
        container = container_names.get(match.group(0), match.group(0)[:12]) if match else ''
        cmdline = read_text(f'/proc/{pid}/cmdline').replace('\0', ' ').strip()
        for pattern, replacement in SECRETS:
            cmdline = pattern.sub(replacement, cmdline)
        rows.append([ts, pid, container, proc.name, proc.rss_bytes, cpu_percent.get(key), cmdline[:200]])
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
    os.umask(0o077)  # samples include command lines, so only root reads them
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


# ---------------------------------------------------------------- reading
# Files and timestamps are UTC; everything shown or typed is in the display time zone (TZ).

def gib(value):
    return '-' if value in (None, '') else f'{float(value) / 2**30:.2f} GiB'


def pct(value):
    return '-' if value in (None, '') else f'{float(value):.1f}%'


def label(minute, fmt):
    """Minutes since the epoch -> text in the display time zone."""
    return time.strftime(fmt, time.localtime(minute * 60))


def utc_day(minute):
    return time.strftime('%Y-%m-%d', time.gmtime(minute * 60))


@lru_cache(maxsize=None)
def to_minute(ts):
    """'2026-11-06T03:14:27Z' -> minutes since the epoch."""
    return calendar.timegm(time.strptime(ts[:16], '%Y-%m-%dT%H:%M')) // 60


def parse_time(text, around=None):
    """'YYYY-MM-DD HH:MM', or 'HH:MM' on the date of minute `around`, in the display time zone, or with an offset
    like '+05:30' -> minutes since the epoch; None if unreadable."""
    try:
        moment = datetime.fromisoformat(text.strip().replace(' ', 'T').replace('Z', '+00:00'))
        if moment.tzinfo:
            return int(moment.timestamp()) // 60
        return int(time.mktime(moment.timetuple())) // 60
    except ValueError:
        pass
    try:
        clock = time.strptime(text.strip(), '%H:%M')
    except ValueError:
        return None
    day = time.localtime((around or 0) * 60)
    return int(time.mktime((day.tm_year, day.tm_mon, day.tm_mday, clock.tm_hour, clock.tm_min, 0, 0, 0, -1))) // 60


def show_snapshot(at, csv_dir=DATA_DIR):
    """Prints usage at the sample nearest to `at`, with a trend for the minutes before it."""
    target_minute = parse_time(at)
    if target_minute is None:
        sys.exit(f'Could not read the time "{at}"; use "YYYY-MM-DD HH:MM".')
    target = datetime.fromtimestamp(target_minute * 60, timezone.utc).replace(tzinfo=None)  # naive UTC, like ts
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
        sys.exit(f'No samples around {label(target_minute, "%Y-%m-%d %H:%M %Z")} in {csv_dir}')
    host = min(hosts, key=lambda row: abs(datetime.fromisoformat(row['ts'].rstrip('Z')) - target))
    ts = host['ts']
    end = datetime.fromisoformat(ts.rstrip('Z'))
    minutes = [f'{end - timedelta(minutes=m):%Y-%m-%dT%H:%M}' for m in reversed(range(TREND_MINUTES))]
    window = set(minutes)
    containers = read('containers', lambda row: row['ts'][:16] in window)
    processes = read('processes', lambda row: row['ts'][:16] in window)

    def trends(rows, key, field):
        """{key(row): sparkline of `field` per minute}, all keys on one scale; blank = no sample that minute."""
        series = {}
        for row in rows:
            if row['ts'][:16] in window and row[field]:
                series.setdefault(key(row), {})[row['ts'][:16]] = float(row[field])
        top = max((value for values in series.values() for value in values.values()), default=0) or 1
        return {k: ''.join(BLOCKS[min(7, int(values[m] / top * 8))] if m in values else ' ' for m in minutes)
                for k, values in series.items()}

    host_cpu = trends(hosts, lambda r: 'host', 'cpu_percent').get('host', '')
    host_mem = trends(hosts, lambda r: 'host', 'mem_available_bytes').get('host', '')
    container_mem = trends(containers, lambda r: r['container'], 'mem_bytes')
    process_mem = trends(processes, lambda r: r['pid'], 'rss_bytes')
    used = 100 * (1 - int(host['mem_available_bytes']) / int(host['mem_total_bytes']))
    sample_time = calendar.timegm(end.timetuple())

    away = abs(end - target).total_seconds()
    print(f'Snapshot {time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(sample_time))}  '
          f'({away:.0f}s from {label(target_minute, "%H:%M")})   trends: last {TREND_MINUTES} min, oldest -> newest\n')
    print(f"host  cpu {pct(host['cpu_percent']):>9}  {host_cpu}   load {host['load_1m']}")
    print(f"      available {gib(host['mem_available_bytes']):>9}  {host_mem}   "
          f"of {gib(host['mem_total_bytes'])} ({pct(used)} used)   swap used {gib(host['swap_used_bytes'])}\n")

    print(f"{'container':<20}{'cpu':>9}{'memory':>12}{'limit':>12}{'pids':>6}  memory trend")
    for row in sorted((r for r in containers if r['ts'] == ts), key=lambda r: -int(r['mem_bytes'] or 0)):
        print(f"{row['container']:<20}{pct(row['cpu_percent']):>9}{gib(row['mem_bytes']):>12}"
              f"{gib(row['mem_limit_bytes']):>12}{row['pids'] or '-':>6}  {container_mem.get(row['container'], '')}")

    print(f"\n{'pid':<8}{'container':<20}{'memory':>12}{'cpu':>9}  {'memory trend':<{TREND_MINUTES}}  command")
    for row in sorted((r for r in processes if r['ts'] == ts), key=lambda r: -int(r['rss_bytes'] or 0)):
        print(f"{row['pid']:<8}{row['container'] or 'host':<20}{gib(row['rss_bytes']):>12}{pct(row['cpu_percent']):>9}  "
              f"{process_mem.get(row['pid'], ''):<{TREND_MINUTES}}  {row['cmdline'] or '[' + row['name'] + ']'}")


def load_host(csv_dir):
    """{minute: (memory used %, cpu % or None, load, swap used bytes, memory total bytes)} for every host sample."""
    host = {}
    for path in sorted(glob.glob(os.path.join(csv_dir, 'host_*.csv'))):
        with open(path, newline='') as f:
            for row in islice(csv.reader(f), 1, None):
                ts, cpu, load, total, available, swap = row[:6]
                host[to_minute(ts)] = (100 * (1 - int(available) / int(total)), float(cpu) if cpu else None,
                                       float(load), int(swap), int(total))
    return host


@lru_cache(maxsize=4)
def load_day(csv_dir, kind, day):
    """{minute: rows} for one UTC day's containers or processes CSV; strings are interned and a few days cached."""
    by_minute = defaultdict(list)
    path = os.path.join(csv_dir, f'{kind}_{day}.csv')
    if os.path.exists(path):
        with open(path, newline='') as f:
            for row in islice(csv.reader(f), 1, None):
                by_minute[to_minute(row[0])].append(tuple(sys.intern(value) for value in row))
    return by_minute


def rows_in(csv_dir, kind, start, zoom):
    """Rows of one graph column; a column can span two UTC days when the display zone isn't UTC."""
    return [row for m in range(start, start + zoom) for row in load_day(csv_dir, kind, utc_day(m)).get(m, ())]


def host_average(host, start, zoom):
    """(memory used %, cpu %, load, swap used, memory total) averaged over one graph column, or None without samples."""
    samples = [host[m] for m in range(start, start + zoom) if m in host]
    if not samples:
        return None
    cpus = [s[1] for s in samples if s[1] is not None]
    return (mean(s[0] for s in samples), mean(cpus) if cpus else None,
            mean(s[2] for s in samples), mean(s[3] for s in samples), mean(s[4] for s in samples))


def average_by(rows, key, mem_col, cpu_col):
    """{key(row): (avg memory bytes, avg cpu %)}; a missing value is skipped rather than counted as zero."""
    memory, cpu = defaultdict(list), defaultdict(list)
    for row in rows:
        if row[mem_col]:
            memory[key(row)].append(int(row[mem_col]))
        if row[cpu_col]:
            cpu[key(row)].append(float(row[cpu_col]))
    return {k: (mean(memory[k]) if memory[k] else None, mean(cpu[k]) if cpu[k] else None)
            for k in set(memory) | set(cpu)}


def table_lines(csv_dir, start, zoom, metric, total, collapsed, glyphs):
    """htop-style rows averaged over one graph column: processes outside containers, and each container as a group.

    Returns [(text, is_container_row)], biggest first by `metric` (0 = memory, 1 = cpu).
    """
    open_mark, closed_mark, branch, last_branch = glyphs
    container_rows = rows_in(csv_dir, 'containers', start, zoom)
    container_usage = average_by(container_rows, lambda r: r[1], mem_col=3, cpu_col=2)
    container_pids = {r[1]: r[9] for r in container_rows}
    members = defaultdict(list)  # container name ('' = not in a container) -> [(pid, command, mem, cpu)]
    process_usage = average_by(rows_in(csv_dir, 'processes', start, zoom),
                               lambda r: (r[2], r[1], r[6] or f'[{r[3]}]'), mem_col=4, cpu_col=5)
    for (container, pid, command), (mem, cpu) in process_usage.items():
        members[container].append((pid, command, mem, cpu))

    def size(mem, cpu):
        return (mem, cpu)[metric] or 0

    def line(pid, cpu, mem, command):
        share = f'{100 * mem / total:.1f}%' if mem and total else '-'
        return f'{pid:>7} {pct(cpu):>7} {gib(mem):>10} {share:>6}  {command}'

    # (size, pid, command, mem, cpu, member processes or None for a process outside any container)
    entries = [(size(mem, cpu), pid, command, mem, cpu, None) for pid, command, mem, cpu in members.pop('', [])]
    for name in set(members) | set(container_usage):
        procs = sorted(members.get(name, []), key=lambda p: -size(p[2], p[3]))
        mem, cpu = container_usage.get(name) or (sum(p[2] or 0 for p in procs), sum(p[3] or 0 for p in procs))
        entries.append((size(mem, cpu), '', name, mem, cpu, procs))

    lines = []
    for _, pid, command, mem, cpu, procs in sorted(entries, key=lambda entry: -entry[0]):
        if procs is None:
            lines.append((line(pid, cpu, mem, command), False))
            continue
        pids = container_pids.get(command) or '?'
        mark = closed_mark if collapsed else open_mark
        lines.append((line('', cpu, mem, f'{mark} {command}  (container, {pids} pids)'), True))
        if not collapsed:
            for i, (child_pid, child_command, child_mem, child_cpu) in enumerate(procs):
                tree = last_branch if i == len(procs) - 1 else branch
                lines.append((line(child_pid, child_cpu, child_mem, f'  {tree} {child_command}'), False))
    return lines


def view(stdscr, csv_dir, host):
    """Host memory or CPU over time with a marker moved by the arrow keys, and every process at the marker below."""
    def show_cursor(visible):
        try:
            curses.curs_set(visible)
        except curses.error:  # terminals without cursor control
            pass

    show_cursor(0)
    has_colors = curses.has_colors()
    if has_colors:
        try:
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
        except curses.error:
            has_colors = False
    bar_attr = curses.color_pair(1) if has_colors else 0
    marker_attr = (curses.color_pair(2) if has_colors else 0) | curses.A_BOLD
    unicode = locale.getpreferredencoding(False).lower().replace('-', '') == 'utf8'
    bars = BLOCKS if unicode else '.:-=+*#@'
    vline, hline, corner, marker = ('│', '─', '└', '▲') if unicode else ('|', '-', '+', '^')
    glyphs = ('▾', '▸', '├─', '└─') if unicode else ('-', '+', '|-', '`-')

    first, last = min(host), max(host)
    # Columns and labels follow the display zone's clock. ponytail: uses today's UTC offset, so across a DST change
    # older 60-minute columns sit an hour off the clock.
    shift = time.localtime(last * 60).tm_gmtoff // 60
    tab, zoom, scroll, collapsed, notice = 0, 1, 0, False, ''  # tab 0 = memory, 1 = cpu
    cursor = view_end = last

    def align(minute):
        return (minute + shift) // zoom * zoom - shift

    def put(y, x, text, attr=0):
        if 0 <= y < height and 0 <= x < width - 1:  # curses errors on the bottom-right cell
            stdscr.addstr(y, x, text[:width - 1 - x], attr)

    def prompt(question):
        put(height - 1, 0, question.ljust(width - 1), curses.A_REVERSE)
        curses.echo()
        show_cursor(1)
        try:
            return stdscr.getstr(height - 1, len(question), 40).decode(errors='replace')
        finally:
            curses.noecho()
            show_cursor(0)
            stdscr.clear()  # repaint everything next time, so nothing echoed while typing lingers

    while True:
        height, width = stdscr.getmaxyx()
        graph_h, graph_w = max(4, (height - 9) // 2), max(10, width - 6)
        cursor = min(max(align(cursor), align(first)), align(last))
        view_end = min(max(view_end, cursor), cursor + (graph_w - 1) * zoom)  # keep the marker on screen

        stdscr.erase()
        tabs = '  '.join(f'[{name}]' if i == tab else f' {name} ' for i, name in enumerate(('Memory', 'CPU')))
        put(0, 0, f' hmon   {tabs}   {zoom} min/column   times in {label(cursor, "%Z")}', curses.A_BOLD)

        axis_row = 1 + graph_h
        put(1, 0, '100%')
        put(1 + graph_h // 2, 0, ' 50%')
        put(axis_row, 0, '  0%' + corner + hline * graph_w)
        for row in range(1, axis_row):
            put(row, 4, vline)
        time_format = '%H:%M' if zoom < 15 else '%m-%d %H:%M'
        for col in range(graph_w):
            start = view_end - (graph_w - 1 - col) * zoom
            average = host_average(host, start, zoom)
            value = average[tab] if average else None
            eighths = round(min(value, 100) / 100 * graph_h * 8) if value is not None else 0
            is_marker = start == cursor
            for row in range(graph_h):
                filled = eighths - (graph_h - 1 - row) * 8
                char = bars[7] if filled >= 8 else bars[filled - 1] if filled > 0 else (vline if is_marker else ' ')
                put(1 + row, 5 + col, char, marker_attr if is_marker else bar_attr)
            if is_marker:
                put(axis_row, 5 + col, marker, marker_attr)
            if (start + shift) % LABEL_MINUTES[zoom] == 0:
                put(axis_row + 1, 5 + col, label(start, time_format))

        average = host_average(host, cursor, zoom)
        span = label(cursor, '%Y-%m-%d %H:%M') + (f"-{label(cursor + zoom - 1, '%H:%M')}" if zoom > 1 else '')
        span += label(cursor, ' %Z')
        if average:
            info = (f'{span}   memory used {average[0]:.1f}% of {gib(average[4])}   cpu {pct(average[1])}   '
                    f'load {average[2]:.1f}   swap used {gib(average[3])}')
        else:
            info = f'{span}   no samples (host down or not collecting)'
        put(axis_row + 2, 1, info, curses.A_BOLD)

        lines = table_lines(csv_dir, cursor, zoom, tab, average[4] if average else None, collapsed, glyphs)
        table_row = axis_row + 4
        visible = max(0, height - table_row - 2)
        scroll = min(max(scroll, 0), max(0, len(lines) - visible))
        sort_name = ('MEM', 'CPU%')[tab]
        header = f"{'PID':>7} {'CPU%':>7} {'MEM':>10} {'MEM%':>6}  COMMAND   (average over the column, by {sort_name})"
        put(table_row, 0, header.ljust(width - 1), curses.A_REVERSE)
        for i, (text, is_container) in enumerate(lines[scroll:scroll + visible]):
            put(table_row + 1 + i, 0, text, curses.A_BOLD if is_container else 0)
        put(height - 1, 0, notice or ' left/right time  g go to  up/down scroll  PgUp/PgDn  Home/End  +/- zoom  '
                                     'Tab mem/cpu  c fold  q quit', curses.A_REVERSE)
        stdscr.refresh()

        notice = ''
        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            return
        if key == curses.KEY_LEFT:
            cursor -= zoom
        elif key == curses.KEY_RIGHT:
            cursor += zoom
        elif key == curses.KEY_PPAGE:
            cursor -= graph_w * zoom
        elif key == curses.KEY_NPAGE:
            cursor += graph_w * zoom
        elif key == curses.KEY_HOME:
            cursor = first
        elif key == curses.KEY_END:
            cursor = last
        elif key == curses.KEY_UP:
            scroll -= 1
        elif key == curses.KEY_DOWN:
            scroll += 1
        elif key == ord('\t'):
            tab = 1 - tab
        elif key == ord('c'):
            collapsed = not collapsed
        elif key == ord('g'):
            text = prompt(f' go to (YYYY-MM-DD HH:MM, or HH:MM on {label(cursor, "%Y-%m-%d")}) {label(cursor, "%Z")}: ')
            minute = parse_time(text, cursor)
            if minute is None:
                notice = f' could not read "{text.strip()}"; use YYYY-MM-DD HH:MM or HH:MM'
            else:
                cursor = view_end = minute
                if not first <= minute <= last:
                    notice = f' no data at {label(minute, "%Y-%m-%d %H:%M")}; showing the nearest end of the recording'
        elif key in (ord('+'), ord('='), ord('-')):
            level = ZOOM_LEVELS.index(zoom) + (1 if key == ord('-') else -1)
            zoom = ZOOM_LEVELS[min(max(level, 0), len(ZOOM_LEVELS) - 1)]
            cursor = align(cursor)
            view_end = max(cursor, min(cursor + graph_w // 2 * zoom, align(last)))  # re-centre on the marker


def check_readable(csv_dir):
    if os.path.isdir(csv_dir) and not os.access(csv_dir, os.R_OK | os.X_OK):
        sys.exit(f'{csv_dir} is readable by root only; run hmon with sudo.')


def main(args):
    if args in (['-V'], ['--version']):
        print(f'hmon {VERSION}')
        return
    if args[:1] == ['--tz'] and len(args) > 1:
        os.environ['TZ'] = args[1]
        args = args[2:]
    time.tzset()
    if args == ['collect']:
        collect()
    elif args[:1] == ['at'] and len(args) in (2, 3):
        check_readable(args[2] if len(args) == 3 else DATA_DIR)
        show_snapshot(*args[1:])
    elif len(args) <= 1 and not any(arg == 'at' or arg.startswith('-') for arg in args):
        if curses is None:
            sys.exit('The viewer needs the Python curses module; `hmon at TIME` works without it.')
        csv_dir = args[0] if args else DATA_DIR
        check_readable(csv_dir)
        host = load_host(csv_dir)
        if not host:
            sys.exit(f'No samples in {csv_dir} yet (the first one lands a minute after the service starts).')
        locale.setlocale(locale.LC_ALL, '')
        curses.wrapper(view, csv_dir, host)
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
