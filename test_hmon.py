"""End-to-end checks: collect from a fake host, browse with the real viewer, export and query. `python3 -m unittest`"""
import base64
import contextlib
import csv
import glob
import io
import itertools
import os
import pty
import select
import sys
import tempfile
import time
import unittest
from unittest import mock

import hmon

GiB, MiB = 2**30, 2**20
ORIGINAL_TZ = os.environ.get('TZ')


class Stop(Exception):
    pass


class FakeScreen:
    """Stands in for the curses window: keys in, one text frame out per key read."""

    def __init__(self, keys, rows=46, cols=150):
        self.keys, self.rows, self.cols = list(keys), rows, cols
        self.cells, self.frames = {}, []

    def getmaxyx(self):
        return self.rows, self.cols

    def erase(self):
        self.cells = {}

    clear = erase

    def addstr(self, y, x, text, attr=0):
        for i, char in enumerate(text):
            self.cells[(y, x + i)] = char

    def refresh(self):
        pass

    def timeout(self, delay):
        pass

    def move(self, y, x):
        pass

    def getch(self):
        self.frames.append('\n'.join(''.join(self.cells.get((y, x), ' ') for x in range(self.cols)).rstrip()
                                     for y in range(self.rows)))
        return self.keys.pop(0) if self.keys else ord('q')


def browse(data_dir, keys, sampler=None, clicks=()):
    """Runs the viewer on `data_dir` with the given keys; returns the frames it drew."""
    screen = FakeScreen(keys)
    settings = dict(hmon.DEFAULTS, tz='UTC')
    with mock.patch.object(hmon.curses, 'getmouse', side_effect=list(clicks)):
        hmon.Viewer(screen, hmon.Store(data_dir), settings, sampler, use_color=False).run()
    return screen.frames


def read_pty(fd, until=None):
    """What a program in a pseudo-terminal wrote, up to `until` or until it exits."""
    output, deadline = b'', time.time() + 10
    while (until is None or until not in output) and time.time() < deadline:
        if select.select([fd], [], [], 0.1)[0]:
            try:
                chunk = os.read(fd, 65536)
            except OSError:  # Linux, once the program has exited
                break
            if not chunk:  # macOS
                break
            output += chunk
    return output


def proc_files(pid, ppid, command, cgroup, rss, ticks, start='100'):
    stat = ['S', str(ppid)] + ['0'] * 29
    stat[11], stat[19], stat[21] = str(ticks), start, str(rss // hmon.PAGE_SIZE)
    name = os.path.basename(command.split(' ')[0]) or 'kworker'
    return {f'/proc/{pid}/stat': f'{pid} ({name[:15]}) ' + ' '.join(stat),
            f'/proc/{pid}/cgroup': f'0::{cgroup}\n', f'/proc/{pid}/cmdline': command.replace(' ', '\0')}


def fake_sys(root, energy):
    """A /sys with two hwmon temperature sensors (and a thermal zone, which hwmon covers), a CPU package's RAPL
    counter (and a core part inside it, not to be counted again) and a discharging battery."""
    files = {'class/hwmon/hwmon0/temp1_input': '45000', 'class/hwmon/hwmon1/temp1_input': '52000',
             'class/thermal/thermal_zone0/temp': '60000',
             'class/powercap/intel-rapl:0/name': 'package-0', 'class/powercap/intel-rapl:0/energy_uj': str(energy),
             'class/powercap/intel-rapl:0/max_energy_range_uj': '262143328850',
             'class/powercap/intel-rapl:0:0/name': 'core', 'class/powercap/intel-rapl:0:0/energy_uj': '7',
             'class/power_supply/BAT0/status': 'Discharging', 'class/power_supply/BAT0/power_now': '12500000'}
    for path, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
        with open(os.path.join(root, path), 'w') as f:
            f.write(text + '\n')


class Live:
    """Stands in for /proc, a little after the last recorded sample: one new process, probe."""

    def sample(self):
        ts = '2026-11-06T04:00:30Z'
        return hmon.to_second(ts), [ts, 30.0, 1.0, 8 * GiB, 4 * GiB, 0, 1, 1, 0], [
            [ts, 900, '', 'probe', 50 * MiB, 2.0, 'probe --live', 1, '/system.slice/probe.service']]


class EndToEnd(unittest.TestCase):
    def setUp(self):
        os.environ['TZ'] = 'UTC'
        time.tzset()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = mock.patch.object(hmon, 'CONFIG_PATH', os.path.join(self.dir.name, 'config', 'hmonrc'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        if ORIGINAL_TZ is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = ORIGINAL_TZ
        time.tzset()

    def test_collect_from_a_host_then_browse_apps_and_containers(self):
        data_dir = os.path.join(self.dir.name, 'data')
        container = '7526' + 'c' * 60
        session = '/user.slice/user-1000.slice/session-3.scope'
        processes = [
            (1, 0, '/sbin/init', '/init.scope', 12 * MiB),
            (516450, 1, 'sshd-session: sukumar [priv]', '/system.slice/ssh.service', 11 * MiB),
            (600, 516450, '-bash', session, 6 * MiB),
            (3011, 600, 'claude', session, 190 * MiB),
            (89702, 1, '/home/sukumar/.local/bin/claude daemon run', session, 130 * MiB),
            (117389, 89702, '/home/sukumar/.local/share/claude/versions/2.1.316 --resume x', session, 360 * MiB),
            (1092, 1, '/usr/bin/dockerd -H fd://', '/system.slice/docker.service', 200 * MiB),
            (942400, 1092, 'python app.py --db postgres://app:hunter2@db/app', f'/system.slice/docker-{container}.scope',
             300 * MiB),
            (1418867, 1, '/srv/venv/bin/python -u /srv/market-recorder/tick_recorder.py run',
             '/system.slice/market-recorder.service', 320 * MiB),
        ]
        files = {}
        for sample, ticks in ((0, 0), (1, 500)):
            pass
        for pid, ppid, command, cgroup, rss in processes:
            files.update(proc_files(pid, ppid, command, cgroup, rss, 0))
        proc = {'/proc/stat': 'cpu 100 0 50 800 50 0 0 0 0 0\n',
                '/proc/meminfo': 'MemTotal: 8000000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n',
                '/proc/loadavg': '0.50 0.40 0.30 1/200 999\n'}
        real_open = open
        stats = mock.Mock(stdout=f'{container}\topenalgo\t3.10%\t320MiB / 7.6GiB\t1kB / 2kB\t0B / 0B\t14\n')
        sleeps = iter([None, Stop()])

        def sleep(seconds):  # the second sample's CPU ticks move on, then the collector is stopped
            outcome = next(sleeps)
            if outcome:
                raise outcome
            for pid, ppid, command, cgroup, rss in processes:
                files.update(proc_files(pid, ppid, command, cgroup, rss, 600))
            proc['/proc/stat'] = 'cpu 900 0 150 1600 50 0 0 0 0 0\n'

        with mock.patch.object(hmon, 'DATA_DIR', data_dir), \
                mock.patch.object(hmon.os, 'listdir', return_value=[str(p[0]) for p in processes] + ['self']), \
                mock.patch.object(hmon, 'read_text', side_effect=lambda path: files.get(path, '')), \
                mock.patch.object(hmon, 'open', create=True,
                                  side_effect=lambda path, *a, **k: io.StringIO(proc[path]) if path in proc
                                  else real_open(path, *a, **k)), \
                mock.patch.object(hmon.shutil, 'which', return_value='/usr/bin/docker'), \
                mock.patch.object(hmon.subprocess, 'run', return_value=stats), \
                mock.patch.object(hmon.time, 'monotonic', side_effect=itertools.count(0, 30)), \
                mock.patch.object(hmon.time, 'sleep', side_effect=sleep):
            with self.assertRaises(Stop):
                hmon.main(['collect'])

        keys = [ord('/')] + [ord(c) for c in 'docker'] + [10, ord('+'), ord('+'), ord('-'), hmon.curses.KEY_F5]
        frames = browse(data_dir, keys)
        folded = frames[0]
        for app in ('+ claude', '+ docker', '+ market-recorder', '+ ssh', '+ sessions', '+ systemd'):
            self.assertIn(app, folded)
        self.assertNotIn('dockerd', folded)  # apps start folded
        self.assertIn('2 processes in', folded.replace('Tasks: 9 processes in', '2 processes in'))
        unfolded = frames[9]
        self.assertIn('/usr/bin/dockerd -H fd://', unfolded)
        self.assertRegex(unfolded, r'[├└]\+ openalgo')  # the container sits under docker, folded itself
        self.assertIn('/usr/bin/dockerd -H fd://', frames[10])  # + again keeps it unfolded
        self.assertNotIn('/usr/bin/dockerd -H fd://', frames[11])  # - folds
        listed = frames[12]
        self.assertIn('docker/openalgo', listed)
        self.assertIn('postgres://app:***@db/app', listed)  # stored with the password masked
        self.assertNotIn('hunter2', listed)

    def history(self):
        """Four hours of samples: a service whose memory climbs and resets every 15 minutes, a container, sshd."""
        data_dir = os.path.join(self.dir.name, 'history')
        with mock.patch.object(hmon, 'DATA_DIR', data_dir):
            os.makedirs(data_dir)
            for minute in range(240):
                ts = f'2026-11-06T{minute // 60:02d}:{minute % 60:02d}:10Z'
                leak = (100 + 10 * (minute % 15)) * MiB
                hmon.append('host', hmon.HOST_FIELDS, [[ts, 20.0, 1.5, 8 * GiB, 8 * GiB - leak - GiB, 0, 1.2, 1.0, 0]],
                            '2026-11-06')
                hmon.append('containers', hmon.CONTAINER_FIELDS,
                            [[ts, 'openalgo', 1.5, 320 * MiB, 8 * GiB, 0, 0, 0, 0, 3, 'c' * 64]], '2026-11-06')
                hmon.append('processes', hmon.PROCESS_FIELDS, [
                    [ts, 500, '', 'leak', leak, 5.0, '/opt/leak/bin/leak --serve', 1, '/system.slice/leak.service'],
                    [ts, 600, 'openalgo', 'python', 300 * MiB, 1.0, 'python app.py', 1, '/system.slice/docker-c.scope'],
                    [ts, 50, '', 'sshd', 10 * MiB, 0.0, 'sshd: /usr/sbin/sshd -D', 1, '/system.slice/ssh.service']],
                    '2026-11-06')
        return data_dir

    def test_browse_history_like_a_cloudwatch_graph(self):
        data_dir = self.history()
        header_click = (0, 10, 19, 0, hmon.curses.BUTTON1_RELEASED)  # the RES title of the table header
        go_to = [ord(c) for c in '6/11/2026 08:44 IST'] + [10]
        keys = ([ord('g')] + go_to + [ord('['), ord('['), ord('s'), ord('\t'), ord('\t'), ord('\t'), hmon.curses.KEY_BTAB,
                                      ord('\\')]
                + [ord(c) for c in 'leak'] + [10, ord('\\'), 27, hmon.curses.KEY_MOUSE, hmon.curses.KEY_F2, 10]
                + [ord(c) for c in 'kolk'] + [10, 27])
        frames = browse(data_dir, keys, sampler=Live(), clicks=[header_click])
        frames = frames[:1] + frames[1 + len(go_to):]  # leave out the frames drawn while typing the time

        self.assertIn('live', frames[0].split('\n')[2])  # the newest column is the live sample
        self.assertIn('+ probe', frames[0])
        self.assertIn('Went to 06 Nov 2026 03:14 UTC', frames[1])  # 08:44 IST typed, shown in UTC
        self.assertIn('Average per 15 min', frames[3])
        leak_row = next(line for line in frames[3].split('\n') if '+ leak' in line)
        self.assertIn(' 170M ', leak_row)  # 100..240 MiB over 03:00-03:14
        self.assertIn('Maximum per 15 min', frames[4])
        self.assertIn(' 240M ', next(line for line in frames[4].split('\n') if '+ leak' in line))
        graph_top = frames[6].split('\n')[5]
        self.assertTrue(graph_top.startswith('    2'), graph_top)  # Load is scaled to its peak, not to 100%
        self.assertNotEqual(frames[7].split('\n')[5], graph_top)  # Tab again: Swap
        self.assertEqual(frames[8].split('\n')[5], graph_top)  # Shift+Tab: back to Load
        filtered = frames[14]
        self.assertIn('/opt/leak/bin/leak --serve', filtered)
        self.assertNotIn('openalgo', filtered)
        self.assertIn('+ docker', frames[16])  # Esc in the filter bar clears it; apps are folded again
        self.assertIn('RES▽', frames[17])  # a click on a column title sorts by it
        self.assertIn('F2 Setup  F3 Search  F4 Filter', frames[17])  # each key apart from its label and the next
        self.assertIn('Time zone (type to filter)', frames[19].replace('   ', ' '))  # Enter opens a dropdown
        zones = frames[23]
        self.assertIn('Time zone: kolk', zones)
        self.assertRegex(zones, r'Asia/Kolkata\s+UTC\+05:30')
        self.assertIn('times in IST', frames[25])
        with open(hmon.CONFIG_PATH) as f:
            self.assertIn('tz=Asia/Kolkata', f.read())

    def test_a_range_of_bars_becomes_table_columns(self):
        data_dir = self.history()
        c = hmon.curses
        drag = [(0, 145, 10, 0, c.BUTTON1_PRESSED), (0, 146, 10, 0, c.REPORT_MOUSE_POSITION),
                (0, 147, 10, 0, c.BUTTON1_RELEASED)]  # over the graph's last three bars: 02:00, 03:00, 04:00
        keys = [ord('[')] * 4 + [ord(' '), c.KEY_LEFT, 27] + [c.KEY_MOUSE] * 3  # 1 hour bars; Space, back one, Esc
        terminal = io.StringIO()
        with contextlib.redirect_stdout(terminal):
            frames = browse(data_dir, keys, sampler=Live(), clicks=drag)

        def table(frame):
            lines = frame.split('\n')
            return lines[next(i for i, line in enumerate(lines) if 'PID' in line):]

        ranged = table(frames[6])
        self.assertRegex(ranged[0], r'PID\s+06 Nov 03:00▽\s+06 Nov 04:00\s+App / Process')  # ordered by the marker's bar
        self.assertRegex(next(line for line in ranged if '+ leak' in line), r'170M\s+-\s+\+ leak')  # not running live
        self.assertRegex(next(line for line in ranged if '+ probe' in line), r'-\s+50\.0M\s+\+ probe')  # live only
        self.assertIn('2 bars in the table, Esc for one', frames[6])
        self.assertRegex(frames[6].split('\n')[16], '▲═|═▲')  # the range shows on the axis, from the marker
        self.assertNotIn('═', frames[7].split('\n')[16])
        self.assertRegex(table(frames[7])[0], r'PID\s+RES\s+CPU%\s+MEM%')  # Esc: one bar again
        self.assertRegex(table(frames[10])[0], r'06 Nov 02:00\s+06 Nov 03:00\s+06 Nov 04:00▽')  # a drag on the graph
        self.assertEqual(terminal.getvalue(), '')  # picks bars, and copies no text

    def test_a_time_zone_is_found_by_its_abbreviation(self):
        data_dir = self.history()
        frames = browse(data_dir, [hmon.curses.KEY_F2, 10] + [ord(c) for c in 'ist'] + [27, 27])  # Setup, Time zone
        found = frames[5]
        self.assertIn('Time zone: ist', found)
        self.assertRegex(found, r'Asia/Kolkata\s+UTC\+05:30 IST')  # IST is in the row, so typing it finds the zone
        self.assertNotIn('America/New_York', found)

    def test_the_live_column_shows_what_runs_now(self):
        data_dir = self.history()
        with mock.patch.object(hmon, 'DATA_DIR', data_dir):  # leak still ran at 04:00:10; at 04:00:30 only probe runs
            ts = '2026-11-06T04:00:10Z'
            hmon.append('host', hmon.HOST_FIELDS, [[ts, 20.0, 1.5, 8 * GiB, 6 * GiB, 0, 1.2, 1.0, 0]], '2026-11-06')
            hmon.append('processes', hmon.PROCESS_FIELDS, [[ts, 500, '', 'leak', 100 * MiB, 5.0,
                                                           '/opt/leak/bin/leak --serve', 1, '/system.slice/leak.service']],
                        '2026-11-06')
        frames = browse(data_dir, [ord('[')] * 5, sampler=Live())
        now, today = frames[0], frames[5]
        self.assertIn('+ probe', now)
        self.assertNotIn('+ leak', now)  # 1 min bars: the live one shows now, so what stopped is gone at once
        self.assertIn('30.0%', next(line for line in now.split('\n') if 'CPU[' in line))  # the live CPU
        self.assertIn('Average per 1 day', today)
        self.assertIn('+ leak', today)  # 1 day bars keep their statistic on the live one: today's peak stays findable

    def test_uninstall_asks_about_the_samples_and_the_settings_apart(self):
        data_dir = self.history()
        installed = [os.path.join(self.dir.name, name) for name in ('hmon.service', 'hmon')]
        for samples, settings in (('n', 'y'), ('y', 'n')):
            os.makedirs(os.path.dirname(hmon.CONFIG_PATH), exist_ok=True)
            for path in installed + [hmon.CONFIG_PATH]:
                open(path, 'w').close()
            with mock.patch.object(hmon, 'DATA_DIR', data_dir), mock.patch.object(hmon, 'INSTALLED_FILES', installed), \
                    mock.patch.dict(os.environ), mock.patch.object(hmon.os, 'geteuid', return_value=0), \
                    mock.patch.object(hmon.subprocess, 'run') as run, \
                    mock.patch('builtins.input', side_effect=[samples, settings]) as asked, \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                os.environ.pop('SUDO_USER', None)
                hmon.main(['uninstall'])
            self.assertIn('Delete the recorded samples in', asked.call_args_list[0][0][0])
            self.assertIn('Delete the settings in', asked.call_args_list[1][0][0])
            self.assertFalse(any(os.path.exists(path) for path in installed))  # the service and the command go
            run.assert_any_call(['systemctl', 'disable', '--now', 'hmon'], stdout=hmon.subprocess.DEVNULL,
                                stderr=hmon.subprocess.DEVNULL)
            self.assertEqual(os.path.exists(data_dir), samples == 'n')  # each goes only on its own yes
            self.assertEqual(os.path.exists(hmon.CONFIG_PATH), settings == 'n')
            self.assertIn('Kept', out.getvalue())
            self.assertIn('Deleted', out.getvalue())

    def test_the_wheel_moves_through_time_on_either_ncurses_mouse_abi(self):
        data_dir = self.history()
        c = hmon.curses
        over_graph = (0, 40, 8, 0)
        abis = [c.REPORT_MOUSE_POSITION] + ([c.BUTTON5_PRESSED] if hasattr(c, 'BUTTON5_PRESSED') else [])
        for wheel_down in abis:  # the old ABI (Python 3.7's image has it) has no button 5, and the new one may be here
            with mock.patch.dict(vars(c)):
                if wheel_down == c.REPORT_MOUSE_POSITION:
                    vars(c).pop('BUTTON5_PRESSED', None)
                frames = browse(data_dir, [c.KEY_MOUSE] * 2,
                                clicks=[over_graph + (c.BUTTON4_PRESSED,), over_graph + (wheel_down,)])
            times = [next(line for line in frame.split('\n') if 'Time:' in line) for frame in frames[:3]]
            self.assertNotEqual(times[1], times[0])  # up: a column back
            self.assertEqual(times[2], times[0])  # down: forward again

    def test_sgr_mouse_reports_where_ncurses_reads_only_x10(self):
        data_dir = self.history()
        c = hmon.curses
        keys = [27] + [ord(ch) for ch in '[<0;201;9M'] + [27] + [ord(ch) for ch in '[<0;201;9m'] + [27, ord('t')]
        screen = FakeScreen(keys, cols=300)  # a wide terminal whose terminfo knows only X10 reports (\E[M), so
        terminal = io.StringIO()  # ncurses passes SGR ones on as keys: a click at column 200, then Esc and t
        with mock.patch.object(c, 'mousemask'), mock.patch.object(c, 'mouseinterval'), \
                mock.patch.object(c, 'tigetstr', return_value=b'\x1b[M'), \
                mock.patch.object(c, 'ungetch', side_effect=lambda key: screen.keys.insert(0, key)), \
                contextlib.redirect_stdout(terminal):
            hmon.Viewer(screen, hmon.Store(data_dir), dict(hmon.DEFAULTS, tz='UTC'), None, use_color=False).run()
        self.assertIn('\x1b[?1006h', terminal.getvalue())  # hmon asked for SGR reports
        clicked = next(f for f in screen.frames if f.split('\n')[16].find('▲') == 200)  # the marker went to column 200
        self.assertGreater(len(clicked.split('\n')[16].rstrip()), 223)  # on a graph as wide as the screen
        self.assertIn('Command', screen.frames[-1])  # Esc, then t (list view): keys that aren't a report still work

    def test_hovering_a_bar_shows_its_tooltip(self):
        data_dir = self.history()
        c = hmon.curses
        screen = FakeScreen([c.KEY_MOUSE, -1])  # the pointer moves onto a bar, then rests there
        terminal = io.StringIO()  # an X10 terminfo, so hmon reads the reports and hovers work on any ncurses
        with mock.patch.object(c, 'mousemask'), mock.patch.object(c, 'mouseinterval'), \
                mock.patch.object(c, 'tigetstr', return_value=b'\x1b[M'), \
                mock.patch.object(c, 'getmouse', side_effect=[(0, 100, 8, 0, c.REPORT_MOUSE_POSITION)]), \
                contextlib.redirect_stdout(terminal):
            hmon.Viewer(screen, hmon.Store(data_dir), dict(hmon.DEFAULTS, tz='UTC'), None, use_color=False).run()
        self.assertIn('\x1b[?1003h', terminal.getvalue())  # every move is reported, so hover can be seen
        moved, rested = screen.frames[1], screen.frames[2]
        for statistic in ('Average', 'Maximum', 'Minimum'):
            self.assertRegex(moved, statistic + r'\s+[\d.]+%')  # the bar's memory, at once
        self.assertNotIn('▸ docker', moved)
        self.assertRegex(rested, r'▸ docker\s+320M')  # and once the pointer rests, its top 3 apps
        self.assertRegex(rested, r'▸ ssh')

    def test_a_pinned_tooltip_walks_the_table(self):
        data_dir = self.history()
        c = hmon.curses
        click = [(0, 100, 8, 0, c.BUTTON1_PRESSED), (0, 100, 8, 0, c.BUTTON1_RELEASED)]
        frames = browse(data_dir, [c.KEY_MOUSE, c.KEY_MOUSE, c.KEY_DOWN, 27], clicks=click)
        pinned, down, closed = frames[2], frames[3], frames[4]
        self.assertIn('▾ docker', pinned)  # the click pins the bar's tooltip, its first app selected...
        self.assertRegex(pinned, r'[├└]\+ openalgo')  # ...and unfolded in the table
        self.assertIn('▾ leak', down)  # Down: the next app; the table follows
        self.assertIn('/opt/leak/bin/leak --serve', down)
        self.assertNotIn('openalgo', down)  # docker, unfolded by the tooltip, folds back
        self.assertNotIn('▾', closed)  # Esc closes the tooltip
        self.assertIn('/opt/leak/bin/leak --serve', closed)  # and the table stays where it was walked to

    def test_a_hover_never_turns_the_wheel_on_an_old_ncurses(self):
        data_dir = self.history()
        c = hmon.curses
        reports = ['[<64;100;9M', '[<35;100;9M', '[<65;100;9M']  # wheel up, a hover, wheel down, as SGR reports
        keys = [key for report in reports for key in [27] + [ord(ch) for ch in report]]
        screen = FakeScreen(keys)
        with mock.patch.dict(vars(c)), mock.patch.object(c, 'mousemask'), mock.patch.object(c, 'mouseinterval'), \
                mock.patch.object(c, 'tigetstr', return_value=b'\x1b[M'), contextlib.redirect_stdout(io.StringIO()):
            vars(c).pop('BUTTON5_PRESSED', None)  # the old mouse ABI, which hmon reads SGR reports for itself
            hmon.Viewer(screen, hmon.Store(data_dir), dict(hmon.DEFAULTS, tz='UTC'), None, use_color=False).run()
        before = [i for i, key in enumerate(keys) if key == 27] + [len(keys)]  # the frames between reports
        times = [next(line for line in screen.frames[i].split('\n') if 'Time:' in line) for i in before]
        self.assertNotEqual(times[1], times[0])  # up: a column back
        self.assertEqual(times[2], times[1])  # the hover moved nothing
        self.assertEqual(times[3], times[0])  # down: forward again

    def test_mouse_clicks_act_on_release(self):
        data_dir = self.history()
        f1 = (1, 45)  # F1 Help on the function bar
        clicks = [(0, *f1, 0, hmon.curses.BUTTON1_PRESSED), (0, *f1, 0, hmon.curses.BUTTON1_RELEASED),
                  (0, 5, 5, 0, hmon.curses.BUTTON1_PRESSED)]
        frames = browse(data_dir, [hmon.curses.KEY_MOUSE] * 3 + [ord('x')], clicks=clicks)
        self.assertNotIn('Press any key or click to return.', frames[1])  # the press alone does nothing
        self.assertIn('Press any key or click to return.', frames[2])  # the release opens help
        self.assertIn('Press any key or click to return.', frames[3])  # and a stray press doesn't close it
        self.assertNotIn('Press any key or click to return.', frames[4])

    def test_go_to_cancels_and_a_drag_copies_text(self):
        data_dir = self.history()
        mouse = hmon.curses
        clicks = [(0, 30, 3, 0, mouse.BUTTON1_PRESSED), (0, 30, 3, 0, mouse.BUTTON1_RELEASED),
                  (0, 0, 45, 0, mouse.BUTTON1_PRESSED), (0, 3, 45, 0, mouse.REPORT_MOUSE_POSITION),
                  (0, 5, 45, 0, mouse.BUTTON1_RELEASED)]  # a click, then a drag over the start of the function bar
        keys = [ord('g'), ord('1'), 27, ord('g')] + [mouse.KEY_MOUSE] * 5
        terminal = io.StringIO()
        with contextlib.redirect_stdout(terminal):
            frames = browse(data_dir, keys, clicks=clicks)

        self.assertTrue(frames[2].split('\n')[45].endswith('): 1'), frames[2])  # what's typed shows as it's typed
        self.assertNotIn('Go to', frames[3])  # Esc cancels
        self.assertNotIn('Could not read', frames[3])
        self.assertIn('Go to', frames[5])
        self.assertNotIn('Go to', frames[6])  # and so does a click
        dragged = frames[8].split('\n')[45][:6]
        self.assertIn('F1', dragged)
        self.assertIn(f'\033]52;c;{base64.b64encode(dragged.encode()).decode()}\a', terminal.getvalue())
        self.assertIn(f'Copied "{dragged}"', frames[9])
        self.assertNotIn('Press any key or click to return.', frames[9])  # the drag ended on F1 without opening help

    def test_ctrl_c_quits_quietly(self):
        data_dir = self.history()
        home = os.path.join(self.dir.name, 'home')
        pid, fd = pty.fork()
        if pid == 0:  # the viewer, in a terminal of its own
            os.environ.update(TERM='xterm', HOME=home, XDG_CONFIG_HOME=home)
            os.execv(sys.executable, [sys.executable, os.path.abspath(hmon.__file__), data_dir])
        shown = read_pty(fd, until=b'Quit')
        os.write(fd, b'\x03')
        shown += read_pty(fd)
        _, status = os.waitpid(pid, 0)
        os.close(fd)
        self.assertIn(b'Quit', shown)
        self.assertNotIn(b'Traceback', shown)
        self.assertEqual(os.WEXITSTATUS(status), 130)

    def test_a_newer_release_is_announced_and_installed(self):
        data_dir = self.history()
        requested = []

        def github(url, timeout):  # the releases API, and the newest release's installer
            requested.append(url)
            return io.BytesIO(b'{"tag_name": "v0.2.5"}' if 'api.github.com' in url else b'echo installing')

        class Inline:  # runs the background check at once, so the first frame shows what it found
            def __init__(self, target, daemon):
                self.start = target

        with mock.patch.object(hmon, 'VERSION', '0.2.4'), mock.patch.object(hmon.threading, 'Thread', Inline), \
                mock.patch.object(hmon.urllib.request, 'urlopen', side_effect=github), \
                contextlib.redirect_stdout(io.StringIO()) as progress:
            bar = browse(data_dir, [])[0].split('\n')[45]
            with mock.patch.object(hmon.os, 'geteuid', return_value=1000), \
                    mock.patch.object(hmon.os, 'execvp', side_effect=SystemExit) as sudo, self.assertRaises(SystemExit):
                hmon.main(['update'])
            with mock.patch.object(hmon.os, 'geteuid', return_value=0), \
                    mock.patch.object(hmon.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run, \
                    self.assertRaises(SystemExit) as done:
                hmon.main(['update'])
        self.assertTrue(bar.endswith('New update available, Run: "hmon update"'), bar)  # at the bottom right
        self.assertEqual(sudo.call_args[0][1][:2], ['sudo', sys.executable])  # not root: it asks sudo to run it
        self.assertEqual(sudo.call_args[0][1][-1], 'update')
        self.assertEqual(requested[-1], f'https://github.com/{hmon.REPO}/releases/download/v0.2.5/install.sh')
        run.assert_called_once_with(['bash'], input=b'echo installing')
        self.assertEqual(done.exception.code, 0)
        self.assertIn('Downloading the hmon 0.2.5 installer...', progress.getvalue())  # a slow step shows where it is

        with mock.patch.object(hmon, 'VERSION', '0.2.5'), \
                mock.patch.object(hmon.urllib.request, 'urlopen', side_effect=github), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            hmon.main(['update'])
        self.assertIn('hmon 0.2.5 is up to date.', out.getvalue())

    def test_opt_in_metrics_are_recorded_and_graphed(self):
        data_dir, sys_dir = os.path.join(self.dir.name, 'data'), os.path.join(self.dir.name, 'sys')
        fake_sys(sys_dir, energy=1000000)
        proc = {'/proc/stat': 'cpu 100 0 50 800 50 0 0 0 0 0\n', '/proc/loadavg': '0.50 0.40 0.30 1/200 999\n',
                '/proc/meminfo': 'MemTotal: 8000000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n'}
        real_open, steps = open, iter([lambda: fake_sys(sys_dir, energy=121000000), Stop])

        def sleep(seconds):  # between the two samples the package uses 120 J; then the collector is stopped
            step = next(steps)
            if step is Stop:
                raise Stop
            step()

        with mock.patch.object(hmon, 'DATA_DIR', data_dir), mock.patch.object(hmon, 'SYS', sys_dir), \
                mock.patch.dict(os.environ, {'HMON_METRICS': 'temperature,cpu-power,battery'}), \
                mock.patch.object(hmon.os, 'listdir', return_value=[]), \
                mock.patch.object(hmon.shutil, 'which', return_value=None), \
                mock.patch.object(hmon, 'open', create=True,
                                  side_effect=lambda path, *a, **k: io.StringIO(proc[path]) if path in proc
                                  else real_open(path, *a, **k)), \
                mock.patch.object(hmon.time, 'monotonic', side_effect=itertools.count(0, 30)), \
                mock.patch.object(hmon.time, 'sleep', side_effect=sleep), self.assertRaises(Stop):
            hmon.main(['collect'])
        with open(glob.glob(os.path.join(data_dir, 'host_*.csv'))[0]) as f:
            rows = list(csv.reader(f))
        self.assertEqual(rows[0][-3:], ['temps_c', 'cpu_power_w', 'battery_power_w'])
        self.assertEqual(rows[2][-3:], ['45;52', '1.0', '12.5'])  # every sensor; 120 J in 120 s; 12.5 W out

        with mock.patch.object(hmon, 'UNIT_PATH', os.path.join(self.dir.name, 'none.service')):
            frames = browse(data_dir, [ord('\t')] * 4 + [ord('s'), ord('s'), ord('\t'), ord('\t')])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                hmon.main(['sql', 'SELECT temp_avg_c, temp_max_c, temp_min_c FROM host WHERE temp_max_c > 0', data_dir])
        self.assertIn(' Swap   Temp   CPU W   Batt W ', frames[0])  # tabs for the metrics with readings
        self.assertIn(' 100°', frames[4])
        top = [frame.split('\n')[10][147] for frame in frames[4:7]]  # the newest bar's highest row at 48.5, 52, 45°
        self.assertEqual(top, ['▃', '▆', '│'])  # Average, Maximum, Minimum: across the sensors as well as time
        self.assertIn('   2W', frames[7])  # watts scale to the most in view
        self.assertIn('  14W', frames[8])
        self.assertRegex(out.getvalue(), r'48\.5\s+52\s+45')  # and sql has each sample's average, hottest, coolest

    def test_an_empty_opt_in_graph_says_why(self):
        data_dir = self.history()  # recorded before any opt-in
        unit, rule = os.path.join(self.dir.name, 'hmon.service'), os.path.join(self.dir.name, 'hmon.conf')
        with open(unit, 'w') as f:
            f.write('[Service]\nEnvironment=HMON_INTERVAL=60\nEnvironment=HMON_METRICS=battery,cpu-power,temperature\n')
        with open(rule, 'w') as f:
            f.write('d /var/lib/hmon 0755 root root 14d\n')
        bare = os.path.join(self.dir.name, 'sys')  # a laptop whose sensor drivers aren't loaded, without lm-sensors
        os.makedirs(bare)
        with mock.patch.object(hmon, 'UNIT_PATH', unit), mock.patch.object(hmon, 'TMPFILES_PATH', rule), \
                mock.patch.object(hmon, 'SYS', bare), mock.patch.object(hmon.shutil, 'which', return_value=None):
            with mock.patch.object(hmon, 'virtual_machine', return_value=''):
                laptop = browse(data_dir, [ord('\t')] * 6, sampler=Live())
            with mock.patch.object(hmon, 'virtual_machine', return_value='amazon'):
                ec2 = browse(data_dir, [ord('\t')] * 4, sampler=Live())
        self.assertIn('No temperature readings: install lm-sensors', laptop[4])  # in the middle of the empty graph
        self.assertIn('No CPU power readings: this CPU or kernel has no RAPL energy counters', laptop[5])
        self.assertIn('No battery here', laptop[6])
        self.assertIn('No temperature readings: this is a virtual machine (amazon), which has no such sensors', ec2[4])

    def test_setup_turns_a_metric_on_through_sudo(self):
        data_dir = self.history()
        unit, rule = os.path.join(self.dir.name, 'hmon.service'), os.path.join(self.dir.name, 'hmon.conf')
        with open(unit, 'w') as f:
            f.write('[Service]\nEnvironment=HMON_INTERVAL=60\nExecStart=/usr/local/bin/hmon collect\n')
        with open(rule, 'w') as f:
            f.write('d /var/lib/hmon 0755 root root 14d\n')

        def run(command, **kwargs):  # sudo runs hmon configure as root; systemctl does nothing here
            if command[0] == 'sudo':
                with mock.patch.object(hmon.os, 'geteuid', return_value=0):
                    hmon.main(command[3:])
            return mock.Mock(returncode=0)

        keys = [hmon.curses.KEY_F2] + [hmon.curses.KEY_DOWN] * 9 + [hmon.curses.KEY_RIGHT, 27]  # Temperature: on
        with mock.patch.object(hmon, 'UNIT_PATH', unit), mock.patch.object(hmon, 'TMPFILES_PATH', rule), \
                mock.patch.object(hmon.os, 'geteuid', return_value=1000), mock.patch.object(hmon.curses, 'endwin'), \
                mock.patch.object(hmon.subprocess, 'run', side_effect=run) as ran, \
                contextlib.redirect_stdout(io.StringIO()):
            frames = browse(data_dir, keys)
        self.assertRegex(frames[11], r'Temperature\s+on\s+records every sensor')
        self.assertEqual(ran.call_args_list[0][0][0][:2], ['sudo', sys.executable])  # not root: sudo, off the screen
        with open(unit) as f:
            self.assertIn('Environment=HMON_METRICS=temperature\n', f.read())  # it stuck
        self.assertIn('The recording changed', frames[12])
        self.assertIn(' Swap   Temp ', frames[12])  # and its tab is there at once

    def test_setup_changes_what_the_installer_asked(self):
        data_dir = self.history()
        unit, rule = os.path.join(self.dir.name, 'hmon.service'), os.path.join(self.dir.name, 'hmon.conf')
        with open(unit, 'w') as f:
            f.write('[Unit]\nDescription=hmon\n\n[Service]\nEnvironment=HMON_INTERVAL=60\n'
                    'ExecStart=/usr/local/bin/hmon collect\n')
        with open(rule, 'w') as f:
            f.write('d /var/lib/hmon 0755 root root 14d\n')
        down = hmon.curses.KEY_DOWN
        keys = ([hmon.curses.KEY_F2] + [down] * 6 + [hmon.curses.KEY_RIGHT, down, hmon.curses.KEY_LEFT, down, 10,
                ord('7'), 10, 27])
        with mock.patch.object(hmon, 'UNIT_PATH', unit), mock.patch.object(hmon, 'TMPFILES_PATH', rule), \
                mock.patch.object(hmon.os, 'geteuid', return_value=0), \
                mock.patch.object(hmon.subprocess, 'run') as run:
            frames = browse(data_dir, keys)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                hmon.main(['configure'])
        self.assertIn('what the installer asked', frames[1])
        self.assertRegex(frames[1], r'Sample every\s+60 s\s+about [\d,]+ MB a day')
        self.assertRegex(frames[1], r'Keep\s+14 days\s+about [\d,]+ MB in all')
        self.assertRegex(frames[1], r'Mouse\s+on\s+clicks act; a drag highlights text and copies it')
        self.assertRegex(frames[1], r'Temperature\s+off\s+not recorded')  # the opt-in metrics, in Recording
        self.assertRegex(frames[1], r'Battery draw\s+off')
        self.assertRegex(frames[8], r'Mouse\s+off\s+the terminal selects text')  # Right steps through the choices
        self.assertRegex(frames[10], r'Sample every\s+30 s')
        self.assertRegex(frames[13], r'7 days\s+about [\d,]+ MB in all')  # the retention dropdown, filtered
        self.assertIn('Recording every 30 s, kept 7 days, with no opt-in metrics; the hmon service restarted.', frames[15])
        with open(hmon.CONFIG_PATH) as f:
            self.assertIn('mouse=off', f.read())
        with open(unit) as f:
            self.assertIn('Environment=HMON_INTERVAL=30\n', f.read())
        with open(rule) as f:
            self.assertEqual(f.read(), 'd /var/lib/hmon 0755 root root 7d\n')
        run.assert_any_call(['systemctl', 'restart', 'hmon'], check=True)
        self.assertIn('Recording every 30 s, kept 7 days, with no opt-in metrics.', out.getvalue())

        with mock.patch.object(hmon, 'UNIT_PATH', unit), mock.patch.object(hmon, 'TMPFILES_PATH', rule), \
                mock.patch.object(hmon.os, 'geteuid', return_value=0), mock.patch.object(hmon.subprocess, 'run'), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            hmon.main(['configure', '--metrics', 'temperature,battery'])
        with open(unit) as f:
            self.assertIn('Environment=HMON_METRICS=battery,temperature\n', f.read())
        self.assertIn('with battery, temperature; the hmon service restarted.', out.getvalue())

        with mock.patch.object(hmon, 'UNIT_PATH', unit), mock.patch.object(hmon, 'TMPFILES_PATH', rule), \
                mock.patch.object(hmon.os, 'geteuid', return_value=1000), \
                mock.patch.object(hmon.os, 'execvp', side_effect=SystemExit) as sudo, self.assertRaises(SystemExit):
            hmon.main(['configure', '--interval', '10'])
        command = sudo.call_args[0][1]  # not root: it runs itself again under sudo, by path, with its options
        self.assertEqual(command[:2], ['sudo', sys.executable])
        self.assertTrue(os.path.isabs(command[2]), command)
        self.assertEqual(command[3:], ['configure', '--interval', '10'])

    def test_export_a_dump_and_query_it(self):
        data_dir = self.history()
        dump = os.path.join(self.dir.name, 'host.tar.gz')
        window = ['--from', '6/11/2026 00:00 UTC', '--to', '6/11/2026 04:00 UTC']
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            hmon.main(['export', '-o', dump, data_dir] + window)
            hmon.main(['sql', "SELECT app, max(rss) AS peak FROM processes WHERE app = 'leak' GROUP BY app", dump]
                      + window)
            hmon.main(['--tz', 'Asia/Kolkata', 'at', '6/11/2026 08:44', dump])
        text = out.getvalue()
        self.assertIn(f'Wrote {dump}', text)
        self.assertRegex(text, r'leak\s+251658240')  # 240 MiB, its peak
        self.assertIn('Snapshot 2026-11-06 08:44:10 IST', text)
        self.assertIn('/opt/leak/bin/leak --serve', text)


if __name__ == '__main__':
    unittest.main()
