"""End-to-end checks: collect from a fake host, browse with the real viewer, export and query. `python3 -m unittest`"""
import contextlib
import io
import itertools
import os
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
    """Stands in for the curses window: keys and typed lines in, one text frame out per key read."""

    def __init__(self, keys, typed=(), rows=46, cols=150):
        self.keys, self.typed, self.rows, self.cols = list(keys), list(typed), rows, cols
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

    def getstr(self, y, x, n):
        return self.typed.pop(0).encode()


def browse(data_dir, keys, typed=(), sampler=None, clicks=()):
    """Runs the viewer on `data_dir` with the given keys; returns the frames it drew."""
    screen = FakeScreen(keys, typed)
    settings = dict(hmon.DEFAULTS, tz='UTC')
    with mock.patch.object(hmon.curses, 'echo'), mock.patch.object(hmon.curses, 'noecho'), \
            mock.patch.object(hmon.curses, 'getmouse', side_effect=list(clicks)):
        hmon.Viewer(screen, hmon.Store(data_dir), settings, sampler, use_color=False).run()
    return screen.frames


def proc_files(pid, ppid, command, cgroup, rss, ticks, start='100'):
    stat = ['S', str(ppid)] + ['0'] * 29
    stat[11], stat[19], stat[21] = str(ticks), start, str(rss // hmon.PAGE_SIZE)
    name = os.path.basename(command.split(' ')[0]) or 'kworker'
    return {f'/proc/{pid}/stat': f'{pid} ({name[:15]}) ' + ' '.join(stat),
            f'/proc/{pid}/cgroup': f'0::{cgroup}\n', f'/proc/{pid}/cmdline': command.replace(' ', '\0')}


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

        frames = browse(data_dir, [ord('/')] + [ord(c) for c in 'docker'] + [10, ord('+'), hmon.curses.KEY_F5])
        folded = frames[0]
        for app in ('+ claude', '+ docker', '+ market-recorder', '+ ssh', '+ sessions', '+ systemd'):
            self.assertIn(app, folded)
        self.assertNotIn('dockerd', folded)  # apps start folded
        self.assertIn('2 processes in', folded.replace('Tasks: 9 processes in', '2 processes in'))
        unfolded = frames[9]
        self.assertIn('/usr/bin/dockerd -H fd://', unfolded)
        self.assertRegex(unfolded, r'[├└]\+ openalgo')  # the container sits under docker, folded itself
        listed = frames[10]
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

        class Live:  # stands in for /proc, a little after the last recorded sample
            def sample(self):
                ts = '2026-11-06T04:00:30Z'
                return hmon.to_second(ts), [ts, 30.0, 1.0, 8 * GiB, 4 * GiB, 0, 1, 1, 0], [
                    [ts, 900, '', 'probe', 50 * MiB, 2.0, 'probe --live', 1, '/system.slice/probe.service']]

        header_click = (0, 10, 19, 0, hmon.curses.BUTTON1_PRESSED)  # the RES title of the table header
        keys = ([ord('g'), ord('['), ord('['), ord('s'), ord('\t'), ord('\t'), ord('\\')] + [ord(c) for c in 'leak']
                + [10, ord('\\'), 27, hmon.curses.KEY_MOUSE, hmon.curses.KEY_F2, 10, 27])
        frames = browse(data_dir, keys, typed=['6/11/2026 08:44 IST', 'Asia/Kolkata'], sampler=Live(),
                        clicks=[header_click])

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
        filtered = frames[12]
        self.assertIn('/opt/leak/bin/leak --serve', filtered)
        self.assertNotIn('openalgo', filtered)
        self.assertIn('+ docker', frames[14])  # Esc in the filter bar clears it; apps are folded again
        self.assertIn('RES▽', frames[15])  # a click on a column title sorts by it
        self.assertIn('times in IST', frames[18])
        with open(hmon.CONFIG_PATH) as f:
            self.assertIn('tz=Asia/Kolkata', f.read())

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
