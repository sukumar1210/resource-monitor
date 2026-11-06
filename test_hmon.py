"""Checks for hmon's collector and viewer data paths; run with `python3 -m unittest` (Linux or macOS)."""
import contextlib
import csv
import io
import os
import tempfile
import time
import unittest
from unittest import mock

import hmon

GiB = 2**30
ORIGINAL_TZ = os.environ.get('TZ')


def setUpModule():
    os.environ['TZ'] = 'UTC'
    time.tzset()


def tearDownModule():
    if ORIGINAL_TZ is None:
        os.environ.pop('TZ', None)
    else:
        os.environ['TZ'] = ORIGINAL_TZ
    time.tzset()


def fake_stat(pid, name, cpu_ticks, start_time, rss_bytes):
    fields = ['S'] + ['0'] * 30
    fields[11], fields[19], fields[21] = str(cpu_ticks), str(start_time), str(rss_bytes // hmon.PAGE_SIZE)
    return f'{pid} ({name}) ' + ' '.join(fields)


class CollectorTest(unittest.TestCase):
    def test_to_bytes_handles_docker_units(self):
        self.assertEqual(hmon.to_bytes('1.5GiB'), round(1.5 * GiB))
        self.assertEqual(hmon.to_bytes('8.19kB'), 8190)
        self.assertEqual(hmon.to_bytes('0B'), 0)
        self.assertIsNone(hmon.to_bytes('--'))

    def test_sample_containers_parses_stats_and_restarting_container(self):
        stats = (f'{"a" * 64}\tapi\t12.50%\t1.5GiB / 7.6GiB\t1.2kB / 3.4MB\t0B / 8.19kB\t42\n'
                 f'{"b" * 64}\tdb\t--\t-- / --\t-- / --\t-- / --\t--\n')
        with mock.patch.object(hmon.subprocess, 'run', return_value=mock.Mock(stdout=stats)):
            rows, names = hmon.sample_containers('T')
        self.assertEqual(rows[0], ['T', 'api', 12.5, round(1.5 * GiB), round(7.6 * GiB), 1200, 3400000, 0, 8190, '42'])
        self.assertEqual(rows[1], ['T', 'db'] + [None] * 8)
        self.assertEqual(names, {'a' * 64: 'api', 'b' * 64: 'db'})

    def sample(self, files, prev=None, names=None, now=0.0):
        pids = sorted({path.split('/')[2] for path in files})
        with mock.patch.object(hmon.os, 'listdir', return_value=pids + ['self']), \
                mock.patch.object(hmon, 'read_text', side_effect=lambda path: files.get(path, '')), \
                mock.patch.object(hmon.time, 'monotonic', return_value=now):
            return hmon.sample_processes('T', prev, names or {})

    def test_sample_processes_tags_containers_and_computes_cpu(self):
        api_id = 'a' * 64
        files = {
            '/proc/1/stat': fake_stat(1, 'my (odd) name', 0, 100, GiB),
            '/proc/1/cgroup': f'0::/system.slice/docker-{api_id}.scope\n',
            '/proc/1/cmdline': 'python\0job.py\0',
            '/proc/2/stat': fake_stat(2, 'kworker/0:1', 0, 5, 0),
            '/proc/3/stat': fake_stat(3, 'old', 0, 200, GiB // 2),
        }
        first, prev = self.sample(files, names={api_id: 'api'})
        files['/proc/1/stat'] = fake_stat(1, 'my (odd) name', 30 * hmon.CLOCK_TICKS, 100, GiB)
        files['/proc/3/stat'] = fake_stat(3, 'reused', 60 * hmon.CLOCK_TICKS, 999, GiB // 2)
        second, _ = self.sample(files, prev, {api_id: 'api'}, now=60.0)
        self.assertEqual([row[1] for row in first], [1, 3])  # idle kernel thread 2 skipped, biggest first
        self.assertEqual(first[0], ['T', 1, 'api', 'my (odd) name', GiB, None, 'python job.py'])
        by_pid = {row[1]: row for row in second}
        self.assertEqual(by_pid[1][5], 50.0)
        self.assertIsNone(by_pid[3][5])  # pid reused by a new process: no CPU delta against the old one
        self.assertEqual(by_pid[3][2], '')

    def test_sample_processes_masks_credentials(self):
        commands = {
            'mongodump --uri mongodb://backup:s3cr3t@db:27017/app': 'mongodump --uri mongodb://backup:***@db:27017/app',
            'app --password=hunter2 --port 80': 'app --password=*** --port 80',
            'cli --api-key abc123 run': 'cli --api-key *** run',
            'curl https://x.io/hook?token=abc&x=1': 'curl https://x.io/hook?token=***&x=1',
            'celery -A cel.app worker --queues=a,b': 'celery -A cel.app worker --queues=a,b',
        }
        files = {}
        for pid, command in enumerate(commands, start=1):
            files[f'/proc/{pid}/stat'] = fake_stat(pid, 'p', 0, pid, GiB)
            files[f'/proc/{pid}/cmdline'] = command.replace(' ', '\0')
        rows, _ = self.sample(files)
        self.assertEqual(sorted(row[6] for row in rows), sorted(commands.values()))

    def test_append_writes_header_once(self):
        with tempfile.TemporaryDirectory() as data_dir, mock.patch.object(hmon, 'DATA_DIR', data_dir):
            hmon.append('host', hmon.HOST_FIELDS, [['T', 1.0, 0.5, 8, 4, 0]], 'D')
            hmon.append('host', hmon.HOST_FIELDS, [['T', 2.0, 0.5, 8, 4, 0]], 'D')
            with open(os.path.join(data_dir, 'host_D.csv'), newline='') as f:
                rows = list(csv.reader(f))
        self.assertEqual(rows[0], hmon.HOST_FIELDS)
        self.assertEqual(len(rows), 3)


class TimeTest(unittest.TestCase):
    def tearDown(self):
        os.environ['TZ'] = 'UTC'
        time.tzset()

    def test_parse_time_in_display_zone(self):
        crash = hmon.to_minute('2026-11-06T03:14:00Z')
        os.environ['TZ'] = 'Asia/Kolkata'
        time.tzset()
        self.assertEqual(hmon.parse_time('2026-11-06 08:44'), crash)
        self.assertEqual(hmon.parse_time('08:44', around=crash - 60), crash)  # HH:MM on the marker's local date
        self.assertEqual(hmon.parse_time('2026-11-06T03:14+00:00'), crash)  # an explicit offset wins
        self.assertEqual(hmon.label(crash, '%H:%M %Z'), '08:44 IST')
        self.assertIsNone(hmon.parse_time('yesterday'))


class ViewerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        hmon.load_day.cache_clear()
        samples = [('2026-11-06T03:12:10Z', 1.0 * GiB, 1.0), ('2026-11-06T03:13:10Z', 3.0 * GiB, 99.0)]
        with mock.patch.object(hmon, 'DATA_DIR', self.dir.name):
            for ts, job_rss, job_cpu in samples:
                hmon.append('host', hmon.HOST_FIELDS, [[ts, 50.0, 1.0, 8 * GiB, 2 * GiB, 0]], '2026-11-06')
                hmon.append('containers', hmon.CONTAINER_FIELDS, [
                    [ts, 'api', job_cpu + 1, int(job_rss + 0.2 * GiB), 8 * GiB, 0, 0, 0, 0, 2],
                    [ts, 'db', 5.0, 2 * GiB, 8 * GiB, 0, 0, 0, 0, 30]], '2026-11-06')
                hmon.append('processes', hmon.PROCESS_FIELDS, [
                    [ts, 10, 'api', 'python', int(job_rss), job_cpu, 'python job.py'],
                    [ts, 11, 'api', 'gunicorn', int(0.2 * GiB), 1.0, 'gunicorn app'],
                    [ts, 20, 'db', 'mongod', 2 * GiB, 5.0, 'mongod'],
                    [ts, 30, '', 'sshd', int(0.01 * GiB), 0.0, 'sshd: admin'],
                    [ts, 40, '', 'kswapd0', 0, 3.0, '']], '2026-11-06')
        self.host = hmon.load_host(self.dir.name)
        self.start = min(self.host)
        self.glyphs = ('-', '+', '|-', '`-')

    def test_host_average_over_a_column(self):
        memory_used, cpu, load, swap, total = hmon.host_average(self.host, self.start, 5)
        self.assertEqual((memory_used, cpu, total), (75.0, 50.0, 8 * GiB))
        self.assertIsNone(hmon.host_average(self.host, self.start + 60, 5))

    def test_table_groups_processes_under_containers_sorted_by_memory(self):
        lines = hmon.table_lines(self.dir.name, self.start, 5, 0, 8 * GiB, False, self.glyphs)
        self.assertIn('- api  (container, 2 pids)', lines[0][0])  # api averages 2.2 GiB, ahead of db's 2.0
        self.assertTrue(lines[0][1])
        self.assertIn('python job.py', lines[1][0])
        self.assertIn('2.00 GiB', lines[1][0])  # the job's average over 1 and 3 GiB
        self.assertIn('db  (container, 30 pids)', lines[3][0])
        self.assertEqual([text.split()[-1] for text, _ in lines[-2:]], ['admin', '[kswapd0]'])

    def test_table_by_cpu_and_folded(self):
        lines = hmon.table_lines(self.dir.name, self.start, 5, 1, 8 * GiB, True, self.glyphs)
        self.assertEqual([group for _, group in lines], [True, True, False, False])
        self.assertIn('+ api', lines[0][0])
        self.assertIn('[kswapd0]', lines[2][0])  # 3% CPU ranks above sshd's 0%

    def test_column_spanning_utc_midnight_reads_both_days(self):
        with mock.patch.object(hmon, 'DATA_DIR', self.dir.name):
            hmon.append('processes', hmon.PROCESS_FIELDS, [['2026-11-05T23:59:30Z', 50, '', 'late', GiB, 1.0, 'late']],
                        '2026-11-05')
            hmon.append('processes', hmon.PROCESS_FIELDS, [['2026-11-06T00:00:30Z', 51, '', 'early', GiB, 1.0, 'early']],
                        '2026-11-06')
        hmon.load_day.cache_clear()
        lines = hmon.table_lines(self.dir.name, hmon.to_minute('2026-11-05T23:59:00Z'), 2, 0, 8 * GiB, False, self.glyphs)
        self.assertEqual(sorted(text.split()[-1] for text, _ in lines), ['early', 'late'])

    def test_rows_from_a_newer_version_with_extra_columns_still_load(self):
        with mock.patch.object(hmon, 'DATA_DIR', self.dir.name):
            hmon.append('host', hmon.HOST_FIELDS, [['2026-11-06T03:14:10Z', 60.0, 1.0, 8 * GiB, 4 * GiB, 0, 'new']],
                        '2026-11-06')
        self.assertEqual(hmon.load_host(self.dir.name)[hmon.to_minute('2026-11-06T03:14:10Z')][0], 50.0)

    def test_snapshot_text(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            hmon.show_snapshot('2026-11-06T08:43+05:30', self.dir.name)
        text = out.getvalue()
        self.assertIn('Snapshot 2026-11-06 03:13:10 UTC', text)
        self.assertIn('python job.py', text)
        self.assertIn('(75.0% used)', text)


if __name__ == '__main__':
    unittest.main()
