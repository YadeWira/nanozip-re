#!/usr/bin/env python3
"""pty_prompt_parallel.py -- `x` over files that already exist, -p1 and -p4, through a real pty.

Up to v0.17.6-pre the parallel sink asked its overwrite question with the lock
dropped, so with -p4 (reported by xman as "hangs up"):
  - a second worker asked about another file at the same time, and after `a` it
    kept waiting for a line nobody would type;
  - the question came out before the Compressor lines, which then hid it;
  - the progress line was drawn over a question still waiting;
  - a file split between two workers was truncated and written by the second
    worker while the first was still asking, so answering No lost it.
Per method x -p1/-p4 x key (y, n, a): the original builds the archive of six
files whose worker boundaries fall inside files; both binaries extract it over
earlier copies overwritten with a marker, answering every question with the key.
Same exit, same number of questions, the footer, and per file the same outcome
(new contents, or the marker kept) -- or the case fails.

usage: pty_prompt_parallel.py   env: NZ_ORIG, OURS (defaults ../linux32/nz, bin/nz-re), NZ_PROMPT_SRC
"""
import os, pty, select, shutil, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORIG = os.path.abspath(os.environ.get('NZ_ORIG', os.path.join(HERE, '..', 'linux32', 'nz')))
OURS = os.path.abspath(os.environ.get('OURS', os.environ.get('NZ_RECON', os.path.join(HERE, 'bin', 'nz-re'))))
ROOT = '/tmp/nzre_pty_par'
TMO = 60.0
if not os.access(ORIG, os.X_OK):
    print(f'pty_prompt_parallel: no original at {ORIG}, skipped'); sys.exit(77)
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'TERM': 'dumb'}


def run(bin_, d, key):
    m, s = pty.openpty()
    p = subprocess.Popen([bin_, 'x', '../o.nz'], stdin=s, stdout=s, stderr=s, cwd=d, env=ENV, preexec_fn=os.setsid)
    os.close(s)
    out = b''; t0 = time.time(); status = None
    while True:
        if time.time() - t0 > TMO:
            os.killpg(p.pid, signal.SIGKILL); status = 'HANG'; break
        r, _, _ = select.select([m], [], [], 0.3)
        if r:
            try: b = os.read(m, 65536)
            except OSError: b = b''
            if not b: break
            out += b
        elif p.poll() is not None: break
        elif out.rstrip().endswith(b'?'): os.write(m, key + b'\n')
    p.wait(); os.close(m)
    if status is None: status = p.returncode
    t = out.replace(b'\r', b'\n').replace(b'\b', b'\n').decode('latin1')
    foot = [l.split(' in ')[0] for l in t.split('\n') if l.startswith('Decompressed')]
    return status, t.count('Overwrite'), foot


shutil.rmtree(ROOT, ignore_errors=True)
src = os.path.join(ROOT, 'in'); os.makedirs(src)
data = b''.join(bytes(f'line {i} of the prompt test, some text to compress\n', 'ascii') for i in range(60000))
data += os.urandom(1 << 20)
for i in range(1, 7):
    open(os.path.join(src, f'f{i}.bin'), 'wb').write(data[-i * 400000:])
names = sorted(os.listdir(src))
same_n = total = 0
for c in ('cn', 'cf', 'cd', 'cD', 'co', 'cO', 'cc'):
    for pn in ('1', '4'):
        arc = os.path.join(ROOT, 'o.nz')
        if os.path.exists(arc): os.remove(arc)
        subprocess.run([ORIG, 'a', f'-{c}', f'-p{pn}', '-t4', '-r', arc, 'in'], cwd=ROOT, env=ENV,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for key in (b'y', b'n', b'a'):
            res = {}
            for who, bin_ in (('orig', ORIG), ('ours', OURS)):
                d = os.path.join(ROOT, 'x'); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
                subprocess.run([OURS, 'x', '-y', '../o.nz'], cwd=d, env=ENV, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for n in names: open(os.path.join(d, 'in', n), 'w').write('marker\n')
                status, prompts, foot = run(bin_, d, key)
                files = ''
                for n in names:
                    got = open(os.path.join(d, 'in', n), 'rb').read()
                    files += 'S' if got == open(os.path.join(src, n), 'rb').read() else 'm' if got == b'marker\n' else 'X'
                res[who] = (status, prompts, foot, files)
            total += 1
            same = res['orig'] == res['ours'] and res['ours'][0] == 0
            same_n += same
            if not same or '-v' in sys.argv:
                print(f'{"same" if same else "DIFF"} -{c} -p{pn} {key.decode()}: orig={res["orig"]} ours={res["ours"]}')
print(f'pty_prompt_parallel: {same_n}/{total} same')
sys.exit(0 if same_n == total else 1)
