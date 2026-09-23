#!/usr/bin/env python3
"""pty_prompt_add.py -- `a` over an EXISTING archive, both binaries, through a real pty.

The original asks `Overwrite <archive> (Yes/No/Always)?` before it replaces an archive
that exists, the same question `x` asks per file (quirk 3). Per key sequence: a fresh
dir under /tmp/nzre_pty_add/<case>/<who>/ holding old.nz (an archive of a.txt) and
b.txt; run `<bin> a -t1 -cf old.nz b.txt` with stdin+stdout on a pty, feed the keys
with a 0.2 s gap, cap the output at 256 KB and the run at 10 s, then record stdout,
exit status and whether old.nz is still the old archive, a new one, or gone.

usage: pty_prompt_add.py        env: NZ_ORIG, OURS (defaults ../linux32/nz, bin/nz-re)
"""
import hashlib, os, pty, re, select, signal, subprocess, sys, time

ORIG = os.path.abspath(os.environ.get('NZ_ORIG', '../linux32/nz'))
OURS = os.path.abspath(os.environ.get('OURS', os.environ.get('NZ_RECON', 'bin/nz-re')))
ROOT = '/tmp/nzre_pty_add'
CAP = 256 * 1024
TMO = 10.0
CASES = [  # name, keys, extra args
    ('y', b'y\n', []), ('n', b'n\n', []), ('a', b'a\n', []),
    ('Y', b'Y\n', []), ('N', b'N\n', []),
    ('enter_y', b'\ny\n', []), ('q_y', b'q\ny\n', []), ('yes_line', b'yes\n', []), ('no_line', b'nope\n', []),
    ('eof', b'\x04', []), ('nothing', b'', []), ('dash_y', b'', ['-y']),
]


def prepare(d):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, 'a.txt'), 'w').write('the old archive holds this file\n' * 200)
    open(os.path.join(d, 'b.txt'), 'w').write('the new archive would hold this one\n' * 300)
    subprocess.run([ORIG, 'a', '-t1', '-cf', 'old.nz', 'a.txt'], cwd=d, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'})
    return hashlib.sha256(open(os.path.join(d, 'old.nz'), 'rb').read()).hexdigest()


def run(bin_, args, keys, d):
    m, s = pty.openpty()
    err = open(os.path.join(d, 'err'), 'wb')
    p = subprocess.Popen([bin_, 'a', '-t1', '-cf'] + args + ['old.nz', 'b.txt'], stdin=s, stdout=s, stderr=err, cwd=d,
                         env={'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'TERM': 'dumb'}, preexec_fn=os.setsid)
    os.close(s)
    buf = b''; t0 = time.time(); sent = 0; next_key = t0 + 0.5; status = None
    while True:
        if time.time() - t0 > TMO or len(buf) > CAP:
            os.killpg(p.pid, signal.SIGKILL); status = 'KILLED'; break
        r, _, _ = select.select([m], [], [], 0.05)
        if r:
            try: chunk = os.read(m, 65536)
            except OSError: chunk = b''
            if not chunk: break
            buf += chunk
        if sent < len(keys) and time.time() >= next_key:
            os.write(m, keys[sent:sent + 1]); sent += 1; next_key = time.time() + 0.2
        if p.poll() is not None and not r: break
    p.wait(); err.close(); os.close(m)
    if status is None: status = p.returncode
    return buf, status


def norm(b):
    s = b.decode('latin1').replace('\r\n', '\n').replace('\r', '\n').replace('\b', '\n')
    s = re.sub(r'[0-9]+\.[0-9]+s', '<T>s', s); s = re.sub(r'[0-9 ]+[KMG]?B/s', ' <R>', s)
    s = re.sub(r'Intel\(R\).*MHz.*\n', '<HOSTLINE>\n', s)
    s = s.replace('Linux32', 'LinuxNN').replace('Linux64', 'LinuxNN')
    lines = [l.rstrip() for l in s.split('\n') if l.strip()]
    prompts = sum(1 for l in lines if l.startswith('Overwrite'))
    first = next((l for l in lines if l.startswith('Overwrite')), '')
    lines = [l for l in lines if not l.startswith('Overwrite') and not re.fullmatch(r'\d+%', l.strip())]
    return '\n'.join(lines + [f'<{prompts} prompt lines: {first!r}>'])


os.makedirs(ROOT, exist_ok=True)
same_n = 0
for name, keys, args in CASES:
    res = {}
    for who, bin_ in (('orig', ORIG), ('ours', OURS)):
        d = os.path.join(ROOT, name, who)
        subprocess.run(['rm', '-rf', d]); old = prepare(d)
        buf, status = run(bin_, args, keys, d)
        arc = os.path.join(d, 'old.nz')
        if not os.path.exists(arc): state = 'GONE'
        elif hashlib.sha256(open(arc, 'rb').read()).hexdigest() == old: state = 'old archive kept'
        else: state = 'replaced'
        leftovers = sorted(f for f in os.listdir(d) if f not in ('a.txt', 'b.txt', 'old.nz', 'err'))
        res[who] = (norm(buf), status, state, leftovers)
    same = res['orig'][0] == res['ours'][0] and res['orig'][2] == res['ours'][2]
    same_n += same
    print(f'{name:9} {"same" if same else "DIFF"}  exit orig={res["orig"][1]} ours={res["ours"][1]}  '
          f'archive orig=[{res["orig"][2]}] ours=[{res["ours"][2]}] leftovers ours={res["ours"][3]}')
    if not same or '-v' in sys.argv:
        for who in ('orig', 'ours'):
            print(f'   --- {who}:\n   ' + res[who][0].replace('\n', '\n   ')[:700])
print(f'pty_prompt_add: {same_n}/{len(CASES)} same')
