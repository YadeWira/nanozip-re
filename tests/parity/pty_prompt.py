#!/usr/bin/env python3
"""pty_prompt.py -- drive the overwrite prompt of both binaries through a real pty and compare.

For each key sequence: fresh dir under /tmp/nzre_pty/<case>/<who>/ with a pre-existing multi/e.txt
("OLD"), run `<bin> x <archive>` with stdin+stdout on a pty (stderr to a file), feed the keys with a
0.2 s gap, cap the output at 256 KB and the run at 10 s (SIGKILL), record stdout/stderr/exit/tree.
The original re-prints the prompt forever on EOF; the cap turns that into a bounded sample.

usage: pty_prompt.py [ARCHIVE=${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}/m_o.nz]
env:   OURS=path to nz_recon (default dev tree bin)
"""
import os, pty, select, signal, subprocess, sys, time, hashlib

ORIG = os.environ.get('NZ_ORIG', '../linux32/nz')
OURS = os.environ.get('OURS', os.environ.get('NZ_RECON', 'bin/nz_recon'))
ARC = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('${NZ_PARITY_FIXTURES:-/tmp/nzre_parity_fx}/m_o.nz')
ROOT = '/tmp/nzre_pty'
CAP = 256 * 1024
TMO = 10.0
CASES = [  # name, keys (bytes), extra args -- the original reads a LINE (canonical pty), so keys end in \n
    ('y',        b'y\n',      []),
    ('n',        b'n\n',      []),
    ('a',        b'a\n',      []),
    ('Y',        b'Y\n',      []),
    ('N',        b'N\n',      []),
    ('A',        b'A\n',      []),
    ('enter_y',  b'\ny\n',    []),
    ('q_y',      b'q\ny\n',    []),
    ('yes_line', b'yes\n',    []),
    ('no_line',  b'nope\n',   []),
    ('eof',      b'\x04',     []),
    ('nothing',  b'',         []),
    ('n_then_a', b'n\na\n',   []),
    ('dash_y',   b'',         ['-y']),
]

def tree(d):
    out = []
    for r, ds, fs in os.walk(d):
        for f in sorted(fs):
            p = os.path.join(r, f)
            if f in ('out', 'err', 'exit'): continue
            st = os.lstat(p)
            out.append(f'{oct(st.st_mode & 0o7777)} {st.st_size} {os.path.relpath(p, d)} {hashlib.sha256(open(p,"rb").read()).hexdigest()[:8]}')
    return '\n'.join(sorted(out))

def run(bin_, args, keys, d):
    os.makedirs(os.path.join(d, 'multi'), exist_ok=True)
    with open(os.path.join(d, 'multi', 'e.txt'), 'w') as f: f.write('OLD')
    m, s = pty.openpty()
    err = open(os.path.join(d, 'err'), 'wb')
    p = subprocess.Popen([bin_, 'x'] + args + [ARC], stdin=s, stdout=s, stderr=err, cwd=d,
                         env={'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'TERM': 'dumb'}, preexec_fn=os.setsid)
    os.close(s)
    buf = b''; t0 = time.time(); sent = 0; next_key = t0 + 0.5
    while True:
        if time.time() - t0 > TMO or len(buf) > CAP:
            os.killpg(p.pid, signal.SIGKILL); status = 'KILLED'; break
        r, _, _ = select.select([m], [], [], 0.05)
        if r:
            try: chunk = os.read(m, 65536)
            except OSError: chunk = b''
            if not chunk:
                break
            buf += chunk
        if sent < len(keys) and time.time() >= next_key:
            os.write(m, keys[sent:sent+1]); sent += 1; next_key = time.time() + 0.2
        if p.poll() is not None and not r:
            break
    p.wait(); err.close(); os.close(m)
    status = p.returncode if 'status' not in dir() or status != 'KILLED' else 'KILLED'
    open(os.path.join(d, 'out'), 'wb').write(buf)
    open(os.path.join(d, 'exit'), 'w').write(f'{status}\n')
    return buf, status

def norm(b):
    s = b.decode('latin1').replace('\r\n', '\n').replace('\r', '\n')
    import re
    s = re.sub(r'[0-9]+\.[0-9]+s', '<T>s', s); s = re.sub(r'[0-9]+ [KMG]?B/s', '<R>', s)
    s = re.sub(r'Intel\(R\).*MHz.*\n', '<HOSTLINE>\n', s); s = s.replace('Linux32', 'LinuxNN').replace('Linux64', 'LinuxNN')
    lines = [l for l in s.split('\n') if l.strip()]
    # collapse the original's infinite re-prompt into a count
    prompts = sum(1 for l in lines if l.startswith('Overwrite'))
    lines = [l for l in lines if not l.startswith('Overwrite')] + [f'<{prompts} prompt lines>']
    return '\n'.join(lines)

os.makedirs(ROOT, exist_ok=True)
for name, keys, args in CASES:
    res = {}
    for who, bin_ in (('orig', ORIG), ('ours', OURS)):
        d = os.path.join(ROOT, name, who)
        if os.path.exists(d): subprocess.run(['rm', '-rf', d])
        os.makedirs(d)
        buf, status = run(bin_, args, keys, d)
        res[who] = (norm(buf), status, tree(d))
    same = res['orig'] == res['ours']
    print(f'{name:10} {"same" if same else "DIFF"}  exit orig={res["orig"][1]} ours={res["ours"][1]}  bytes orig={len(open(os.path.join(ROOT,name,"orig","out"),"rb").read())} ours={len(open(os.path.join(ROOT,name,"ours","out"),"rb").read())}')
    if not same:
        for who in ('orig', 'ours'):
            print(f'   --- {who} stdout:'); print('   ' + res[who][0].replace('\n', '\n   ')[:600])
            print(f'   --- {who} tree:'); print('   ' + res[who][2].replace('\n', '\n   '))
