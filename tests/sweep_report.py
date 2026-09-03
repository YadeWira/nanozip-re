#!/usr/bin/env python3
"""sweep_report.py -- summarise real_corpus_sweep.sh results.

usage: sweep_report.py RESULTS.tsv [MANIFEST.tsv]

Reads the results file written with NZ_RESULTS_TSV (relpath, method, status, reason) and the
optional RESULTS.tsv.constructs file (relpath, method, key=value) produced from
NZ_TRACE_CONSTRUCTS lines. Prints pass/fail/skip per method, failures grouped by reason, the
table of constructs observed (with one example fixture each), and, with a manifest, coverage
per category and band.
"""
import collections, os, sys

def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    res = sys.argv[1]
    man = sys.argv[2] if len(sys.argv) > 2 else None
    rows = []
    with open(res, errors='replace') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < 3: continue
            rows.append((p[0], p[1], p[2], p[3] if len(p) > 3 else ''))
    methods = sorted({m for _, m, _, _ in rows}, key=lambda m: 'n f F d D o O c'.split().index(m[1:]) if m[1:] in 'n f F d D o O c'.split() else 99)
    per = {m: collections.Counter() for m in methods}
    for _, m, s, _ in rows: per[m][s] += 1
    files = {r for r, _, _, _ in rows}
    print(f'fixtures: {len(files)}   pairs: {len(rows)}')
    print(f'{"method":6} {"pass":>6} {"fail":>6} {"skip":>6}')
    tp = tf = 0
    for m in methods:
        c = per[m]; tp += c['PASS']; tf += c['FAIL']
        print(f'-{m:5} {c["PASS"]:6d} {c["FAIL"]:6d} {c["SKIP"]:6d}')
    print(f'TOTAL  {tp:6d} {tf:6d}')
    fails = [(r, m, why) for r, m, s, why in rows if s == 'FAIL']
    if fails:
        print('\n=== failures grouped by reason ===')
        for why, n in collections.Counter(w for _, _, w in fails).most_common():
            print(f'{n:5d}  {why}')
        print('\n=== failure detail ===')
        for r, m, why in sorted(fails):
            print(f'-{m:4} {r:60} {why}')
    cpath = res + '.constructs'
    if os.path.exists(cpath):
        seen = collections.OrderedDict(); count = collections.Counter()
        with open(cpath, errors='replace') as f:
            for line in f:
                p = line.rstrip('\n').split('\t')
                if len(p) < 3: continue
                key = (p[1], p[2]); count[key] += 1
                seen.setdefault(key, p[0])
        print('\n=== constructs observed (method, construct, fixtures, example) ===')
        for (m, kv), ex in sorted(seen.items()):
            print(f'-{m:4} {kv:40} {count[(m, kv)]:6d}  {ex}')
    if man and os.path.exists(man):
        cat_of = {}; band_of = {}
        with open(man, errors='replace') as f:
            for line in f:
                p = line.rstrip('\n').split('\t')
                if len(p) >= 5: cat_of[p[0]] = p[2]; band_of[p[0]] = p[4]
        cov = collections.defaultdict(collections.Counter)
        for r, m, s, _ in rows:
            cov[cat_of.get(r, '?')][s] += 1; cov['band:' + band_of.get(r, '?')][s] += 1
        print('\n=== coverage by category / band ===')
        for k in sorted(cov):
            c = cov[k]; print(f'{k:20} pass {c["PASS"]:6d} fail {c["FAIL"]:5d} skip {c["SKIP"]:5d}')
    return 0 if tf == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
