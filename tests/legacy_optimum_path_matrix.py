#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import tempfile
import glob
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


def expand_inputs(patterns: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    seen = set()
    for p in patterns:
        for m in sorted(glob.glob(p)):
            pm = Path(m)
            if not pm.is_file():
                continue
            rp = pm.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            out.append(rp)
    return out


def parse_hits(trace_output: str) -> Tuple[str, ...]:
    hits: List[str] = []
    capture = False
    for line in trace_output.splitlines():
        if line.startswith("hits_ordered:"):
            capture = True
            continue
        if capture:
            if line.strip() == "" or line.startswith("raw_hits:"):
                break
            m = re.match(r"\s+(\S+)", line)
            if m:
                hits.append(m.group(1))
    return tuple(hits)


def run_cmd(cmd: Sequence[str], env: dict | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, check=False)


@dataclass
class GroupStats:
    count: int = 0
    t_ok: int = 0
    x_ok: int = 0
    compat_t: int = 0
    compat_x: int = 0
    samples: List[Tuple[str, int, int, bool]] = field(default_factory=list)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Classify legacy optimum/co/cO archives by runtime path (legacy backend) and native-pure recon behavior."
    )
    ap.add_argument(
        "inputs",
        nargs="+",
        help="glob patterns (quote them), e.g. '/tmp/nz_co_grid/*.nz'",
    )
    ap.add_argument(
        "--trace-script",
        default="work/reconstruccion/tests/legacy_optimum_trace_path.sh",
        help="path to trace script",
    )
    ap.add_argument(
        "--recon-bin",
        default="work/reconstruccion/bin/nz_recon",
        help="path to nz_recon binary",
    )
    ap.add_argument(
        "--max-samples",
        type=int,
        default=3,
        help="max sample rows shown per group",
    )
    args = ap.parse_args()

    trace_script = Path(args.trace_script)
    if not trace_script.is_file():
        raise SystemExit(f"error: trace script not found: {trace_script}")

    recon_bin = Path(args.recon_bin)
    if not recon_bin.is_file():
        fallback = Path("work/reconstruccion/build-release/nz_recon")
        if fallback.is_file():
            recon_bin = fallback
        else:
            raise SystemExit(f"error: recon binary not found: {args.recon_bin}")

    files = expand_inputs(args.inputs)
    if not files:
        raise SystemExit("error: no files matched input patterns")

    groups: dict[Tuple[str, ...], GroupStats] = defaultdict(GroupStats)

    env_pure = os.environ.copy()
    env_pure["NZ_DISABLE_EXTRACT_BRIDGE"] = "1"
    env_pure["NZ_DISABLE_GDB_BRIDGE"] = "1"

    for f in files:
        trace = run_cmd([str(trace_script), str(f)])
        sig = parse_hits(trace.stdout)
        g = groups[sig]
        g.count += 1

        t = run_cmd([str(recon_bin), "t", str(f)], env=env_pure)
        if t.returncode == 0:
            g.t_ok += 1
        if "[compat]" in t.stdout:
            g.compat_t += 1

        with tempfile.TemporaryDirectory(prefix="nz_path_matrix_") as td:
            x = run_cmd([str(recon_bin), "x", "-y", f"-o{td}", str(f)], env=env_pure)
        if x.returncode == 0:
            g.x_ok += 1
        if "[compat]" in x.stdout:
            g.compat_x += 1

        if len(g.samples) < args.max_samples:
            g.samples.append((str(f), t.returncode, x.returncode, ("[compat]" in t.stdout or "[compat]" in x.stdout)))

    print(f"groups={len(groups)} files={len(files)}")
    for sig, st in sorted(groups.items(), key=lambda kv: (-kv[1].count, kv[0])):
        label = "->".join(sig) if sig else "(none)"
        print("---")
        print(f"path={label} n={st.count}")
        print(f"t_ok={st.t_ok} x_ok={st.x_ok} compat_t={st.compat_t} compat_x={st.compat_x}")
        for sample in st.samples:
            print("sample", sample)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
