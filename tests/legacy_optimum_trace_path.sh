#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 /path/to/archive.nz [legacy_bin]" >&2
  exit 1
fi

ARCHIVE="$1"
if [[ ! -f "${ARCHIVE}" ]]; then
  echo "error: archive not found: ${ARCHIVE}" >&2
  exit 1
fi

LEGACY_BIN="${2:-${NZ_LEGACY_BACKEND:-}}"
if [[ -n "${LEGACY_BIN}" && -d "${LEGACY_BIN}" ]]; then
  LEGACY_BIN="${LEGACY_BIN%/}/nz"
fi
if [[ -z "${LEGACY_BIN}" ]]; then
  if [[ -x "work/linux32/nz" ]]; then
    LEGACY_BIN="work/linux32/nz"
  elif [[ -x "../linux32/nz" ]]; then
    LEGACY_BIN="../linux32/nz"
  else
    LEGACY_BIN="nz"
  fi
fi
if ! command -v "${LEGACY_BIN}" >/dev/null 2>&1 && [[ ! -x "${LEGACY_BIN}" ]]; then
  echo "error: legacy backend not found: ${LEGACY_BIN}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/nz_trace.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT
GDB_SCRIPT="${TMP_DIR}/trace.gdb"
RAW_OUT="${TMP_DIR}/raw.txt"

cat > "${GDB_SCRIPT}" <<'GDB'
set pagination off
set confirm off
set disassembly-flavor intel

break *0x080aa850
commands
  silent
  printf "HIT aa850 0x080aa850\n"
  continue
end
break *0x080abca0
commands
  silent
  printf "HIT abca0 0x080abca0\n"
  continue
end
break *0x080a87e0
commands
  silent
  printf "HIT a87e0 0x080a87e0\n"
  continue
end
break *0x080acaf0
commands
  silent
  printf "HIT acaf0 0x080acaf0\n"
  continue
end
break *0x0809a250
commands
  silent
  printf "HIT a9a250 0x0809a250\n"
  continue
end
break *0x0809d370
commands
  silent
  printf "HIT a9d370 0x0809d370\n"
  continue
end
break *0x080b1950
commands
  silent
  printf "HIT b1950 0x080b1950\n"
  continue
end
break *0x080b98a0
commands
  silent
  printf "HIT b98a0 0x080b98a0\n"
  continue
end
break *0x080b98e0
commands
  silent
  printf "HIT b98e0 0x080b98e0\n"
  continue
end
break *0x080a9ca0
commands
  silent
  printf "HIT a9ca0 0x080a9ca0\n"
  continue
end
break *0x080a5bb0
commands
  silent
  printf "HIT a5bb0 0x080a5bb0\n"
  continue
end
break *0x080b50b0
commands
  silent
  printf "HIT b50b0 0x080b50b0\n"
  continue
end
break *0x080a07a0
commands
  silent
  printf "HIT a07a0 0x080a07a0\n"
  continue
end
break *0x080a4fd0
commands
  silent
  printf "HIT a4fd0 0x080a4fd0\n"
  continue
end
break *0x080a3c90
commands
  silent
  printf "HIT a3c90 0x080a3c90\n"
  continue
end
break *0x080b5240
commands
  silent
  printf "HIT b5240 0x080b5240\n"
  continue
end
break *0x080b5c80
commands
  silent
  printf "HIT b5c80 0x080b5c80\n"
  continue
end

run
GDB

gdb -q -batch -x "${GDB_SCRIPT}" --args "${LEGACY_BIN}" t "${ARCHIVE}" > "${RAW_OUT}" 2>&1 || true

echo "archive=${ARCHIVE}"
echo "legacy_bin=${LEGACY_BIN}"
echo "hits_ordered:"
grep '^HIT ' "${RAW_OUT}" | awk '!seen[$2]++ {print "  " $2}'
echo
echo "raw_hits:"
grep '^HIT ' "${RAW_OUT}" || true
