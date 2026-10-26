#!/usr/bin/env python3
"""Test-suite for atc-salvage. Standard library only.

Run via `make test` (builds everything first) or `python3 tests/run_tests.py`
after building.

What is and is not asserted
  * Files the tools label OK are compared byte-for-byte with independently
    rebuilt ground truth, EXCEPT files adjacent to a break or gap: the format has
    no per-file checksum, so those are exactly where the README asks users to
    look by hand.
  * Recovery amounts are checked with deliberately loose thresholds.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
DATA = os.path.join(ROOT, "tests", "data")
sys.path.insert(0, os.path.join(ROOT, "src"))

PASSWORD = "testpass"
N_FILES = 120
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok    " if cond else "  FAIL  ") + name + (f"  -- {detail}" if (detail and not cond) else ""))


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return p.returncode, p.stdout, p.stderr


def truth(jpg, i):
    """Must match tests/make_test_archive.cpp."""
    m = i % 50
    d = bytearray(jpg)
    for k in range(1000, len(d), 37 + m):
        d[k] ^= (0x11 + m) & 0xFF
    return bytes(d)


def rel(i):
    return f"Folder{i % 4:02d}/Sub/photo_{i:04d}.jpg"


def read(path):
    with open(path, "rb") as f:
        return f.read()


def read_or_none(path):
    """A missing file counts as a mismatch instead of crashing the run."""
    try:
        return read(path)
    except OSError:
        return None


def parse_labels(log):
    """-> {index: 'OK'|'GAP'|'PART'} from a tool log.

    Lines look like "[ OK ] Folder01\\Sub\\photo_0045.jpg (...)" and
    "[GAP ] ...", "[PART] ...". Match the bracketed label, then the name."""
    out = {}
    for line in log.splitlines():
        m = re.match(r"^\[\s*(OK|GAP|PART)\s*\]\s+(\S+)", line)
        if not m:
            continue
        i = index_of(m.group(2))
        if i is not None:
            out[i] = m.group(1)
    return out


def index_of(name):
    m = re.search(r"photo_(\d+)\.jpg", name)
    return int(m.group(1)) if m else None


def main():
    for tool in ("salvage_extract", "dump_body", "make_test_archive"):
        if not os.path.exists(os.path.join(BIN, tool)):
            print(f"missing bin/{tool}; run `make test` (or build first)")
            return 2
    jpg = read(os.path.join(DATA, "cosmos.jpg"))
    tmp = tempfile.mkdtemp(prefix="atc-salvage-test-")
    try:
        print("[1] bundled upstream sample archives")
        for name in sorted(os.listdir(DATA)):
            if not name.endswith(".atc.tester"):
                continue
            out = os.path.join(tmp, "sample_" + name)
            rc, _, err = run([os.path.join(BIN, "salvage_extract"), os.path.join(DATA, name), "cosmos", out])
            ok = rc == 0 and read_or_none(os.path.join(out, "cosmos.jpg")) == jpg
            check(f"extracts {name} byte-identically", ok, err[-300:])

        print("[2] synthetic multi-file archive, undamaged")
        clean = os.path.join(tmp, "clean.atc")
        rc, _, err = run([os.path.join(BIN, "make_test_archive"), os.path.join(DATA, "cosmos.jpg"), clean, str(N_FILES)])
        check("test archive generated", rc == 0, err)
        out = os.path.join(tmp, "out_clean")
        rc, _, err = run([os.path.join(BIN, "salvage_extract"), clean, PASSWORD, out])
        check("salvage_extract exits 0 on an undamaged archive", rc == 0, err[-300:])
        bad = [i for i in range(N_FILES) if read_or_none(os.path.join(out, rel(i))) != truth(jpg, i)]
        check("all files match ground truth, in the right folders", not bad, f"mismatched: {bad[:5]}")
        flat = [f for f in (os.listdir(out) if os.path.isdir(out) else []) if "\\" in f]
        check("Windows backslash paths became real folders",
              not flat and os.path.isdir(os.path.join(out, "Folder01", "Sub")), str(flat[:3]))

        print("[3] damaged archive (300 KB zeroed at 40%)")
        data = bytearray(read(clean))
        start = int(len(data) * 0.4)
        data[start:start + 300000] = bytes(300000)
        damaged = os.path.join(tmp, "damaged.atc")
        with open(damaged, "wb") as f:
            f.write(data)

        out = os.path.join(tmp, "out_damaged")
        rc, _, err = run([os.path.join(BIN, "salvage_extract"), damaged, PASSWORD, out])
        check("salvage_extract reports the break (exit code 3)", rc == 3, f"rc={rc}")
        got = sorted(i for i in range(N_FILES) if os.path.exists(os.path.join(out, rel(i))))
        check("salvage_extract recovered some files before the break", len(got) > 10, f"{len(got)} files")
        wrong = [i for i in got[:-2] if read_or_none(os.path.join(out, rel(i))) != truth(jpg, i)]
        check("files before the break match ground truth", not wrong, f"mismatched: {wrong[:5]}")

        body, manifest = os.path.join(tmp, "body.bin"), os.path.join(tmp, "manifest.json")
        rc, _, err = run([os.path.join(BIN, "dump_body"), damaged, PASSWORD, body, manifest])
        check("dump_body succeeds on a damaged archive", rc == 0 and os.path.exists(body), err[-300:])

        out2 = os.path.join(tmp, "out_resync")
        rc, _, log = run([sys.executable, os.path.join(ROOT, "src", "resync_recover.py"),
                          body, manifest, out2, "--max-skip", "2000000"])
        check("resync_recover exits 0", rc == 0, log[-400:])
        labels = parse_labels(log)
        n_ok = sum(1 for v in labels.values() if v == "OK")
        gaps = sorted(i for i, v in labels.items() if v == "GAP")
        check("at least one corrupted region was bridged",
              re.search(r"[1-9]\d* corrupted region\(s\) bridged", log) is not None, log[-400:])
        check("the lost region is reported as GAP files", len(gaps) >= 1, str(labels)[:200])
        check("most files recovered (>= 80% labelled OK)", n_ok >= 0.8 * N_FILES, f"{n_ok}/{N_FILES}")
        near_gap = {j for g in gaps for j in range(g - 2, g + 3)}
        wrong = [i for i, v in labels.items()
                 if v == "OK" and i not in near_gap
                 and read_or_none(os.path.join(out2, rel(i))) != truth(jpg, i)]
        check("OK files away from a gap match ground truth (right content under right name)",
              not wrong, f"mismatched: {wrong[:5]}")
        after = list(range(max(gaps) + 3, N_FILES)) if gaps else []
        check("files AFTER the gap were recovered (beyond what salvage_extract can do)",
              len(after) > 5 and all(labels.get(i) == "OK" for i in after), f"{len(after)} after gap")
        m = re.search(r"Decoded data: (\d+) / (\d+) bytes", log)
        check("summary reports real recovery, not just the padded length",
              m is not None and int(m.group(1)) < int(m.group(2)), log[-300:])
        flat = [f for f in (os.listdir(out2) if os.path.isdir(out2) else []) if "\\" in f]
        check("resync output has real folders (no backslash filenames)",
              not flat and os.path.isdir(os.path.join(out2, "Folder02", "Sub")), str(flat[:3]))

        print("[4] unverifiable-type warning")
        import resync_recover as rr

        def warned(names):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rr.warn_if_unverifiable([{"name": n, "is_dir": False, "size": 1} for n in names])
            return "WARNING" in buf.getvalue()
        check("no warning when every file type has a signature check", not warned(["a.jpg", "b/c.PNG", "d.pdf"]))
        check("warns when a file type has no signature check", warned(["a.jpg", "notes.txt"]))

        print("[5] truncated archive: no stale data reported as OK")
        trunc = os.path.join(tmp, "trunc.atc")
        with open(trunc, "wb") as f:
            f.write(read(clean)[:len(read(clean)) // 2])
        out3 = os.path.join(tmp, "out_trunc")
        rc, _, log = run([os.path.join(BIN, "salvage_extract"), trunc, PASSWORD, out3])
        check("salvage_extract reports the truncation (exit code 3)", rc == 3, f"rc={rc}")
        labels = parse_labels(log)
        wrong = [i for i, v in labels.items() if v == "OK"
                 and read_or_none(os.path.join(out3, rel(i))) != truth(jpg, i)]
        check("nothing labelled OK is wrong in a truncated archive", not wrong, f"wrong OK: {wrong[:5]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
